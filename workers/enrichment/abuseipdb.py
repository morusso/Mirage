import json
from dataclasses import asdict, dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any

import httpx
import structlog
from pydantic import SecretStr
from redis.asyncio import Redis
from redis.exceptions import RedisError

logger = structlog.get_logger()

API_URL = "https://api.abuseipdb.com/api/v2/check"
CACHE_TTL_S = 24 * 3600
MAX_AGE_IN_DAYS = 90
DEFAULT_BACKOFF_S = 3600
MAX_BACKOFF_S = 24 * 3600


@dataclass(frozen=True, slots=True)
class Reputation:
    abuse_score: int
    total_reports: int
    last_reported_at: datetime | None
    usage_type: str | None
    isp: str | None


class AbuseIPDBClient:
    """IP reputation from AbuseIPDB, cached in Redis and careful with the API quota.

    The free plan allows ~1000 checks a day, so:
    - every successful answer is cached for 24 h (a repeat visitor costs nothing),
    - non-public addresses are never sent (no answer, and it would leak internal ranges),
    - a 429 pauses all calls until the quota resets, instead of burning requests on it.
    Every failure (timeout, quota, bad response, Redis down) yields None and is never
    cached: reputation is nice to have and must not stall or fail enrichment.
    The ISP and usage type are third-party text; treat them as data.
    """

    def __init__(
        self,
        http: httpx.AsyncClient,
        redis: Redis,
        api_key: SecretStr,
        *,
        cache_ttl_s: int = CACHE_TTL_S,
        key_prefix: str = "abuseipdb",
    ) -> None:
        self._http = http
        self._redis = redis
        self._api_key = api_key
        self._cache_ttl_s = cache_ttl_s
        self._cache_prefix = f"{key_prefix}:ip:"
        self._paused_key = f"{key_prefix}:paused"

    async def lookup(self, ip: IPv4Address | IPv6Address) -> Reputation | None:
        if not ip.is_global:
            return None
        key = f"{self._cache_prefix}{ip}"
        try:
            cached = await self._redis.get(key)
            if cached is not None and (hit := _from_cache(cached)) is not None:
                return hit
            if await self._redis.exists(self._paused_key):
                return None
        except RedisError:
            logger.warning("abuseipdb_cache_unavailable")
            return None

        reputation = await self._fetch(ip)
        if reputation is not None:
            try:
                await self._redis.set(key, _to_cache(reputation), ex=self._cache_ttl_s)
            except RedisError:
                logger.warning("abuseipdb_cache_write_failed")
        return reputation

    async def _fetch(self, ip: IPv4Address | IPv6Address) -> Reputation | None:
        try:
            response = await self._http.get(
                API_URL,
                params={"ipAddress": str(ip), "maxAgeInDays": MAX_AGE_IN_DAYS},
                headers={"Key": self._api_key.get_secret_value(), "Accept": "application/json"},
            )
        except httpx.HTTPError:
            logger.warning("abuseipdb_request_failed")
            return None
        if response.status_code == 429:
            await self._pause(_backoff_seconds(response))
            return None
        if response.status_code != 200:
            logger.warning("abuseipdb_bad_status", status=response.status_code)
            return None
        return _parse(response)

    async def _pause(self, seconds: int) -> None:
        logger.warning("abuseipdb_rate_limited", pause_s=seconds)
        try:
            await self._redis.set(self._paused_key, "1", ex=seconds)
        except RedisError:
            logger.warning("abuseipdb_cache_write_failed")


def _backoff_seconds(response: httpx.Response) -> int:
    try:
        seconds = int(response.headers["Retry-After"])
    except (KeyError, ValueError):
        return DEFAULT_BACKOFF_S
    return min(max(seconds, 1), MAX_BACKOFF_S)


def _parse(response: httpx.Response) -> Reputation | None:
    try:
        data: Any = response.json()["data"]
        score = data["abuseConfidenceScore"]
        reports = data["totalReports"]
        if not isinstance(score, int) or not isinstance(reports, int):
            raise TypeError
        return Reputation(
            abuse_score=score,
            total_reports=reports,
            last_reported_at=_timestamp(data.get("lastReportedAt")),
            usage_type=_text(data.get("usageType")),
            isp=_text(data.get("isp")),
        )
    except (ValueError, KeyError, TypeError):
        logger.warning("abuseipdb_bad_response")
        return None


def _timestamp(value: Any) -> datetime | None:
    return datetime.fromisoformat(value) if isinstance(value, str) and value else None


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _to_cache(reputation: Reputation) -> str:
    fields = asdict(reputation)
    if reputation.last_reported_at is not None:
        fields["last_reported_at"] = reputation.last_reported_at.isoformat()
    return json.dumps(fields)


def _from_cache(raw: str | bytes) -> Reputation | None:
    """A corrupt or outdated cache entry counts as a miss."""
    try:
        fields = json.loads(raw)
        fields["last_reported_at"] = _timestamp(fields["last_reported_at"])
        return Reputation(**fields)
    except (ValueError, KeyError, TypeError):
        return None
