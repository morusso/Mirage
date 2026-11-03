from datetime import UTC, datetime
from ipaddress import ip_address
from typing import cast

import httpx
import pytest
from pydantic import SecretStr
from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.config import Settings
from workers.enrichment.abuseipdb import (
    API_URL,
    DEFAULT_BACKOFF_S,
    MAX_BACKOFF_S,
    AbuseIPDBClient,
    Reputation,
)

IP = ip_address("185.220.101.1")
BODY = {
    "data": {
        "ipAddress": "185.220.101.1",
        "abuseConfidenceScore": 100,
        "totalReports": 42,
        "lastReportedAt": "2026-10-30T08:15:00+00:00",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Example Hosting",
    }
}
EXPECTED = Reputation(
    abuse_score=100,
    total_reports=42,
    last_reported_at=datetime(2026, 10, 30, 8, 15, tzinfo=UTC),
    usage_type="Data Center/Web Hosting/Transit",
    isp="Example Hosting",
)


class FakeRedis:
    """The few commands the client uses; remembers the TTL it was given."""

    def __init__(self, *, broken: bool = False) -> None:
        self.values: dict[str, str] = {}
        self.ttls: dict[str, int | None] = {}
        self.broken = broken

    async def get(self, key: str) -> str | None:
        self._check()
        return self.values.get(key)

    async def exists(self, key: str) -> int:
        self._check()
        return int(key in self.values)

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self._check()
        self.values[key] = value
        self.ttls[key] = ex

    def _check(self) -> None:
        if self.broken:
            raise RedisError("down")


class Api:
    """Counts requests and answers with a canned response."""

    def __init__(self, response: httpx.Response | Exception) -> None:
        self.response = response
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _client(api: Api, redis: FakeRedis) -> AbuseIPDBClient:
    http = httpx.AsyncClient(transport=httpx.MockTransport(api))
    return AbuseIPDBClient(http, cast(Redis, redis), SecretStr("secret-key"))


def _ok() -> httpx.Response:
    return httpx.Response(200, json=BODY)


async def test_fetches_parses_and_caches_for_24_hours() -> None:
    api, redis = Api(_ok()), FakeRedis()

    result = await _client(api, redis).lookup(IP)

    assert result == EXPECTED
    assert redis.ttls["abuseipdb:ip:185.220.101.1"] == 24 * 3600


async def test_request_carries_key_and_address() -> None:
    api = Api(_ok())

    await _client(api, FakeRedis()).lookup(IP)

    (request,) = api.requests
    assert str(request.url).startswith(API_URL)
    assert request.url.params["ipAddress"] == "185.220.101.1"
    assert request.headers["Key"] == "secret-key"


async def test_second_lookup_is_served_from_cache() -> None:
    api, redis = Api(_ok()), FakeRedis()
    client = _client(api, redis)

    first = await client.lookup(IP)
    second = await client.lookup(IP)

    assert first == second == EXPECTED
    assert len(api.requests) == 1


async def test_null_fields_round_trip_through_cache() -> None:
    body = {"data": {"abuseConfidenceScore": 0, "totalReports": 0, "lastReportedAt": None}}
    api, redis = Api(httpx.Response(200, json=body)), FakeRedis()
    client = _client(api, redis)

    expected = Reputation(0, 0, None, None, None)
    assert await client.lookup(IP) == expected
    assert await client.lookup(IP) == expected
    assert len(api.requests) == 1


@pytest.mark.parametrize("ip", ["10.0.0.1", "192.168.1.1", "127.0.0.1", "203.0.113.7", "::1"])
async def test_non_public_addresses_are_never_sent(ip: str) -> None:
    api = Api(_ok())

    assert await _client(api, FakeRedis()).lookup(ip_address(ip)) is None
    assert api.requests == []


async def test_rate_limit_pauses_all_calls_until_retry_after() -> None:
    api = Api(httpx.Response(429, headers={"Retry-After": "7200"}))
    redis = FakeRedis()
    client = _client(api, redis)

    assert await client.lookup(IP) is None
    assert redis.ttls["abuseipdb:paused"] == 7200

    assert await client.lookup(ip_address("185.220.101.2")) is None
    assert len(api.requests) == 1  # the second address never reached the API


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ({}, DEFAULT_BACKOFF_S),
        ({"Retry-After": "soon"}, DEFAULT_BACKOFF_S),
        ({"Retry-After": "0"}, 1),
        ({"Retry-After": "999999"}, MAX_BACKOFF_S),
    ],
)
async def test_retry_after_is_sanitized(headers: dict[str, str], expected: int) -> None:
    redis = FakeRedis()

    await _client(Api(httpx.Response(429, headers=headers)), redis).lookup(IP)

    assert redis.ttls["abuseipdb:paused"] == expected


async def test_cached_answers_still_served_while_paused() -> None:
    api, redis = Api(_ok()), FakeRedis()
    client = _client(api, redis)
    await client.lookup(IP)
    redis.values["abuseipdb:paused"] = "1"

    assert await client.lookup(IP) == EXPECTED


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(401, json={"errors": [{"detail": "bad key"}]}),
        httpx.Response(500),
        httpx.Response(200, text="<html>not json</html>"),
        httpx.Response(200, json={"data": {"abuseConfidenceScore": "high"}}),
        httpx.Response(
            200,
            json={
                "data": {
                    "abuseConfidenceScore": 5,
                    "totalReports": 1,
                    "lastReportedAt": "yesterday",
                }
            },
        ),
        httpx.Response(200, json=["unexpected"]),
        httpx.ConnectTimeout("slow"),
        httpx.ConnectError("refused"),
    ],
)
async def test_failures_give_none_and_are_not_cached(response: httpx.Response | Exception) -> None:
    redis = FakeRedis()

    assert await _client(Api(response), redis).lookup(IP) is None
    assert redis.values == {}


async def test_corrupt_cache_entry_is_refetched() -> None:
    api, redis = Api(_ok()), FakeRedis()
    redis.values["abuseipdb:ip:185.220.101.1"] = "{not json"

    assert await _client(api, redis).lookup(IP) == EXPECTED
    assert len(api.requests) == 1


async def test_redis_down_gives_none_without_calling_the_api() -> None:
    api = Api(_ok())

    assert await _client(api, FakeRedis(broken=True)).lookup(IP) is None
    assert api.requests == []  # cannot honour the quota without the cache


def test_api_key_is_optional_and_secret_in_settings() -> None:
    assert Settings().abuseipdb_api_key is None
    settings = Settings(abuseipdb_api_key=SecretStr("s3cr3t-abuse-key"))
    assert "s3cr3t-abuse-key" not in repr(settings)
