import httpx
import pytest
from pydantic import SecretStr
from redis.asyncio import Redis

from tests.unit.test_abuseipdb import BODY, EXPECTED, IP
from workers.enrichment.abuseipdb import AbuseIPDBClient

pytestmark = pytest.mark.integration


async def test_cache_round_trip_and_ttl_in_real_redis(redis: Redis) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=BODY)

    prefix = f"test:abuseipdb:{id(redis)}"
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = AbuseIPDBClient(http, redis, SecretStr("k"), key_prefix=prefix)

    assert await client.lookup(IP) == EXPECTED
    assert await client.lookup(IP) == EXPECTED

    assert calls == 1
    ttl = await redis.ttl(f"{prefix}:ip:{IP}")
    assert 24 * 3600 - 60 < ttl <= 24 * 3600
