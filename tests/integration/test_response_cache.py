import pytest
from redis.asyncio import Redis

from app.engine.cache import KEY_PREFIX, CachedResponse, ResponseCache

pytestmark = pytest.mark.integration

SIG = "ab" * 32


def _response() -> CachedResponse:
    return CachedResponse(status_code=200, headers={"content-type": "text/plain"}, body="hi")


async def test_set_then_get_round_trips(redis: Redis) -> None:
    cache = ResponseCache(redis)

    assert await cache.get(SIG) is None
    assert not await cache.has(SIG)

    assert await cache.set(SIG, _response())

    assert await cache.has(SIG)
    assert await cache.get(SIG) == _response()


async def test_entries_expire(redis: Redis) -> None:
    cache = ResponseCache(redis, ttl_s=100)
    await cache.set(SIG, _response())

    ttl = await redis.ttl(KEY_PREFIX + SIG)

    assert 0 < ttl <= 100


async def test_corrupt_entry_is_a_miss(redis: Redis) -> None:
    await redis.set(KEY_PREFIX + SIG, "not json")

    assert await ResponseCache(redis).get(SIG) is None


async def test_redis_failure_degrades_to_a_miss() -> None:
    dead = Redis.from_url("redis://127.0.0.1:1/0")
    cache = ResponseCache(dead, timeout_s=0.2)
    try:
        assert await cache.get(SIG) is None
        assert await cache.has(SIG) is False
        assert await cache.set(SIG, _response()) is False
    finally:
        await dead.aclose()
