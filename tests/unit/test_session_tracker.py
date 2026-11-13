from uuid import uuid4

from redis.asyncio import Redis

from app.session.tracker import SessionTracker


async def test_unreachable_redis_returns_none_instead_of_raising() -> None:
    redis = Redis.from_url("redis://127.0.0.1:1/0")
    try:
        assert await SessionTracker(redis).record(uuid4()) is None
    finally:
        await redis.aclose()
