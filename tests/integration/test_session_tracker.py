"""SessionTracker against a real Redis."""

import asyncio
from uuid import uuid4

import pytest
from redis.asyncio import Redis

from app.session.tracker import KEY_PREFIX, SessionTracker

pytestmark = pytest.mark.integration


class Clock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
async def clock(redis: Redis) -> Clock:
    await redis.flushdb()
    return Clock()


@pytest.fixture
def tracker(redis: Redis, clock: Clock) -> SessionTracker:
    return SessionTracker(redis, clock=clock)


async def test_first_request_has_count_one_and_no_interval(tracker: SessionTracker) -> None:
    counters = await tracker.record(uuid4())

    assert counters is not None
    assert (counters.request_count, counters.mean_interval_s) == (1, 0.0)


async def test_mean_interval_is_the_average_gap(tracker: SessionTracker, clock: Clock) -> None:
    session = uuid4()
    await tracker.record(session)
    clock.now += 2.0
    await tracker.record(session)
    clock.now += 4.0
    counters = await tracker.record(session)

    assert counters is not None
    assert counters.request_count == 3
    assert counters.mean_interval_s == pytest.approx(3.0)


async def test_sessions_are_counted_separately(tracker: SessionTracker) -> None:
    a, b = uuid4(), uuid4()
    await tracker.record(a)
    await tracker.record(a)

    counters = await tracker.record(b)

    assert counters is not None
    assert counters.request_count == 1


async def test_a_request_that_arrives_out_of_order_adds_no_negative_gap(
    tracker: SessionTracker, clock: Clock
) -> None:
    session = uuid4()
    await tracker.record(session)
    clock.now += 10.0
    await tracker.record(session)
    clock.now -= 30.0  # clock stepped back
    counters = await tracker.record(session)

    assert counters is not None
    assert counters.mean_interval_s == pytest.approx(10.0 / 2)


async def test_concurrent_requests_are_all_counted(redis: Redis, clock: Clock) -> None:
    tracker = SessionTracker(redis, clock=clock)
    session = uuid4()

    results = await asyncio.gather(*(tracker.record(session) for _ in range(50)))

    assert sorted(r.request_count for r in results if r) == list(range(1, 51))


async def test_session_expires_after_the_ttl(redis: Redis, clock: Clock) -> None:
    tracker = SessionTracker(redis, ttl_s=60, clock=clock)
    session = uuid4()

    await tracker.record(session)

    assert 0 < await redis.ttl(f"{KEY_PREFIX}{session}") <= 60


async def test_activity_refreshes_the_ttl(redis: Redis, clock: Clock) -> None:
    tracker = SessionTracker(redis, ttl_s=60, clock=clock)
    session = uuid4()
    await tracker.record(session)
    await redis.expire(f"{KEY_PREFIX}{session}", 5)

    await tracker.record(session)

    assert await redis.ttl(f"{KEY_PREFIX}{session}") > 5
