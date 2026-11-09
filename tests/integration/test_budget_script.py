"""The sliding-window Lua script against a real Redis."""

from uuid import uuid4

import pytest
from redis.asyncio import Redis

from app.engine.budget_script import SlidingWindowBudget

pytestmark = pytest.mark.integration

WINDOW_S = 60
T0 = 1_000 * WINDOW_S * 1000  # start of a bucket, so elapsed-in-bucket is 0


def _keys(*names: str) -> list[str]:
    run = uuid4().hex
    return [f"test:budget:{run}:{n}" for n in names]


async def test_charges_until_the_limit_then_refuses(redis: Redis) -> None:
    budget = SlidingWindowBudget(redis, window_s=WINDOW_S)
    keys = _keys("ip")

    results = [await budget.check_and_consume(keys, [1000], 400, now_ms=T0) for _ in range(3)]

    assert results == [None, None, 0]  # 400 + 400 fit, a third 400 would make 1200


async def test_refusal_reports_the_first_exhausted_dimension(redis: Redis) -> None:
    budget = SlidingWindowBudget(redis, window_s=WINDOW_S)
    keys = _keys("ip", "net", "global")

    await budget.check_and_consume(keys, [1000, 500, 10_000], 400, now_ms=T0)

    assert await budget.check_and_consume(keys, [1000, 500, 10_000], 400, now_ms=T0) == 1


async def test_refused_request_charges_no_dimension(redis: Redis) -> None:
    budget = SlidingWindowBudget(redis, window_s=WINDOW_S)
    ip, glob = _keys("ip", "global")

    # The global limit refuses; the IP must keep its full allowance.
    assert await budget.check_and_consume([ip, glob], [1000, 100], 400, now_ms=T0) == 1
    assert await budget.check_and_consume([ip], [1000], 1000, now_ms=T0) is None


async def test_non_positive_limit_means_unlimited(redis: Redis) -> None:
    budget = SlidingWindowBudget(redis, window_s=WINDOW_S)
    keys = _keys("ip")

    for _ in range(5):
        assert await budget.check_and_consume(keys, [0], 10_000, now_ms=T0) is None


async def test_previous_bucket_fades_out_across_the_window(redis: Redis) -> None:
    budget = SlidingWindowBudget(redis, window_s=WINDOW_S)
    keys = _keys("ip")
    window_ms = WINDOW_S * 1000

    assert await budget.check_and_consume(keys, [1000], 1000, now_ms=T0) is None
    # Halfway into the next bucket, half of the old usage still counts.
    halfway = T0 + window_ms + window_ms // 2
    assert await budget.check_and_consume(keys, [1000], 600, now_ms=halfway) == 0
    assert await budget.check_and_consume(keys, [1000], 500, now_ms=halfway) is None


async def test_idle_for_two_windows_resets_the_budget(redis: Redis) -> None:
    budget = SlidingWindowBudget(redis, window_s=WINDOW_S)
    keys = _keys("ip")

    assert await budget.check_and_consume(keys, [1000], 1000, now_ms=T0) is None
    later = T0 + 2 * WINDOW_S * 1000
    assert await budget.check_and_consume(keys, [1000], 1000, now_ms=later) is None


async def test_keys_expire_so_idle_ips_leave_nothing_behind(redis: Redis) -> None:
    budget = SlidingWindowBudget(redis, window_s=WINDOW_S)
    keys = _keys("ip")

    await budget.check_and_consume(keys, [1000], 10, now_ms=T0)

    ttl_ms = await redis.pttl(keys[0])
    assert 0 < ttl_ms <= 2 * WINDOW_S * 1000


async def test_mismatched_keys_and_limits_are_rejected(redis: Redis) -> None:
    budget = SlidingWindowBudget(redis, window_s=WINDOW_S)

    with pytest.raises(ValueError, match="same length"):
        await budget.check_and_consume(_keys("a", "b"), [1], 1, now_ms=T0)
