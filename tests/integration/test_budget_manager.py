"""BudgetManager against a real Redis: IP and subnet dimensions."""

from datetime import UTC, datetime
from ipaddress import ip_address
from uuid import uuid4

import pytest
from redis.asyncio import Redis

from app.engine.budget import UNAVAILABLE, BudgetManager, TierBudget
from domain.captured_request import CapturedRequest

pytestmark = pytest.mark.integration

LIMITS = {1: TierBudget(ip=1000, subnet=1500, total=2500)}
T0 = 60_000.0 * 1000  # seconds; the start of a bucket


def _req(ip: str) -> CapturedRequest:
    return CapturedRequest(
        ts=datetime.now(UTC),
        session_id=uuid4(),
        world_id="w",
        ip=ip_address(ip),
        method="GET",
        path="/api/v1/x",
    )


def _manager(redis: Redis) -> BudgetManager:
    return BudgetManager(redis, limits=LIMITS, clock=lambda: T0)


@pytest.fixture(autouse=True)
async def _clean(redis: Redis) -> None:
    await redis.flushdb()  # the redis fixture is shared and budget keys repeat across tests


async def test_one_ip_is_stopped_at_its_own_limit(redis: Redis) -> None:
    budget = _manager(redis)
    request = _req("203.0.113.7")

    assert await budget.allow(request, 1, 600)
    assert not await budget.allow(request, 1, 600)
    assert await budget.refused_by(request, 1, 600) == "ip"


async def test_another_ip_has_its_own_allowance(redis: Redis) -> None:
    budget = _manager(redis)

    assert await budget.allow(_req("203.0.113.7"), 1, 1000)
    assert await budget.allow(_req("198.51.100.7"), 1, 1000)


async def test_rotating_addresses_in_one_subnet_share_the_subnet_budget(redis: Redis) -> None:
    budget = _manager(redis)

    assert await budget.allow(_req("203.0.113.1"), 1, 800)
    assert await budget.allow(_req("203.0.113.2"), 1, 700)  # subnet is at 1500 now
    assert await budget.refused_by(_req("203.0.113.3"), 1, 100) == "subnet"
    assert await budget.allow(_req("203.0.114.1"), 1, 100)  # next /24 is untouched


async def test_ipv6_hosts_of_one_64_share_the_subnet_budget(redis: Redis) -> None:
    budget = _manager(redis)

    assert await budget.allow(_req("2001:db8:1:2::1"), 1, 900)
    assert await budget.allow(_req("2001:db8:1:2::2"), 1, 600)
    assert not await budget.allow(_req("2001:db8:1:2:ffff::3"), 1, 100)


async def test_ipv4_mapped_ipv6_shares_the_budget_of_the_ipv4(redis: Redis) -> None:
    budget = _manager(redis)

    assert await budget.allow(_req("203.0.113.7"), 1, 1000)
    assert not await budget.allow(_req("::ffff:203.0.113.7"), 1, 1000)


async def test_refusal_on_the_subnet_does_not_charge_the_ip(redis: Redis) -> None:
    budget = _manager(redis)
    await budget.allow(_req("203.0.113.1"), 1, 1000)
    await budget.allow(_req("203.0.113.2"), 1, 400)

    assert await budget.refused_by(_req("203.0.113.3"), 1, 400) == "subnet"
    assert await budget.allow(_req("203.0.113.3"), 1, 100)


async def test_unconfigured_tier_is_a_programming_error(redis: Redis) -> None:
    with pytest.raises(KeyError):
        await _manager(redis).allow(_req("203.0.113.7"), 2)


async def test_unreachable_redis_fails_closed() -> None:
    dead = Redis.from_url("redis://127.0.0.1:1/0")
    budget = BudgetManager(dead, limits=LIMITS)

    assert await budget.refused_by(_req("203.0.113.7"), 1) == UNAVAILABLE
    assert not await budget.allow(_req("203.0.113.7"), 1)
    await dead.aclose()


async def test_many_sources_together_hit_the_global_breaker(redis: Redis) -> None:
    budget = _manager(redis)

    # Three different /24s, each well within its own limits, add up to 2400 of 2500.
    for net in ("203.0.113", "198.51.100", "192.0.2"):
        assert await budget.allow(_req(f"{net}.1"), 1, 800)

    assert await budget.refused_by(_req("100.64.0.1"), 1, 200) == "global"
    assert await budget.allow(_req("100.64.0.1"), 1, 100)


async def test_global_refusal_does_not_charge_ip_or_subnet(redis: Redis) -> None:
    budget = _manager(redis)
    for net in ("203.0.113", "198.51.100", "192.0.2"):
        await budget.allow(_req(f"{net}.1"), 1, 800)

    assert await budget.refused_by(_req("100.64.0.1"), 1, 300) == "global"
    assert await redis.keys("mirage:budget:1:ip:100.64.0.1") == []
    assert await redis.keys("mirage:budget:1:net:100.64.0.0/24") == []


async def test_settle_refunds_what_the_model_did_not_use(redis: Redis) -> None:
    budget = _manager(redis)
    request = _req("203.0.113.7")

    assert await budget.allow(request, 1, 1000)  # worst-case estimate fills the IP budget
    assert not await budget.allow(request, 1, 300)
    await budget.settle(request, 1, estimated=1000, actual=400)

    assert await budget.allow(request, 1, 600)  # the 600 refunded tokens are available again
    assert not await budget.allow(request, 1, 1)


async def test_settle_charges_an_overrun_to_every_dimension(redis: Redis) -> None:
    budget = _manager(redis)
    request = _req("203.0.113.7")
    await budget.allow(request, 1, 300)

    await budget.settle(request, 1, estimated=300, actual=1200)

    assert await budget.refused_by(request, 1, 1) == "ip"
    assert await redis.hget("mirage:budget:1:global", "c") == "1200"


async def test_settle_never_drives_a_count_below_zero(redis: Redis) -> None:
    budget = _manager(redis)
    request = _req("203.0.113.7")
    await budget.allow(request, 1, 100)

    await budget.settle(request, 1, estimated=100, actual=0)
    await budget.settle(request, 1, estimated=500, actual=0)  # a stray double refund

    assert await redis.hget("mirage:budget:1:global", "c") == "0"


async def test_settle_with_no_difference_or_no_keys_is_harmless(redis: Redis) -> None:
    budget = _manager(redis)
    request = _req("203.0.113.7")

    await budget.settle(request, 1, estimated=300, actual=300)
    await budget.settle(request, 1, estimated=300, actual=100)  # nothing was ever charged

    assert await redis.keys("mirage:budget:*") == []


async def test_settle_swallows_redis_failures() -> None:
    dead = Redis.from_url("redis://127.0.0.1:1/0")
    budget = BudgetManager(dead, limits=LIMITS)

    await budget.settle(_req("203.0.113.7"), 1, estimated=300, actual=100)
    await dead.aclose()
