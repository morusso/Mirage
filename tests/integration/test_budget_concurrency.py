"""Property: parallel requests can never overspend a budget dimension."""

import asyncio
from collections import defaultdict
from datetime import UTC, datetime
from ipaddress import ip_address
from uuid import uuid4

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from redis.asyncio import Redis

from app.engine.budget import BudgetManager, TierBudget
from domain.captured_request import CapturedRequest
from domain.network import subnet_of

pytestmark = pytest.mark.integration

# Two hosts of one /24 and one host of another, so IP, subnet and global limits all bite.
IPS = ("203.0.113.1", "203.0.113.2", "198.51.100.1")
FROZEN_NOW = 60_000.0 * 1000  # a bucket start: the window never rolls during an example


def _req(ip: str) -> CapturedRequest:
    return CapturedRequest(
        ts=datetime.now(UTC),
        session_id=uuid4(),
        world_id="w",
        ip=ip_address(ip),
        method="GET",
        path="/api/v1/x",
    )


async def _run(
    redis_url: str, budget: TierBudget, calls: list[tuple[str, int]]
) -> list[tuple[str, int, bool]]:
    redis = Redis.from_url(redis_url, decode_responses=True)
    try:
        await redis.flushdb()
        manager = BudgetManager(redis, limits={1: budget}, clock=lambda: FROZEN_NOW, timeout_s=5)
        allowed = await asyncio.gather(*(manager.allow(_req(ip), 1, cost) for ip, cost in calls))
        return [(ip, cost, ok) for (ip, cost), ok in zip(calls, allowed, strict=True)]
    finally:
        await redis.aclose()


@settings(max_examples=25, deadline=None)
@given(
    limits=st.tuples(st.integers(100, 1500), st.integers(100, 2500), st.integers(100, 4000)),
    calls=st.lists(st.tuples(st.sampled_from(IPS), st.integers(1, 600)), min_size=1, max_size=40),
)
def test_charged_tokens_never_exceed_any_limit(
    redis_url: str, limits: tuple[int, int, int], calls: list[tuple[str, int]]
) -> None:
    budget = TierBudget(ip=limits[0], subnet=limits[1], total=limits[2])

    results = asyncio.run(_run(redis_url, budget, calls))

    by_ip: dict[str, int] = defaultdict(int)
    by_subnet: dict[str, int] = defaultdict(int)
    total = 0
    for ip, cost, ok in results:
        if ok:
            by_ip[ip] += cost
            by_subnet[str(subnet_of(ip_address(ip)))] += cost
            total += cost
    assert all(v <= budget.ip for v in by_ip.values())
    assert all(v <= budget.subnet for v in by_subnet.values())
    assert total <= budget.total


@settings(max_examples=15, deadline=None)
@given(n=st.integers(2, 60), limit=st.integers(1, 20))
def test_exactly_the_affordable_number_of_one_token_requests_pass(
    redis_url: str, n: int, limit: int
) -> None:
    """One-token requests land exactly on the limit: the count of winners is exact."""
    budget = TierBudget(ip=limit, subnet=0, total=0)  # only the IP dimension limits

    results = asyncio.run(_run(redis_url, budget, [("203.0.113.1", 1)] * n))

    assert sum(ok for _, _, ok in results) == min(n, limit)
