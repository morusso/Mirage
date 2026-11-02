import asyncio
import json
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import cast
from uuid import uuid4

import pytest
from redis.asyncio import Redis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from domain.captured_request import CapturedRequest
from domain.tables import requests
from workers.persister import Persister

pytestmark = pytest.mark.integration

MAX_DELIVERIES = 2


def _event(path: str = "/.env", **kwargs: object) -> CapturedRequest:
    return CapturedRequest(
        ts=datetime(2026, 1, 1, 12, 0, tzinfo=UTC),
        session_id=uuid4(),
        world_id="w_test",
        persona="fake_api",
        ip=ip_address("203.0.113.9"),
        port=51000,
        method="GET",
        path=path,
        query="a=1",
        headers=[("Host", "example.com"), ("X-Dup", "1"), ("X-Dup", "2")],
        body_excerpt="hello",
        body_size=5,
        body_sha256="a" * 64,
        **kwargs,  # type: ignore[arg-type]
    ).with_response(tier=0, status=404, latency_ms=7, tokens_used=0)


async def _publish(redis: Redis, stream: str, event: CapturedRequest) -> None:
    await redis.xadd(stream, {"data": event.model_dump_json()})


def _persister(redis: Redis, stream: str, sessions: async_sessionmaker[AsyncSession]) -> Persister:
    return Persister(
        redis,
        stream,
        sessions,
        group="persister",
        consumer="t1",
        block_ms=50,
        min_idle_ms=100,
        max_deliveries=MAX_DELIVERIES,
    )


async def _count(sessions: async_sessionmaker[AsyncSession]) -> int:
    async with sessions() as session:
        return cast(int, await session.scalar(select(func.count()).select_from(requests)))


async def _wait_until(sessions: async_sessionmaker[AsyncSession], expected: int) -> None:
    async with asyncio.timeout(5):
        while await _count(sessions) != expected:  # noqa: ASYNC110
            await asyncio.sleep(0.02)


async def test_events_from_stream_land_in_requests_table(
    redis: Redis, stream_name: str, sessions: async_sessionmaker[AsyncSession]
) -> None:
    event = _event()
    await _publish(redis, stream_name, event)
    persister = _persister(redis, stream_name, sessions)

    task = asyncio.create_task(persister.run())
    try:
        await _wait_until(sessions, 1)
    finally:
        persister.stop()
        await asyncio.wait_for(task, timeout=5)

    async with sessions() as session:
        row = (await session.execute(select(requests))).one()
    assert row.event_id == event.event_id
    assert row.session_id == event.session_id
    assert str(row.ip) == "203.0.113.9"
    assert row.ts == event.ts
    assert row.headers == [["Host", "example.com"], ["X-Dup", "1"], ["X-Dup", "2"]]
    assert (row.method, row.path, row.query) == ("GET", "/.env", "a=1")
    assert (row.tier, row.status, row.latency_ms, row.tokens_used) == (0, 404, 7, 0)
    assert row.id is not None


async def test_redelivered_event_is_not_duplicated(
    redis: Redis, stream_name: str, sessions: async_sessionmaker[AsyncSession]
) -> None:
    event = _event()
    await _publish(redis, stream_name, event)
    await _publish(redis, stream_name, event)
    persister = _persister(redis, stream_name, sessions)

    task = asyncio.create_task(persister.run())
    try:
        await _wait_until(sessions, 1)
        async with asyncio.timeout(5):
            while (await redis.xpending(stream_name, "persister"))["pending"]:  # noqa: ASYNC110
                await asyncio.sleep(0.02)
    finally:
        persister.stop()
        await asyncio.wait_for(task, timeout=5)

    assert await _count(sessions) == 1


async def test_malformed_entry_is_dead_lettered_and_valid_ones_are_stored(
    redis: Redis, stream_name: str, sessions: async_sessionmaker[AsyncSession]
) -> None:
    await _publish(redis, stream_name, _event("/a"))
    await redis.xadd(stream_name, {"data": "{not json"})
    await _publish(redis, stream_name, _event("/b"))
    persister = _persister(redis, stream_name, sessions)

    task = asyncio.create_task(persister.run())
    try:
        await _wait_until(sessions, 2)
        async with asyncio.timeout(5):
            while not await redis.xlen(f"{stream_name}:dead"):  # noqa: ASYNC110
                await asyncio.sleep(0.02)
    finally:
        persister.stop()
        await asyncio.wait_for(task, timeout=5)

    dead_entries = await redis.xrange(f"{stream_name}:dead")
    assert dead_entries is not None
    ((_, dead),) = dead_entries
    assert dead is not None
    assert json.loads(str(dead["fields"])) == {"data": "{not json"}
    assert dead["reason"] == "ValueError"
    assert await _count(sessions) == 2
