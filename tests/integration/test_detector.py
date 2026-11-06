from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any
from uuid import uuid4

import pytest
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from domain.captured_request import CapturedRequest
from domain.tables import detections, requests
from workers.base import StreamEntry
from workers.detector.worker import Detector, build_registry
from workers.persister import Persister

pytestmark = pytest.mark.integration


def _event(**kwargs: Any) -> CapturedRequest:
    base: dict[str, Any] = {
        "ts": datetime(2026, 1, 1, 12, 0, tzinfo=UTC),
        "session_id": uuid4(),
        "world_id": "w_test",
        "persona": "fake_api",
        "ip": ip_address("203.0.113.9"),
        "method": "GET",
        "path": "/api/v1/products",
    }
    return CapturedRequest(**{**base, **kwargs})


def _entries(*events: CapturedRequest) -> list[StreamEntry]:
    return [(f"{i}-0", {"data": e.model_dump_json()}) for i, e in enumerate(events)]


def _workers(redis: Redis, stream: str, sessions: async_sessionmaker[AsyncSession]):  # type: ignore[no-untyped-def]
    return Persister(redis, stream, sessions), Detector(redis, stream, sessions)


async def _stored(sessions: async_sessionmaker[AsyncSession]) -> list[Any]:
    async with sessions() as session:
        return list(
            await session.execute(
                select(
                    detections.c.rule,
                    detections.c.category,
                    detections.c.severity,
                    detections.c.request_id,
                    requests.c.path,
                ).join(requests, requests.c.id == detections.c.request_id)
            )
        )


def test_registry_holds_every_family() -> None:
    names = {r.name for r in build_registry().rules}

    assert "sqli.union_select" in names
    assert "scanner.sqlmap" in names
    assert any(n.startswith("log4shell.") for n in names)


async def test_detections_are_stored_against_the_request_row(
    redis: Redis, stream_name: str, sessions: async_sessionmaker[AsyncSession]
) -> None:
    persister, detector = _workers(redis, stream_name, sessions)
    attack = _event(query="id=1 UNION SELECT username,password FROM users--")
    benign = _event(path="/api/v1/products", query="page=2")
    entries = _entries(attack, benign)

    await persister.handle(entries)
    await detector.handle(entries)

    stored = await _stored(sessions)
    assert {(r.category, r.path) for r in stored} == {("sqli", "/api/v1/products")}
    assert all(r.severity in {"low", "medium", "high", "critical"} for r in stored)


async def test_redelivery_does_not_duplicate_detections(
    redis: Redis, stream_name: str, sessions: async_sessionmaker[AsyncSession]
) -> None:
    persister, detector = _workers(redis, stream_name, sessions)
    entries = _entries(_event(headers=[("User-Agent", "sqlmap/1.7")]))
    await persister.handle(entries)

    await detector.handle(entries)
    first = len(await _stored(sessions))
    await detector.handle(entries)

    assert first >= 1
    assert len(await _stored(sessions)) == first


async def test_unpersisted_request_fails_the_batch_for_retry(
    redis: Redis, stream_name: str, sessions: async_sessionmaker[AsyncSession]
) -> None:
    persister, detector = _workers(redis, stream_name, sessions)
    entries = _entries(_event(query="q=<script>alert(1)</script>"))

    with pytest.raises(LookupError):
        await detector.handle(entries)
    assert await _stored(sessions) == []

    await persister.handle(entries)
    await detector.handle(entries)  # the retry succeeds

    assert len(await _stored(sessions)) >= 1


async def test_malformed_event_fails_but_good_ones_are_stored(
    redis: Redis, stream_name: str, sessions: async_sessionmaker[AsyncSession]
) -> None:
    persister, detector = _workers(redis, stream_name, sessions)
    good = _entries(_event(query="id=1' OR '1'='1"))
    await persister.handle(good)

    with pytest.raises(ValueError, match="malformed"):
        await detector.handle([*good, ("9-0", {"data": "{not json"})])

    assert len(await _stored(sessions)) >= 1
