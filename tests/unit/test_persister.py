from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any, cast
from uuid import uuid4

import pytest
from redis.asyncio import Redis
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from domain.captured_request import CapturedRequest
from workers.base import StreamEntry
from workers.persister import Persister, to_row


class FakeSession:
    def __init__(self) -> None:
        self.statements: list[Any] = []

    async def execute(self, statement: Any) -> None:
        self.statements.append(statement)


class FakeSessions:
    def __init__(self) -> None:
        self.session = FakeSession()
        self.transactions = 0

    @asynccontextmanager
    async def begin(self) -> AsyncIterator[FakeSession]:
        self.transactions += 1
        yield self.session


def _persister(sessions: FakeSessions) -> Persister:
    return Persister(
        cast(Redis, None),
        "s",
        cast("async_sessionmaker[AsyncSession]", sessions),
        consumer="c",
    )


def _event(path: str = "/") -> CapturedRequest:
    return CapturedRequest(
        ts=datetime(2026, 1, 1, tzinfo=UTC),
        session_id=uuid4(),
        world_id="w",
        ip=ip_address("203.0.113.9"),
        method="GET",
        path=path,
        headers=[("Host", "example.com")],
    ).with_response(tier=0, status=404, latency_ms=3)


def _entry(event: CapturedRequest, n: int = 1) -> StreamEntry:
    return (f"{n}-0", {"data": event.model_dump_json()})


def test_to_row_maps_event_fields() -> None:
    event = _event("/.env")

    row = to_row(event)

    assert row["event_id"] == event.event_id
    assert row["ip"] == "203.0.113.9"
    assert row["path"] == "/.env"
    assert row["headers"] == [("Host", "example.com")]
    assert (row["tier"], row["status"], row["latency_ms"]) == (0, 404, 3)
    assert "id" not in row


async def test_batch_is_one_insert_in_one_transaction_with_conflict_skip() -> None:
    sessions = FakeSessions()
    entries = [_entry(_event(f"/{i}"), i) for i in range(3)]

    await _persister(sessions).handle(entries)

    assert sessions.transactions == 1
    (statement,) = sessions.session.statements
    compiled = statement.compile(dialect=postgresql.dialect())  # type: ignore[no-untyped-call]
    sql = str(compiled)
    assert sql.count("INSERT INTO") == 1
    assert "ON CONFLICT (event_id, ts) DO NOTHING" in sql
    assert len(compiled.params) >= 3 * 20


async def test_malformed_entries_are_reported_after_valid_ones_are_stored() -> None:
    sessions = FakeSessions()
    entries = [_entry(_event(), 1), ("2-0", {"data": "{not json"}), ("3-0", {"other": "x"})]

    with pytest.raises(ValueError, match="2 malformed"):
        await _persister(sessions).handle(entries)

    assert len(sessions.session.statements) == 1


async def test_only_malformed_entries_means_no_insert() -> None:
    sessions = FakeSessions()

    with pytest.raises(ValueError, match="1 malformed"):
        await _persister(sessions).handle([("1-0", {"data": "nope"})])

    assert sessions.transactions == 0
