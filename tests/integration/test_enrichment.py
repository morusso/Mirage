from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from domain.captured_request import CapturedRequest
from domain.tables import sessions as sessions_table
from workers.base import StreamEntry
from workers.enrichment.asn import AsnLookup
from workers.enrichment.enricher import Enricher
from workers.enrichment.geo import GeoIPLookup
from workers.enrichment.worker import SessionEnricher

pytestmark = pytest.mark.integration

DATA = Path(__file__).parent.parent / "data"
T0 = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


class CountingRdns:
    def __init__(self) -> None:
        self.calls = 0

    async def lookup(self, ip: IPv4Address | IPv6Address) -> str | None:
        self.calls += 1
        return "host.example.net"


def _event(session_id: UUID, *, ip: str = "89.160.20.112", at: int = 0) -> CapturedRequest:
    return CapturedRequest(
        ts=T0 + timedelta(seconds=at),
        session_id=session_id,
        world_id="w_test",
        ip=ip_address(ip),
        method="GET",
        path="/",
    )


def _entries(*events: CapturedRequest) -> list[StreamEntry]:
    return [(f"{i}-0", {"data": e.model_dump_json()}) for i, e in enumerate(events)]


def _worker(
    redis: Redis, stream: str, sessions: async_sessionmaker[AsyncSession], rdns: CountingRdns
) -> SessionEnricher:
    enricher = Enricher(
        geo=GeoIPLookup(DATA / "GeoIP2-City-Test.mmdb"),
        asn=AsnLookup(DATA / "GeoLite2-ASN-Test.mmdb"),
        rdns=rdns,
    )
    return SessionEnricher(redis, stream, sessions, enricher)


async def _rows(sessions: async_sessionmaker[AsyncSession]) -> list[Any]:
    async with sessions() as session:
        return list(await session.execute(select(sessions_table).order_by(sessions_table.c.ip)))


async def test_new_session_is_enriched_and_spans_its_events(
    redis: Redis, stream_name: str, sessions: async_sessionmaker[AsyncSession]
) -> None:
    sid = uuid4()
    worker = _worker(redis, stream_name, sessions, CountingRdns())

    await worker.handle(_entries(_event(sid, at=5), _event(sid, at=0), _event(sid, at=9)))

    (row,) = await _rows(sessions)
    assert (row.country, row.city, row.asn) == ("SE", "Linköping", 29518)
    assert str(row.subnet) == "89.160.20.0/24"
    assert row.reverse_dns == "host.example.net"
    assert (row.first_seen, row.last_seen) == (T0, T0 + timedelta(seconds=9))
    assert row.request_count == 0 and row.closed is False


async def test_later_events_widen_the_window_without_re_enriching(
    redis: Redis, stream_name: str, sessions: async_sessionmaker[AsyncSession]
) -> None:
    sid, rdns = uuid4(), CountingRdns()
    worker = _worker(redis, stream_name, sessions, rdns)

    await worker.handle(_entries(_event(sid, at=10)))
    await worker.handle(_entries(_event(sid, at=3), _event(sid, at=30)))

    (row,) = await _rows(sessions)
    assert (row.first_seen, row.last_seen) == (
        T0 + timedelta(seconds=3),
        T0 + timedelta(seconds=30),
    )
    assert rdns.calls == 1


async def test_redelivery_changes_nothing(
    redis: Redis, stream_name: str, sessions: async_sessionmaker[AsyncSession]
) -> None:
    sid = uuid4()
    worker = _worker(redis, stream_name, sessions, CountingRdns())
    entries = _entries(_event(sid, at=1), _event(sid, at=2))

    await worker.handle(entries)
    before = await _rows(sessions)
    await worker.handle(entries)

    assert await _rows(sessions) == before


async def test_sessions_from_different_ips_get_their_own_rows(
    redis: Redis, stream_name: str, sessions: async_sessionmaker[AsyncSession]
) -> None:
    worker = _worker(redis, stream_name, sessions, CountingRdns())

    await worker.handle(
        _entries(_event(uuid4(), ip="89.160.20.112"), _event(uuid4(), ip="216.160.83.56"))
    )

    assert {r.country for r in await _rows(sessions)} == {"SE", "US"}


async def test_malformed_event_fails_but_good_ones_are_stored(
    redis: Redis, stream_name: str, sessions: async_sessionmaker[AsyncSession]
) -> None:
    worker = _worker(redis, stream_name, sessions, CountingRdns())

    with pytest.raises(ValueError, match="malformed"):
        await worker.handle([*_entries(_event(uuid4())), ("9-0", {"data": "{nope"})])

    assert len(await _rows(sessions)) == 1
