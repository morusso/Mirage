"""Enrichment worker: one ``sessions`` row per attacker session, with country, ASN,
reverse DNS and reputation.

A consumer group of its own on the capture stream (``enrichment``). A session is
enriched once, when its first event is seen; later events only widen its first/last
seen times (LEAST/GREATEST, so redelivery changes nothing). Lookups happen before the
transaction opens: no database transaction is held open across network calls.

``request_count`` is not maintained here (counting events would double on redelivery);
the sessionizer sets it when it closes the session.
"""

import asyncio
import os
import socket
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any
from uuid import UUID

import httpx
import structlog
from pydantic import ValidationError
from redis.asyncio import Redis
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import Settings
from app.log import configure_logging
from domain.captured_request import CapturedRequest
from domain.db import create_engine, create_session_factory
from domain.tables import sessions as sessions_table
from workers.base import StreamConsumer, StreamEntry, run_until_signalled
from workers.enrichment.abuseipdb import AbuseIPDBClient
from workers.enrichment.asn import AsnLookup
from workers.enrichment.enricher import Enricher
from workers.enrichment.geo import GeoIPLookup
from workers.enrichment.rdns import ReverseDns

logger = structlog.get_logger()

MAX_CONCURRENT_LOOKUPS = 10


@dataclass
class _SessionSeen:
    world_id: str
    ip: IPv4Address | IPv6Address
    first_seen: datetime
    last_seen: datetime


class SessionEnricher(StreamConsumer):
    def __init__(
        self,
        redis: Redis,
        stream: str,
        sessions: async_sessionmaker[AsyncSession],
        enricher: Enricher,
        *,
        group: str = "enrichment",
        consumer: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            redis, stream, group, consumer or f"{socket.gethostname()}-{os.getpid()}", **kwargs
        )
        self.sessions = sessions
        self.enricher = enricher

    async def handle(self, entries: list[StreamEntry]) -> None:
        seen: dict[UUID, _SessionSeen] = {}
        malformed = 0
        for _entry_id, fields in entries:
            try:
                event = CapturedRequest.model_validate_json(fields["data"])
            except (KeyError, ValidationError):
                malformed += 1
                continue
            current = seen.get(event.session_id)
            if current is None:
                seen[event.session_id] = _SessionSeen(event.world_id, event.ip, event.ts, event.ts)
            else:
                current.first_seen = min(current.first_seen, event.ts)
                current.last_seen = max(current.last_seen, event.ts)

        if seen:
            known = await self._known(list(seen))
            new = [sid for sid in seen if sid not in known]
            enriched = await self._enrich(new, seen)
            rows = [_row(sid, s, enriched.get(sid)) for sid, s in seen.items()]
            await self._upsert(rows)
        if malformed:
            raise ValueError(f"{malformed} malformed event(s) in batch")

    async def _known(self, ids: list[UUID]) -> set[UUID]:
        async with self.sessions() as session:
            result = await session.scalars(
                select(sessions_table.c.id).where(sessions_table.c.id.in_(ids))
            )
            return set(result)

    async def _enrich(self, ids: list[UUID], seen: dict[UUID, _SessionSeen]) -> dict[UUID, Any]:
        gate = asyncio.Semaphore(MAX_CONCURRENT_LOOKUPS)

        async def one(sid: UUID) -> tuple[UUID, Any]:
            async with gate:
                return sid, await self.enricher.enrich(seen[sid].ip)

        return dict(await asyncio.gather(*(one(sid) for sid in ids)))

    async def _upsert(self, rows: list[dict[str, Any]]) -> None:
        statement = insert(sessions_table).values(rows)
        statement = statement.on_conflict_do_update(
            index_elements=["id"],
            # Enrichment columns of an existing session are left alone.
            set_={
                "first_seen": func.least(
                    sessions_table.c.first_seen, statement.excluded.first_seen
                ),
                "last_seen": func.greatest(
                    sessions_table.c.last_seen, statement.excluded.last_seen
                ),
            },
        )
        async with self.sessions.begin() as session:
            await session.execute(statement)


def _row(sid: UUID, seen: _SessionSeen, enrichment: Any) -> dict[str, Any]:
    return {
        "id": sid,
        "world_id": seen.world_id,
        "first_seen": seen.first_seen,
        "last_seen": seen.last_seen,
        "ip": str(seen.ip),
        "subnet": getattr(enrichment, "subnet", None),
        "asn": getattr(enrichment, "asn", None),
        "country": getattr(enrichment, "country", None),
        "city": getattr(enrichment, "city", None),
        "reverse_dns": getattr(enrichment, "reverse_dns", None),
        "abuse_score": getattr(enrichment, "abuse_score", None),
    }


async def main() -> None:
    settings = Settings()
    configure_logging(settings.log_level)
    redis = Redis.from_url(settings.redis_url, decode_responses=True)
    engine = create_engine(settings.database_url.get_secret_value())
    geo = GeoIPLookup(settings.geoip_city_db) if settings.geoip_city_db else None
    asn = AsnLookup(settings.geoip_asn_db) if settings.geoip_asn_db else None
    if geo is None or asn is None:
        logger.warning("enrichment_geoip_disabled", city=geo is not None, asn=asn is not None)
    async with httpx.AsyncClient(timeout=5.0) as http:
        reputation = (
            AbuseIPDBClient(http, redis, settings.abuseipdb_api_key)
            if settings.abuseipdb_api_key
            else None
        )
        enricher = Enricher(geo=geo, asn=asn, rdns=ReverseDns(), reputation=reputation)
        worker = SessionEnricher(
            redis, settings.capture_stream, create_session_factory(engine), enricher
        )
        try:
            await run_until_signalled(worker)
        finally:
            await redis.aclose()
            await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
