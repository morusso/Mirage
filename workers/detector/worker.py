"""Detector worker: runs every detection rule over captured requests.

A consumer group of its own on the capture stream (``detector``), independent of the
persister. Detections reference the ``requests`` row by id, which only the persister
creates, so the detector looks the id up and, if the row is not there yet, fails the
batch: the entries stay pending and are retried after the idle period, by which time
the persister has caught up. Inserts are idempotent (unique index on
request_id, request_ts, rule), so retries and redelivery are harmless.
"""

import asyncio
import os
import socket
from typing import Any

import structlog
from pydantic import ValidationError
from redis.asyncio import Redis
from sqlalchemy import select, tuple_
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import Settings
from app.log import configure_logging
from domain.captured_request import CapturedRequest
from domain.db import create_engine, create_session_factory
from domain.tables import detections, requests
from workers.base import StreamConsumer, StreamEntry, run_until_signalled
from workers.detector import cmdi, log4shell, scanners, sqli, ssti, traversal, xss
from workers.detector.rules import RuleRegistry

logger = structlog.get_logger()

FAMILIES = (sqli, xss, ssti, traversal, cmdi, log4shell, scanners)


def build_registry() -> RuleRegistry:
    registry = RuleRegistry()
    for family in FAMILIES:
        for rule in family.RULES:
            registry.register(rule)
    return registry


class Detector(StreamConsumer):
    def __init__(
        self,
        redis: Redis,
        stream: str,
        sessions: async_sessionmaker[AsyncSession],
        registry: RuleRegistry | None = None,
        *,
        group: str = "detector",
        consumer: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            redis, stream, group, consumer or f"{socket.gethostname()}-{os.getpid()}", **kwargs
        )
        self.sessions = sessions
        self.registry = registry or build_registry()

    async def handle(self, entries: list[StreamEntry]) -> None:
        rows: list[dict[str, Any]] = []
        keys: dict[tuple[Any, Any], list[dict[str, Any]]] = {}
        malformed = 0
        for _entry_id, fields in entries:
            try:
                event = CapturedRequest.model_validate_json(fields["data"])
            except (KeyError, ValidationError):
                malformed += 1
                continue
            for detection in self.registry.evaluate(event):
                row = {
                    "request_ts": event.ts,
                    "session_id": event.session_id,
                    "rule": detection.rule,
                    "category": detection.category,
                    "severity": detection.severity.value,
                    "matched_excerpt": detection.matched_excerpt,
                }
                keys.setdefault((event.event_id, event.ts), []).append(row)

        missing = 0
        if keys:
            async with self.sessions.begin() as session:
                found = {
                    (event_id, ts): request_id
                    for event_id, ts, request_id in await session.execute(
                        select(requests.c.event_id, requests.c.ts, requests.c.id).where(
                            tuple_(requests.c.event_id, requests.c.ts).in_(list(keys))
                        )
                    )
                }
                for key, key_rows in keys.items():
                    if key in found:
                        rows.extend({**r, "request_id": found[key]} for r in key_rows)
                    else:
                        missing += 1
                if rows:
                    await session.execute(
                        insert(detections)
                        .values(rows)
                        .on_conflict_do_nothing(index_elements=["request_id", "request_ts", "rule"])
                    )
        if missing:
            raise LookupError(f"{missing} request(s) not persisted yet; retrying later")
        if malformed:
            raise ValueError(f"{malformed} malformed event(s) in batch")


async def main() -> None:
    settings = Settings()
    configure_logging(settings.log_level)
    redis = Redis.from_url(settings.redis_url, decode_responses=True)
    engine = create_engine(settings.database_url.get_secret_value())
    detector = Detector(redis, settings.capture_stream, create_session_factory(engine))
    try:
        await run_until_signalled(detector)
    finally:
        await redis.aclose()
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
