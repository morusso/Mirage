import asyncio
import contextlib
import json
import signal
from abc import ABC, abstractmethod
from typing import cast

import structlog
from redis.asyncio import Redis
from redis.exceptions import RedisError, ResponseError

logger = structlog.get_logger()

StreamEntry = tuple[str, dict[str, str]]


class StreamConsumer(ABC):
    """Consumer-group worker over a Redis Stream: XREADGROUP, XACK, retry, graceful stop.

    Delivery is at-least-once. A batch is acknowledged only after ``handle`` returns;
    if it raises, the entries stay in the group's pending list and are claimed again
    (XAUTOCLAIM) once they have been idle for ``min_idle_ms``, which doubles as the
    retry delay. Handlers must therefore be idempotent (the persister inserts with
    ON CONFLICT DO NOTHING on ``event_id``).

    Several instances can share a group under different ``consumer`` names; any of
    them also picks up entries abandoned by a crashed peer.

    Poison events: retried entries are handled one at a time, so a bad event cannot
    drag healthy neighbours down with it. After ``max_deliveries`` deliveries an
    entry is moved to the dead-letter stream (``<stream>:dead`` by default) and
    acknowledged, so it stops blocking the group but is never silently lost.
    """

    def __init__(
        self,
        redis: Redis,
        stream: str,
        group: str,
        consumer: str,
        *,
        batch_size: int = 100,
        block_ms: int = 1000,
        min_idle_ms: int = 30_000,
        max_deliveries: int = 5,
        dead_letter_stream: str | None = None,
        dead_letter_maxlen: int = 100_000,
    ) -> None:
        self.redis = redis
        self.stream = stream
        self.group = group
        self.consumer = consumer
        self.batch_size = batch_size
        self.block_ms = block_ms
        self.min_idle_ms = min_idle_ms
        self.max_deliveries = max_deliveries
        self.dead_letter_stream = dead_letter_stream or f"{stream}:dead"
        self.dead_letter_maxlen = dead_letter_maxlen
        self._stopping = asyncio.Event()

    @abstractmethod
    async def handle(self, entries: list[StreamEntry]) -> None:
        """Process a batch. Raise to leave it unacknowledged for a later retry."""

    def stop(self) -> None:
        """Ask ``run`` to return after the batch in flight. Safe to call from a signal handler."""
        self._stopping.set()

    async def run(self) -> None:
        await self._ensure_group()
        logger.info("consumer_started", stream=self.stream, group=self.group)
        while not self._stopping.is_set():
            try:
                await self._retry(await self._claim_stale())
                await self._process(await self._read_new())
            except (RedisError, OSError) as exc:
                logger.error("consumer_redis_error", stream=self.stream, error=type(exc).__name__)
                await self._sleep(1.0)
        logger.info("consumer_stopped", stream=self.stream, group=self.group)

    async def _ensure_group(self) -> None:
        try:
            await self.redis.xgroup_create(self.stream, self.group, id="0", mkstream=True)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def _claim_stale(self) -> list[StreamEntry]:
        result = await self.redis.xautoclaim(
            self.stream,
            self.group,
            self.consumer,
            min_idle_time=self.min_idle_ms,
            start_id="0-0",
            count=self.batch_size,
        )
        deleted = result[2] if len(result) > 2 else []
        if deleted:
            logger.error("consumer_entries_lost", stream=self.stream, count=len(deleted))
        return _entries(result[1])

    async def _read_new(self) -> list[StreamEntry]:
        result = cast(
            "list[tuple[str, list[tuple[str, dict[str, str] | None]]]]",
            await self.redis.xreadgroup(
                self.group,
                self.consumer,
                {self.stream: ">"},
                count=self.batch_size,
                block=self.block_ms,
            ),
        )
        if not result:
            return []
        return _entries(result[0][1])

    async def _process(self, entries: list[StreamEntry]) -> None:
        if not entries:
            return
        try:
            await self.handle(entries)
        except Exception as exc:
            # Log the type only: entries hold attacker-controlled payloads.
            logger.error(
                "consumer_handler_failed",
                stream=self.stream,
                batch=len(entries),
                error=type(exc).__name__,
            )
            return
        await self.redis.xack(self.stream, self.group, *(entry_id for entry_id, _ in entries))

    async def _retry(self, entries: list[StreamEntry]) -> None:
        """Handle reclaimed entries one by one, dead-lettering those that keep failing."""
        for entry in entries:
            entry_id = entry[0]
            deliveries = await self._deliveries(entry_id)
            if deliveries > self.max_deliveries:
                # Delivered too often without an outcome (e.g. the worker crashes on it).
                await self._dead_letter(entry, deliveries, "max_deliveries_exceeded")
                continue
            try:
                await self.handle([entry])
            except Exception as exc:
                logger.error(
                    "consumer_handler_failed",
                    stream=self.stream,
                    batch=1,
                    deliveries=deliveries,
                    error=type(exc).__name__,
                )
                if deliveries >= self.max_deliveries:
                    await self._dead_letter(entry, deliveries, type(exc).__name__)
                continue
            await self.redis.xack(self.stream, self.group, entry_id)

    async def _deliveries(self, entry_id: str) -> int:
        rows = cast(
            "list[dict[str, int | str]]",
            await self.redis.xpending_range(self.stream, self.group, entry_id, entry_id, 1),
        )
        return int(rows[0]["times_delivered"]) if rows else 0

    async def _dead_letter(self, entry: StreamEntry, deliveries: int, reason: str) -> None:
        """Copy the entry to the dead-letter stream, then ack it.

        If the XADD fails the entry stays pending and is tried again; a crash between
        XADD and XACK can duplicate it in the dead-letter stream, never lose it.
        """
        entry_id, fields = entry
        await self.redis.xadd(
            self.dead_letter_stream,
            {
                "original_id": entry_id,
                "stream": self.stream,
                "group": self.group,
                "deliveries": str(deliveries),
                "reason": reason,
                "fields": json.dumps(fields),
            },
            maxlen=self.dead_letter_maxlen,
            approximate=True,
        )
        await self.redis.xack(self.stream, self.group, entry_id)
        logger.error(
            "consumer_dead_lettered",
            stream=self.stream,
            entry_id=entry_id,
            deliveries=deliveries,
            reason=reason,
        )

    async def _sleep(self, seconds: float) -> None:
        """Sleep that ends early on stop()."""
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._stopping.wait(), timeout=seconds)


async def run_until_signalled(consumer: StreamConsumer) -> None:
    """Run a consumer until SIGTERM/SIGINT, then let it finish the batch in flight."""
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, consumer.stop)
    await consumer.run()


def _entries(raw: list[tuple[str, dict[str, str] | None]]) -> list[StreamEntry]:
    return [(entry_id, fields) for entry_id, fields in raw if fields is not None]
