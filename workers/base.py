import asyncio
import contextlib
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
    ) -> None:
        self.redis = redis
        self.stream = stream
        self.group = group
        self.consumer = consumer
        self.batch_size = batch_size
        self.block_ms = block_ms
        self.min_idle_ms = min_idle_ms
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
                await self._process(await self._claim_stale())
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

    async def _sleep(self, seconds: float) -> None:
        """Sleep that ends early on stop()."""
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._stopping.wait(), timeout=seconds)


def _entries(raw: list[tuple[str, dict[str, str] | None]]) -> list[StreamEntry]:
    return [(entry_id, fields) for entry_id, fields in raw if fields is not None]
