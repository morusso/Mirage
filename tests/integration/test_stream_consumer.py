import asyncio
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

import pytest
from redis.asyncio import Redis

from workers.base import StreamConsumer, StreamEntry

pytestmark = pytest.mark.integration

GROUP = "g"


class RecordingConsumer(StreamConsumer):
    def __init__(self, redis: Redis, stream: str, *, fail_times: int = 0) -> None:
        super().__init__(redis, stream, GROUP, "c1", block_ms=50, min_idle_ms=100)
        self.seen: list[str] = []
        self.calls = 0
        self.fail_times = fail_times

    async def handle(self, entries: list[StreamEntry]) -> None:
        self.calls += 1
        if self.calls <= self.fail_times:
            raise RuntimeError("boom")
        self.seen.extend(fields["n"] for _, fields in entries)


@asynccontextmanager
async def running(consumer: StreamConsumer) -> AsyncIterator[asyncio.Task[None]]:
    task = asyncio.create_task(consumer.run())
    try:
        yield task
    finally:
        consumer.stop()
        await asyncio.wait_for(task, timeout=5)


async def _wait_for(predicate: Callable[[], bool], within_s: float = 5.0) -> None:
    async with asyncio.timeout(within_s):
        while not predicate():  # noqa: ASYNC110 - polling a plain list, no event to await
            await asyncio.sleep(0.02)


async def _pending(redis: Redis, stream: str) -> int:
    summary = await redis.xpending(stream, GROUP)
    return int(summary["pending"])


def _consumer(redis: Redis, stream: str, *, fail_times: int = 0) -> RecordingConsumer:
    return RecordingConsumer(redis, stream, fail_times=fail_times)


async def test_consumes_events_published_before_start_and_acks(
    redis: Redis, stream_name: str
) -> None:
    for n in range(3):
        await redis.xadd(stream_name, {"n": str(n)})
    consumer = _consumer(redis, stream_name)

    async with running(consumer):
        await _wait_for(lambda: len(consumer.seen) == 3)
        await redis.xadd(stream_name, {"n": "3"})
        await _wait_for(lambda: len(consumer.seen) == 4)

    assert consumer.seen == ["0", "1", "2", "3"]
    assert await _pending(redis, stream_name) == 0


async def test_failed_batch_is_retried_after_idle_time_then_acked(
    redis: Redis, stream_name: str
) -> None:
    await redis.xadd(stream_name, {"n": "0"})
    consumer = _consumer(redis, stream_name, fail_times=2)

    async with running(consumer):
        await _wait_for(lambda: consumer.seen == ["0"])

    assert consumer.calls == 3
    assert await _pending(redis, stream_name) == 0


async def test_failed_batch_stays_pending_until_retried(redis: Redis, stream_name: str) -> None:
    await redis.xadd(stream_name, {"n": "0"})
    consumer = _consumer(redis, stream_name, fail_times=1_000)

    async with running(consumer):
        await _wait_for(lambda: consumer.calls >= 1)
        assert await _pending(redis, stream_name) == 1


async def test_second_consumer_takes_over_abandoned_entries(redis: Redis, stream_name: str) -> None:
    await redis.xadd(stream_name, {"n": "0"})
    await redis.xgroup_create(stream_name, GROUP, id="0")
    await redis.xreadgroup(GROUP, "dead", {stream_name: ">"}, count=1)
    consumer = _consumer(redis, stream_name)

    async with running(consumer):
        await _wait_for(lambda: consumer.seen == ["0"])

    assert await _pending(redis, stream_name) == 0


async def test_stop_returns_promptly_on_idle_stream(redis: Redis, stream_name: str) -> None:
    consumer = _consumer(redis, stream_name)
    task = asyncio.create_task(consumer.run())
    await asyncio.sleep(0.2)

    consumer.stop()

    await asyncio.wait_for(task, timeout=2)
