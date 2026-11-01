import asyncio
import json
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import cast

import pytest
from redis.asyncio import Redis

from workers.base import StreamConsumer, StreamEntry

pytestmark = pytest.mark.integration

GROUP = "g"
MAX_DELIVERIES = 3


class RecordingConsumer(StreamConsumer):
    def __init__(self, redis: Redis, stream: str, *, fail_times: int = 0) -> None:
        super().__init__(
            redis, stream, GROUP, "c1", block_ms=50, min_idle_ms=100, max_deliveries=MAX_DELIVERIES
        )
        self.seen: list[str] = []
        self.calls = 0
        self.poison_calls = 0
        self.fail_times = fail_times

    async def handle(self, entries: list[StreamEntry]) -> None:
        self.calls += 1
        if self.calls <= self.fail_times:
            raise RuntimeError("boom")
        if any("poison" in fields for _, fields in entries):
            self.poison_calls += 1
            raise ValueError("poison")
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


async def _dead_letters(redis: Redis, stream: str) -> list[dict[str, str]]:
    entries = await redis.xrange(f"{stream}:dead")
    return [cast("dict[str, str]", fields) for _, fields in entries or []]


async def test_poison_event_is_dead_lettered_without_hurting_healthy_neighbours(
    redis: Redis, stream_name: str
) -> None:
    await redis.xadd(stream_name, {"n": "0"})
    poison_id = await redis.xadd(stream_name, {"n": "1", "poison": "1"})
    await redis.xadd(stream_name, {"n": "2"})
    consumer = _consumer(redis, stream_name)

    async with running(consumer):
        await _wait_for(lambda: consumer.poison_calls >= MAX_DELIVERIES)
        await _wait_for(lambda: sorted(consumer.seen) == ["0", "2"])
        assert await _pending(redis, stream_name) == 0

    dead = await _dead_letters(redis, stream_name)
    assert len(dead) == 1
    assert dead[0]["original_id"] == poison_id
    assert dead[0]["deliveries"] == str(MAX_DELIVERIES)
    assert dead[0]["reason"] == "ValueError"
    assert json.loads(dead[0]["fields"]) == {"n": "1", "poison": "1"}
    assert consumer.poison_calls == MAX_DELIVERIES


async def test_transient_failure_does_not_reach_dead_letter_stream(
    redis: Redis, stream_name: str
) -> None:
    await redis.xadd(stream_name, {"n": "0"})
    consumer = _consumer(redis, stream_name, fail_times=2)

    async with running(consumer):
        await _wait_for(lambda: consumer.seen == ["0"])

    assert await _dead_letters(redis, stream_name) == []


async def test_entry_delivered_too_often_is_dead_lettered_without_handling(
    redis: Redis, stream_name: str
) -> None:
    await redis.xadd(stream_name, {"n": "0"})
    await redis.xgroup_create(stream_name, GROUP, id="0")
    await redis.xreadgroup(GROUP, "crashy", {stream_name: ">"}, count=1)
    for _ in range(MAX_DELIVERIES):  # each claim counts as a delivery
        await redis.xautoclaim(stream_name, GROUP, "crashy", min_idle_time=0, start_id="0-0")
    await asyncio.sleep(0.15)
    consumer = _consumer(redis, stream_name)

    async with running(consumer):
        async with asyncio.timeout(5):
            while not await _dead_letters(redis, stream_name):  # noqa: ASYNC110
                await asyncio.sleep(0.02)

    dead = await _dead_letters(redis, stream_name)
    assert [d["reason"] for d in dead] == ["max_deliveries_exceeded"]
    assert consumer.calls == 0
    assert await _pending(redis, stream_name) == 0
