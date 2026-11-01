import asyncio
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any
from uuid import uuid4

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from app.capture.publisher import StreamPublisher
from domain.captured_request import CapturedRequest


class FakeRedis:
    def __init__(self, *, error: Exception | None = None, delay_s: float = 0) -> None:
        self.calls: list[tuple[str, dict[str, str], dict[str, Any]]] = []
        self.error = error
        self.delay_s = delay_s

    async def xadd(self, name: str, fields: dict[str, str], **kwargs: Any) -> str:
        await asyncio.sleep(self.delay_s)
        if self.error:
            raise self.error
        self.calls.append((name, fields, kwargs))
        return "1-0"


def _event() -> CapturedRequest:
    return CapturedRequest(
        ts=datetime(2026, 1, 1, tzinfo=UTC),
        session_id=uuid4(),
        world_id="w_x",
        ip=ip_address("203.0.113.1"),
        method="GET",
        path="/.env",
    )


def _publisher(redis: FakeRedis, **kwargs: Any) -> StreamPublisher:
    return StreamPublisher(redis, "mirage:events", maxlen=500, **kwargs)  # type: ignore[arg-type]


async def test_publishes_json_with_approximate_maxlen() -> None:
    redis = FakeRedis()
    event = _event()

    assert await _publisher(redis).publish(event) is True

    ((stream, fields, kwargs),) = redis.calls
    assert stream == "mirage:events"
    assert kwargs == {"maxlen": 500, "approximate": True}
    assert CapturedRequest.model_validate_json(fields["data"]) == event


async def test_redis_error_is_swallowed_and_logged_without_payload(
    capsys: pytest.CaptureFixture[str],
) -> None:
    event = _event()
    redis = FakeRedis(error=RedisConnectionError("down"))

    assert await _publisher(redis).publish(event) is False

    out = capsys.readouterr().out
    assert str(event.event_id) in out
    assert "capture_publish_failed" in out
    assert "/.env" not in out


async def test_slow_redis_times_out_instead_of_blocking_the_request() -> None:
    redis = FakeRedis(delay_s=1)

    assert await _publisher(redis, timeout_s=0.01).publish(_event()) is False


async def test_os_errors_are_swallowed() -> None:
    assert await _publisher(FakeRedis(error=OSError("net"))).publish(_event()) is False
