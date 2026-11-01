import hashlib
from datetime import UTC, datetime
from ipaddress import ip_address
from uuid import uuid4

import httpx
import pytest
from httpx import ASGITransport
from redis.asyncio import Redis

from app.capture.publisher import StreamPublisher
from app.config import Settings
from app.main import create_app
from domain.captured_request import CapturedRequest

pytestmark = pytest.mark.integration


async def _events_in(redis: Redis, stream: str) -> list[CapturedRequest]:
    entries = await redis.xrange(stream)
    assert entries is not None
    events = []
    for _entry_id, fields in entries:
        assert fields is not None
        events.append(CapturedRequest.model_validate_json(str(fields["data"])))
    return events


def _event(path: str = "/.env") -> CapturedRequest:
    return CapturedRequest(
        ts=datetime(2026, 1, 1, tzinfo=UTC),
        session_id=uuid4(),
        world_id="w_x",
        ip=ip_address("203.0.113.1"),
        method="GET",
        path=path,
    )


async def test_publisher_writes_event_to_stream(redis: Redis, stream_name: str) -> None:
    event = _event()

    published = await StreamPublisher(redis, stream_name, maxlen=1000).publish(event)

    assert published is True
    assert await _events_in(redis, stream_name) == [event]


async def test_stream_is_trimmed_approximately(redis: Redis, stream_name: str) -> None:
    publisher = StreamPublisher(redis, stream_name, maxlen=10)

    for i in range(1000):
        await publisher.publish(_event(f"/p/{i}"))

    length = await redis.xlen(stream_name)
    # MAXLEN ~ trims whole radix-tree nodes, so a little over maxlen may remain.
    assert 10 <= length <= 200


async def test_unreachable_redis_does_not_raise() -> None:
    dead = Redis.from_url("redis://127.0.0.1:1/0")
    try:
        publisher = StreamPublisher(dead, "s", maxlen=10, timeout_s=0.5)

        assert await publisher.publish(_event()) is False
    finally:
        await dead.aclose()


async def test_request_through_the_app_lands_in_the_stream(
    redis_url: str, redis: Redis, stream_name: str
) -> None:
    settings = Settings(
        environment="test",
        internal_server_enabled=False,
        redis_url=redis_url,
        capture_stream=stream_name,
    )
    app = create_app(settings)
    body = b'{"email":"a@example.com","password":"hunter2"}'

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client,
    ):
        response = await client.post(
            "/api/v1/auth/login?x=1",
            content=body,
            headers={"user-agent": "integration-test", "content-type": "application/json"},
        )

    assert response.status_code == 401  # unknown e-mail, but the request is still captured
    (event,) = await _events_in(redis, stream_name)
    assert (event.method, event.path, event.query) == ("POST", "/api/v1/auth/login", "x=1")
    assert event.body_excerpt == body.decode()
    assert event.body_sha256 == hashlib.sha256(body).hexdigest()
    assert dict(event.headers)["user-agent"] == "integration-test"
    assert event.world_id.startswith("w_")
    assert (event.persona, event.status, event.tier) == ("fake_api", 401, 0)
    assert event.latency_ms is not None
