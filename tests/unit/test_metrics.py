import httpx
import pytest
from httpx import ASGITransport
from prometheus_client import REGISTRY

from app.asgi_types import Receive, Scope, Send
from app.capture.middleware import TIER_SCOPE_KEY, CaptureMiddleware
from app.internal import create_internal_app
from app.metrics import observe_request
from domain.captured_request import CapturedRequest


def _count(persona: str, tier: str, status: str) -> float:
    labels = {"persona": persona, "tier": tier, "status": status}
    return REGISTRY.get_sample_value("mirage_requests_total", labels) or 0.0


def _observations(persona: str, tier: str) -> float:
    labels = {"persona": persona, "tier": tier}
    return REGISTRY.get_sample_value("mirage_request_duration_seconds_count", labels) or 0.0


async def test_request_is_counted_per_persona_tier_and_status(client: httpx.AsyncClient) -> None:
    before = _count("fake_api", "0", "200")

    response = await client.get("/api/v1/products")

    assert response.status_code == 200
    assert _count("fake_api", "0", "200") == before + 1


async def test_unknown_path_is_counted_for_the_catch_all_persona(client: httpx.AsyncClient) -> None:
    before = _count("catch_all", "0", "404")

    await client.get("/phpmyadmin/")

    assert _count("catch_all", "0", "404") == before + 1


async def test_duration_is_observed_for_every_request(client: httpx.AsyncClient) -> None:
    before = _observations("fake_api", "0")

    await client.get("/api/v1/products")
    await client.get("/api/v1/products")

    assert _observations("fake_api", "0") == before + 2


async def test_internal_metrics_endpoint_shows_request_series(client: httpx.AsyncClient) -> None:
    await client.get("/api/v1/products")

    transport = ASGITransport(app=create_internal_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as internal:
        text = (await internal.get("/metrics")).text

    assert 'mirage_requests_total{persona="fake_api",status="200",tier="0"}' in text
    assert "mirage_request_duration_seconds_bucket" in text


def test_missing_status_is_labelled_none() -> None:
    before = _count("default", "0", "none")

    observe_request(persona="default", tier=0, status=None, duration_s=0.001)

    assert _count("default", "0", "none") == before + 1


async def test_failing_sink_does_not_lose_the_measurement() -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        scope[TIER_SCOPE_KEY] = 1
        await send({"type": "http.response.start", "status": 503, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def sink(event: CapturedRequest) -> None:
        raise RuntimeError("redis down")

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: object) -> None:
        return None

    scope: Scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": [],
        "client": ("203.0.113.9", 1),
    }
    before = _count("default", "1", "503")

    with pytest.raises(RuntimeError, match="redis down"):
        await CaptureMiddleware(app, sink)(scope, receive, send)

    assert _count("default", "1", "503") == before + 1
