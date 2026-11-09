"""Unknown /api/v1 paths: static 404 with tier 1 off, model answer with it on."""

from collections.abc import AsyncIterator

import httpx
import pytest
from httpx import ASGITransport
from prometheus_client import REGISTRY

from app.config import Settings
from app.main import create_app
from tests.fakes.openai_server import FakeOpenAIServer

MODEL_JSON = '{"status_code": 200, "headers": {"x-request-id": "r1"}, "body": "{\\"data\\": []}"}'


def _count(tier: str, status: str) -> float:
    labels = {"persona": "fake_api", "tier": tier, "status": status}
    return REGISTRY.get_sample_value("mirage_requests_total", labels) or 0.0


@pytest.fixture
async def tier1_client(
    fake_llm: FakeOpenAIServer, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[httpx.AsyncClient]:
    monkeypatch.setenv("MIRAGE_LLM_LOCAL__BASE_URL", fake_llm.base_url)
    # Port 1 refuses connections: the cache behaves like an empty one.
    app = create_app(
        Settings(
            environment="test",
            internal_server_enabled=False,
            tier1_enabled=True,
            redis_url="redis://127.0.0.1:1/0",
        )
    )
    async with app.router.lifespan_context(app):
        app.state.engine.budget = None  # budgets need a live Redis; they are tested elsewhere
        transport = ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            yield c


async def test_unknown_path_is_a_static_404_while_tier1_is_off(client: httpx.AsyncClient) -> None:
    before = _count("0", "404")

    response = await client.get("/api/v1/orders")

    assert response.status_code == 404
    assert "nginx" in response.text
    assert _count("0", "404") == before + 1


async def test_unknown_path_is_answered_by_the_model(
    tier1_client: httpx.AsyncClient, fake_llm: FakeOpenAIServer
) -> None:
    fake_llm.enqueue(text=MODEL_JSON)
    before = _count("1", "200")

    response = await tier1_client.get("/api/v1/orders")

    assert response.status_code == 200
    assert response.json() == {"data": []}
    assert response.headers["x-request-id"] == "r1"
    assert response.headers["server"] == "nginx/1.24.0"
    assert _count("1", "200") == before + 1


async def test_model_outage_falls_back_to_the_static_404(
    tier1_client: httpx.AsyncClient, fake_llm: FakeOpenAIServer
) -> None:
    fake_llm.enqueue(status=503)

    response = await tier1_client.post("/api/v1/orders", json={"sku": "x"})

    assert response.status_code == 404
    assert "nginx" in response.text


async def test_known_endpoints_never_reach_the_model(
    tier1_client: httpx.AsyncClient, fake_llm: FakeOpenAIServer
) -> None:
    response = await tier1_client.get("/api/v1/products")

    assert response.status_code == 200
    assert fake_llm.requests == []
