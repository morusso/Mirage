import socket

import httpx
from httpx import ASGITransport

from app.config import Settings
from app.internal import create_internal_app
from app.main import create_app


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


async def test_health_returns_ok() -> None:
    transport = ASGITransport(app=create_internal_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_public_app_does_not_expose_health(client: httpx.AsyncClient) -> None:
    for path in ("/health", "/healthz"):
        assert (await client.get(path)).status_code == 404


async def test_internal_server_runs_on_separate_port_during_lifespan() -> None:
    port = _free_port()
    app = create_app(Settings(environment="test", internal_port=port))

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient() as client:
            response = await client.get(f"http://127.0.0.1:{port}/health")
        assert response.status_code == 200

    # Server is shut down together with the app.
    with socket.socket() as s:
        assert s.connect_ex(("127.0.0.1", port)) != 0
