from collections.abc import AsyncIterator

import httpx
import pytest
from httpx import ASGITransport

from app.config import Settings
from app.main import create_app


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(Settings(environment="test", internal_server_enabled=False))
    transport = ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://test") as c,
    ):
        yield c
