from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from httpx import ASGITransport

from app.config import Settings
from app.main import create_app
from tests.fakes.openai_server import FakeOpenAIServer, running_fake_openai_server


@pytest.fixture
async def app() -> AsyncIterator[FastAPI]:
    app = create_app(Settings(environment="test", internal_server_enabled=False))
    async with app.router.lifespan_context(app):
        yield app


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture
async def fake_llm() -> AsyncIterator[FakeOpenAIServer]:
    """A fake OpenAI-compatible server on a random local port (see tests/fakes)."""
    async with running_fake_openai_server() as server:
        yield server
