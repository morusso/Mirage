from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from httpx import ASGITransport

from app.config import Settings
from app.main import create_app


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
