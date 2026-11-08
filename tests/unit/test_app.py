from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from redis.asyncio import Redis

from app.config import Settings
from app.engine.engine import ResponseEngine
from app.main import create_app


async def test_lifespan_runs_and_settings_are_attached() -> None:
    settings = Settings(environment="test")
    app = create_app(settings)

    async with app.router.lifespan_context(app):
        assert app.state.settings is settings


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
async def test_framework_docs_are_not_exposed(client: httpx.AsyncClient, path: str) -> None:
    response = await client.get(path)

    assert response.status_code == 404


async def test_lifespan_provides_redis_client_and_closes_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[bool] = []
    original = Redis.aclose

    async def spy(self: Redis, *args: Any, **kwargs: Any) -> None:
        closed.append(True)
        await original(self, *args, **kwargs)

    monkeypatch.setattr(Redis, "aclose", spy)
    app = create_app(Settings(environment="test", internal_server_enabled=False))

    async with app.router.lifespan_context(app):
        assert isinstance(app.state.redis, Redis)
        assert closed == []

    assert closed == [True]


async def test_redis_client_uses_configured_url() -> None:
    settings = Settings(
        environment="test",
        internal_server_enabled=False,
        redis_url="redis://cache.internal:6380/3",
    )
    app = create_app(settings)

    async with app.router.lifespan_context(app):
        kwargs = app.state.redis.connection_pool.connection_kwargs
        assert (kwargs["host"], kwargs["port"], kwargs["db"]) == ("cache.internal", 6380, 3)


async def test_engine_is_absent_while_tier1_is_disabled(app: FastAPI) -> None:
    assert app.state.engine is None


async def test_engine_is_built_when_tier1_is_enabled() -> None:
    app = create_app(
        Settings(environment="test", internal_server_enabled=False, tier1_enabled=True)
    )

    async with app.router.lifespan_context(app):
        assert isinstance(app.state.engine, ResponseEngine)
