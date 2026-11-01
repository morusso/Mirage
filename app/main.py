from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from redis.asyncio import Redis

from app.config import Settings
from app.internal import run_internal_server
from app.log import configure_logging
from app.personas import catch_all, fake_api
from app.personas.base import PersonaHeadersMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    # Connects lazily, so the app starts even if Redis is briefly unavailable.
    redis = Redis.from_url(settings.redis_url, decode_responses=True)
    app.state.redis = redis
    try:
        async with run_internal_server(settings):
            yield
    finally:
        await redis.aclose()


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    configure_logging(settings.log_level)
    app = FastAPI(
        lifespan=lifespan,
        # A honeypot must not advertise FastAPI's own docs endpoints.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.add_middleware(PersonaHeadersMiddleware)
    app.include_router(fake_api.router)
    # Must stay last: it matches every path not claimed by a more specific router.
    app.include_router(catch_all.router)
    app.state.settings = settings
    return app
