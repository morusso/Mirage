from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from redis.asyncio import Redis

from app.capture.middleware import CaptureMiddleware, Sink
from app.capture.publisher import StreamPublisher
from app.config import Settings
from app.internal import run_internal_server
from app.log import configure_logging
from app.personas import catch_all, fake_api, phpmyadmin, wordpress
from app.personas.base import PersonaHeadersMiddleware
from domain.captured_request import CapturedRequest


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    # Connects lazily, so the app starts even if Redis is briefly unavailable.
    redis = Redis.from_url(settings.redis_url, decode_responses=True)
    app.state.redis = redis
    app.state.publisher = StreamPublisher(
        redis,
        settings.capture_stream,
        maxlen=settings.capture_stream_maxlen,
        timeout_s=settings.capture_publish_timeout_s,
    )
    try:
        async with run_internal_server(settings):
            yield
    finally:
        await redis.aclose()


def _publish_sink(app: FastAPI) -> Sink:
    """Sink that looks the publisher up per request: it only exists once the lifespan ran."""

    async def sink(event: CapturedRequest) -> None:
        publisher: StreamPublisher | None = getattr(app.state, "publisher", None)
        if publisher is not None:
            await publisher.publish(event)

    return sink


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
    # Added last so it is outermost: every request is recorded before anything else runs.
    app.add_middleware(
        CaptureMiddleware,
        sink=_publish_sink(app),
        trusted_proxies=settings.trusted_proxies,
    )
    app.include_router(fake_api.router)
    app.include_router(wordpress.router)
    app.include_router(phpmyadmin.router)
    # Must stay last: it matches every path not claimed by a more specific router.
    app.include_router(catch_all.router)
    app.state.settings = settings
    return app
