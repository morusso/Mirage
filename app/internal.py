"""Internal-only HTTP server: health and Prometheus metrics.

It runs on a separate port that is never published, so the public honeypot
surface does not expose endpoints like /healthz or /metrics. Prometheus scrapes
it over the internal network.
"""

import asyncio
from collections.abc import AsyncIterator, Generator
from contextlib import asynccontextmanager, contextmanager

import uvicorn
from fastapi import FastAPI, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.config import Settings


class _InternalServer(uvicorn.Server):
    @contextmanager
    def capture_signals(self) -> Generator[None, None, None]:
        # The public server owns SIGINT/SIGTERM; I am stopped via should_exit.
        yield


def create_internal_app() -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/metrics")
    async def metrics() -> Response:
        # Everything registered in prometheus_client's default registry, plus the
        # process, platform and GC collectors it ships with.
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    return app


@asynccontextmanager
async def run_internal_server(settings: Settings) -> AsyncIterator[None]:
    """Serve the internal app in the background for the duration of the context."""
    if not settings.internal_server_enabled:
        yield
        return

    config = uvicorn.Config(
        create_internal_app(),
        host=settings.internal_host,
        port=settings.internal_port,
        log_config=None,
        access_log=False,
    )
    server = _InternalServer(config)
    task = asyncio.create_task(server.serve())
    try:
        while not server.started:
            if task.done():
                task.result()
                raise RuntimeError("Internal server stopped during startup")
            await asyncio.sleep(0.01)
        yield
    finally:
        server.should_exit = True
        await task
