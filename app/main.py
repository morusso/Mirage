from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import Settings
from app.internal import run_internal_server
from app.log import configure_logging
from app.personas import catch_all
from app.personas.base import PersonaHeadersMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    async with run_internal_server(app.state.settings):
        yield


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
    # Must stay last: it matches every path not claimed by a more specific router.
    app.include_router(catch_all.router)
    app.state.settings = settings
    return app
