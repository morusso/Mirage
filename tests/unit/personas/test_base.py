import httpx
from fastapi import APIRouter, Depends, FastAPI
from httpx import ASGITransport

from app.personas.base import (
    DEFAULT_PERSONA,
    PersonaConfig,
    PersonaHeadersMiddleware,
    persona_dependency,
)

ADMIN = PersonaConfig(name="admin", server="nginx/1.18.0 (Ubuntu)", powered_by="PHP/8.1.2")
API = PersonaConfig(name="api", server="nginx/1.24.0")


def _build_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(PersonaHeadersMiddleware)

    admin = APIRouter(dependencies=[Depends(persona_dependency(ADMIN))])
    api = APIRouter(dependencies=[Depends(persona_dependency(API))])

    @admin.get("/admin/ping")
    async def admin_ping() -> dict[str, str]:
        return {}

    @api.get("/api/ping")
    async def api_ping() -> dict[str, str]:
        return {}

    app.include_router(admin)
    app.include_router(api)
    return app


async def _get(path: str) -> httpx.Response:
    transport = ASGITransport(app=_build_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.get(path)


async def test_persona_headers_are_applied() -> None:
    response = await _get("/admin/ping")

    assert response.headers.get_list("server") == ["nginx/1.18.0 (Ubuntu)"]
    assert response.headers["x-powered-by"] == "PHP/8.1.2"


async def test_persona_without_powered_by_omits_header() -> None:
    response = await _get("/api/ping")

    assert response.headers["server"] == "nginx/1.24.0"
    assert "x-powered-by" not in response.headers


async def test_unmatched_route_uses_default_persona() -> None:
    response = await _get("/nope")

    assert response.status_code == 404
    assert response.headers.get_list("server") == [DEFAULT_PERSONA.server]
    assert "x-powered-by" not in response.headers


async def test_app_sets_default_persona_headers(client: httpx.AsyncClient) -> None:
    response = await client.get("/")

    assert response.headers["server"] == DEFAULT_PERSONA.server
