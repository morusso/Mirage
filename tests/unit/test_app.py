import httpx
import pytest

from app.config import Settings
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
