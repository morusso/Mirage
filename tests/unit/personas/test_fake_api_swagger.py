import httpx
import pytest

from app.personas.fake_api import SWAGGER_SPEC


async def test_swagger_json_is_served(client: httpx.AsyncClient) -> None:
    response = await client.get("/swagger.json")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json; charset=utf-8"
    assert response.headers["x-powered-by"] == "Express"
    assert response.json()["openapi"].startswith("3.")


def _documented_operations() -> list[tuple[str, str]]:
    return [
        (method.upper(), path) for path, item in SWAGGER_SPEC["paths"].items() for method in item
    ]


@pytest.mark.parametrize(("method", "path"), _documented_operations())
async def test_every_documented_operation_is_implemented(
    client: httpx.AsyncClient, method: str, path: str
) -> None:
    """Guards against the bait spec drifting from the router (a giveaway for scanners)."""
    base = SWAGGER_SPEC["servers"][0]["url"]
    url = base + path.replace("{id}", "1")

    response = await client.request(method, url, json={})

    # The nginx catch-all page is text/html; every real operation answers with JSON.
    assert response.headers["content-type"].startswith("application/json")
