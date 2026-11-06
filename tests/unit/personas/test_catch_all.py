import httpx
import pytest

from app.personas.base import DEFAULT_PERSONA
from app.personas.errors import nginx_404_page


@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def test_unknown_path_returns_nginx_404_for_every_method(
    client: httpx.AsyncClient, method: str
) -> None:
    response = await client.request(method, "/wp-admin/setup-config.php?step=1", content=b"x=1")

    assert response.status_code == 404
    assert response.text == nginx_404_page(DEFAULT_PERSONA)


async def test_head_returns_404_without_body(client: httpx.AsyncClient) -> None:
    response = await client.head("/nothing-here")

    assert response.status_code == 404
    assert response.content == b""


async def test_response_headers_look_like_nginx(client: httpx.AsyncClient) -> None:
    response = await client.get("/nothing-here")

    assert response.headers["content-type"] == "text/html"
    assert response.headers.get_list("server") == [DEFAULT_PERSONA.server]


async def test_root_and_deep_paths_are_handled(client: httpx.AsyncClient) -> None:
    for path in ("/", "/a/b/c/d/e/f", "/%2e%2e/etc/passwd"):
        assert (await client.get(path)).status_code == 404
