import httpx
import pytest

GET_ROUTES = [
    "/api/v1/products",
    "/api/v1/products/1",
    "/swagger.json",
    "/.env",
    "/wp-login.php",
    "/readme.html",
    "/xmlrpc.php",
    "/wp-json/wp/v2/users",
    "/phpmyadmin/",
    "/phpmyadmin/README",
    "/pma/index.php",
    "/.git/config",
    "/wp-config.php.bak",
    "/.aws/credentials",
    "/actuator",
    "/actuator/health",
]


@pytest.mark.parametrize("path", GET_ROUTES)
async def test_head_gets_the_same_status_and_headers_as_get(
    client: httpx.AsyncClient, path: str
) -> None:
    get = await client.get(path)
    head = await client.head(path)

    assert head.status_code == get.status_code
    assert head.headers["content-type"] == get.headers["content-type"]
    assert head.headers["server"] == get.headers["server"]
    assert head.content == b""


async def test_head_on_a_post_only_route_is_not_invented(client: httpx.AsyncClient) -> None:
    response = await client.head("/api/v1/auth/login")

    assert response.status_code == 404  # falls through to the catch-all, as before


async def test_head_on_unknown_path_is_404(client: httpx.AsyncClient) -> None:
    assert (await client.head("/nothing-here")).status_code == 404
