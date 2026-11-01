import httpx
import pytest

from app.personas.fake_api import MAX_PAGE_SIZE, PRODUCTS


async def test_list_returns_first_page_with_meta(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/products")

    body = response.json()
    assert response.status_code == 200
    assert len(body["data"]) == 10
    assert body["meta"] == {"page": 1, "limit": 10, "total": len(PRODUCTS)}


async def test_list_pagination(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/products", params={"page": 2, "limit": 5})

    ids = [p["id"] for p in response.json()["data"]]
    assert ids == [6, 7, 8, 9, 10]


async def test_list_beyond_last_page_is_empty(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/products", params={"page": 99})

    assert response.status_code == 200
    assert response.json()["data"] == []


@pytest.mark.parametrize(
    ("params", "expected_page", "expected_limit"),
    [
        ({"page": "abc", "limit": "xyz"}, 1, 10),
        ({"page": "-3", "limit": "0"}, 1, 1),
        ({"limit": "100000"}, 1, MAX_PAGE_SIZE),
    ],
)
async def test_list_invalid_params_never_produce_framework_errors(
    client: httpx.AsyncClient, params: dict[str, str], expected_page: int, expected_limit: int
) -> None:
    response = await client.get("/api/v1/products", params=params)

    assert response.status_code == 200
    meta = response.json()["meta"]
    assert (meta["page"], meta["limit"]) == (expected_page, expected_limit)


async def test_get_product(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/products/3")

    assert response.status_code == 200
    assert response.json()["data"]["id"] == 3


@pytest.mark.parametrize("product_id", ["9999", "abc", "-1", "1.5", "1%20OR%201=1"])
async def test_unknown_product_returns_json_404(client: httpx.AsyncClient, product_id: str) -> None:
    response = await client.get(f"/api/v1/products/{product_id}")

    assert response.status_code == 404
    assert response.json() == {"error": "Not Found", "message": "Product not found"}


async def test_responses_use_express_style_headers(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/products")

    assert response.headers["content-type"] == "application/json; charset=utf-8"
    assert response.headers["x-powered-by"] == "Express"
    assert response.headers.get_list("server") == ["nginx/1.24.0"]
