import httpx


async def test_app_starts_and_responds(client: httpx.AsyncClient) -> None:
    response = await client.get("/")

    assert response.status_code == 404
