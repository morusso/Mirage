import httpx


async def test_client_fixture_works(client: httpx.AsyncClient) -> None:
    response = await client.get("/")

    assert response.status_code == 200
