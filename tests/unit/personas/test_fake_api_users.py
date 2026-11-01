import httpx
import pytest

from app.personas.fake_api import USERS


async def test_user_is_readable_without_authentication(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/users/2")

    body = response.json()["data"]
    assert response.status_code == 200
    assert body["id"] == 2
    assert body["email"].endswith("@example.com")


async def test_every_fixture_user_is_enumerable(client: httpx.AsyncClient) -> None:
    for user in USERS:
        assert (await client.get(f"/api/v1/users/{user.id}")).status_code == 200


async def test_user_list_requires_authentication(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/users")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json() == {"error": "Unauthorized", "message": "Authentication required"}


@pytest.mark.parametrize("user_id", ["9999", "abc", "-1", "1' OR '1'='1"])
async def test_unknown_user_returns_json_404(client: httpx.AsyncClient, user_id: str) -> None:
    response = await client.get(f"/api/v1/users/{user_id}")

    assert response.status_code == 404
    assert response.json() == {"error": "Not Found", "message": "User not found"}


async def test_fixtures_contain_no_secrets() -> None:
    for user in USERS:
        assert not hasattr(user, "password") and not hasattr(user, "password_hash")
