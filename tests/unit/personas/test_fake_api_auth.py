from typing import Any

import httpx
import pytest

from app.personas.fake_api import USERS
from tests.helpers import decode_jwt_part

EMAIL = USERS[1].email


async def _login(client: httpx.AsyncClient, **kwargs: Any) -> httpx.Response:
    return await client.post("/api/v1/auth/login", **kwargs)


async def test_weak_password_for_known_user_returns_jwt(client: httpx.AsyncClient) -> None:
    response = await _login(client, json={"email": EMAIL, "password": "password"})

    body = response.json()
    assert response.status_code == 200
    assert body["token_type"] == "Bearer"
    assert body["user"]["email"] == EMAIL
    claims = decode_jwt_part(body["token"].split(".")[1])
    assert claims["email"] == EMAIL
    assert claims["exp"] - claims["iat"] == body["expires_in"]


async def test_email_is_case_insensitive(client: httpx.AsyncClient) -> None:
    response = await _login(client, json={"email": EMAIL.upper(), "password": "admin123"})

    assert response.status_code == 200


@pytest.mark.parametrize(
    ("email", "password"),
    [(EMAIL, "S0me-Str0ng-Pass!"), ("nobody@example.com", "password")],
)
async def test_wrong_password_and_unknown_email_look_identical(
    client: httpx.AsyncClient, email: str, password: str
) -> None:
    response = await _login(client, json={"email": email, "password": password})

    assert response.status_code == 401
    assert response.json() == {"error": "Unauthorized", "message": "Invalid credentials"}


@pytest.mark.parametrize(
    "kwargs",
    [
        {"content": b"not json"},
        {"content": b""},
        {"json": []},
        {"json": {"email": EMAIL}},
        {"json": {"email": EMAIL, "password": ""}},
        {"json": {"email": ["a"], "password": {"b": 1}}},
    ],
)
async def test_malformed_requests_return_400(
    client: httpx.AsyncClient, kwargs: dict[str, Any]
) -> None:
    response = await _login(client, **kwargs)

    assert response.status_code == 400
    assert response.json()["error"] == "Bad Request"
