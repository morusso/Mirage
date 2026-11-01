from io import StringIO

import httpx
from dotenv import dotenv_values

from app.personas.fake_jwt import FAKE_SECRET


async def _env(client: httpx.AsyncClient) -> dict[str, str | None]:
    response = await client.get("/.env")
    assert response.status_code == 200
    return dotenv_values(stream=StringIO(response.text))


async def test_env_is_served_like_a_static_dotfile(client: httpx.AsyncClient) -> None:
    response = await client.get("/.env")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["x-powered-by"] == "Express"
    assert response.text.endswith("\n")


async def test_env_parses_and_contains_expected_keys(client: httpx.AsyncClient) -> None:
    values = await _env(client)

    for key in ("DB_HOST", "DB_USER", "DB_PASSWORD", "REDIS_URL", "JWT_SECRET", "SMTP_PASS"):
        assert values[key]
    assert values["NODE_ENV"] == "production"


async def test_jwt_secret_matches_token_signing_key(client: httpx.AsyncClient) -> None:
    values = await _env(client)

    assert values["JWT_SECRET"] == FAKE_SECRET.decode()


async def test_values_are_rendered_into_dependent_fields(client: httpx.AsyncClient) -> None:
    values = await _env(client)

    assert values["SMTP_USER"] == "noreply@shopnest.store"
    assert values["REDIS_URL"] and "@10.0.4.13:" in values["REDIS_URL"]


async def test_no_secret_shaped_like_real_provider_keys(client: httpx.AsyncClient) -> None:
    text = (await client.get("/.env")).text

    for marker in ("AKIA", "sk_live_", "sk_test_", "ghp_", "xoxb-", "AIza"):
        assert marker not in text
