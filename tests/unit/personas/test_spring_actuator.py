import httpx
import pytest

from app.personas.fake_api import ENV_BAIT_CONTEXT

CONTENT_TYPE = "application/vnd.spring-boot.actuator.v3+json"


@pytest.mark.parametrize("path", ["/actuator", "/actuator/", "/actuator/health", "/actuator/info"])
async def test_endpoints_use_the_actuator_media_type(client: httpx.AsyncClient, path: str) -> None:
    response = await client.get(path)

    assert response.status_code == 200
    assert response.headers["content-type"] == CONTENT_TYPE
    assert response.headers["server"] == "nginx/1.24.0"


async def test_index_links_are_built_from_the_request_host(client: httpx.AsyncClient) -> None:
    response = await client.get(
        "/actuator", headers={"host": "shop.test", "x-forwarded-proto": "https"}
    )
    links = response.json()["_links"]

    assert links["self"]["href"] == "https://shop.test/actuator"
    assert set(links) == {"self", "health", "info", "env"}
    assert links["env"] == {"href": "https://shop.test/actuator/env", "templated": False}


async def test_index_ignores_a_bogus_forwarded_proto(client: httpx.AsyncClient) -> None:
    response = await client.get("/actuator", headers={"x-forwarded-proto": "javascript"})

    assert response.json()["_links"]["self"]["href"].startswith("https://")


async def test_health_shows_details(client: httpx.AsyncClient) -> None:
    body = (await client.get("/actuator/health")).json()

    assert body["status"] == "UP"
    assert body["components"]["db"]["details"]["database"] == "MySQL"


async def test_env_masks_secrets_but_leaks_topology(client: httpx.AsyncClient) -> None:
    sources = (await client.get("/actuator/env")).json()["propertySources"]
    props = {k: v["value"] for s in sources for k, v in s["properties"].items()}

    assert props["spring.datasource.password"] == "******"
    assert props["jwt.secret"] == "******"
    assert ENV_BAIT_CONTEXT["db_host"] in props["spring.datasource.url"]
    assert ENV_BAIT_CONTEXT["db_password"] not in str(props)


async def test_heapdump_and_unknown_endpoints_are_404(client: httpx.AsyncClient) -> None:
    for path in ("/actuator/heapdump", "/actuator/nope"):
        assert (await client.get(path)).status_code == 404
