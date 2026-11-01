from collections.abc import AsyncIterator, Iterator
from uuid import uuid4

import pytest
from docker.errors import DockerException
from redis.asyncio import Redis
from testcontainers.community.redis import RedisContainer


@pytest.fixture(scope="session")
def redis_url() -> Iterator[str]:
    """URL of a throwaway Redis started once per test session."""
    try:
        container = RedisContainer("redis:7-alpine")
        container.start()
    except DockerException as exc:
        pytest.skip(f"Docker is not available: {exc}")
    try:
        host = container.get_container_host_ip()
        port = container.get_exposed_port(6379)
        yield f"redis://{host}:{port}/0"
    finally:
        container.stop()


@pytest.fixture
def stream_name() -> str:
    """Unique stream per test, so tests never see each other's events."""
    return f"test:events:{uuid4().hex}"


@pytest.fixture
async def redis(redis_url: str) -> AsyncIterator[Redis]:
    client = Redis.from_url(redis_url, decode_responses=True)
    try:
        yield client
    finally:
        await client.aclose()
