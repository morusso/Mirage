import asyncio
from collections.abc import AsyncIterator, Iterator
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from docker.errors import DockerException
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from testcontainers.community.postgres import PostgresContainer
from testcontainers.community.redis import RedisContainer

from domain.db import create_engine, create_session_factory


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


@pytest.fixture(scope="session")
def postgres_url() -> Iterator[str]:
    """asyncpg URL of a throwaway TimescaleDB (PostgreSQL 16) started once per session."""
    try:
        container = PostgresContainer(
            "timescale/timescaledb:latest-pg16",
            username="mirage",
            password="mirage",
            dbname="mirage",
            driver="asyncpg",
        )
        container.start()
    except DockerException as exc:
        pytest.skip(f"Docker is not available: {exc}")
    try:
        yield container.get_connection_url()
    finally:
        container.stop()


@pytest.fixture
async def sessions(postgres_url: str) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """Session factory on a migrated database; the requests table is emptied afterwards."""
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", postgres_url)
    # env.py calls asyncio.run(), which cannot nest inside the test's running loop.
    await asyncio.to_thread(command.upgrade, config, "head")
    engine = create_engine(postgres_url)
    try:
        yield create_session_factory(engine)
    finally:
        async with engine.begin() as conn:
            await conn.execute(text("TRUNCATE requests, detections, sessions"))
        await engine.dispose()
