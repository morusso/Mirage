import pytest
from sqlalchemy import text

from domain.db import create_engine, create_session_factory

pytestmark = pytest.mark.integration


async def test_session_runs_queries_against_postgres(postgres_url: str) -> None:
    engine = create_engine(postgres_url)
    try:
        async with create_session_factory(engine)() as session:
            assert (await session.execute(text("SELECT 1"))).scalar_one() == 1
    finally:
        await engine.dispose()


async def test_timescaledb_extension_is_available(postgres_url: str) -> None:
    engine = create_engine(postgres_url)
    try:
        async with engine.connect() as conn:
            available = await conn.execute(
                text("SELECT count(*) FROM pg_available_extensions WHERE name = 'timescaledb'")
            )
            assert available.scalar_one() == 1
    finally:
        await engine.dispose()


async def test_uncommitted_changes_are_rolled_back(postgres_url: str) -> None:
    engine = create_engine(postgres_url)
    factory = create_session_factory(engine)
    try:
        async with factory() as session:
            await session.execute(text("CREATE TEMP TABLE t (x int)"))
            await session.rollback()
        async with factory() as session:
            result = await session.execute(text("SELECT to_regclass('pg_temp.t')"))
            assert result.scalar_one() is None
    finally:
        await engine.dispose()
