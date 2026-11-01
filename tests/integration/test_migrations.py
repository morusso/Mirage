import asyncio

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

pytestmark = pytest.mark.integration


def _alembic_config(url: str) -> Config:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", url)
    return config


async def test_upgrade_head_creates_version_table(postgres_url: str) -> None:
    # env.py calls asyncio.run(), which cannot nest inside the test's running loop.
    await asyncio.to_thread(command.upgrade, _alembic_config(postgres_url), "head")

    engine = create_async_engine(postgres_url)
    try:
        async with engine.connect() as conn:
            found = await conn.scalar(text("SELECT to_regclass('public.alembic_version')"))
    finally:
        await engine.dispose()
    assert found == "alembic_version"
