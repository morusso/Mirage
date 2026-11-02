import asyncio

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
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


async def test_requests_is_hypertable_partitioned_by_ts(postgres_url: str) -> None:
    await asyncio.to_thread(command.upgrade, _alembic_config(postgres_url), "head")

    engine = create_async_engine(postgres_url)
    try:
        async with engine.connect() as conn:
            dimension = await conn.scalar(
                text(
                    "SELECT column_name FROM timescaledb_information.dimensions "
                    "WHERE hypertable_name = 'requests'"
                )
            )
    finally:
        await engine.dispose()
    assert dimension == "ts"


async def test_requests_table_roundtrip(postgres_url: str) -> None:
    config = _alembic_config(postgres_url)
    await asyncio.to_thread(command.upgrade, config, "head")

    engine = create_async_engine(postgres_url)
    try:
        async with engine.begin() as conn:
            columns = {
                row[0]
                for row in await conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_name = 'requests'"
                    )
                )
            }
            assert {"id", "ts", "event_id", "session_id", "ip", "body_sha256", "tier"} <= columns

            insert = text(
                "INSERT INTO requests (ts, event_id, session_id, world_id, ip, method, path) "
                "VALUES (now(), :event_id, gen_random_uuid(), 'w', '203.0.113.7', 'GET', '/') "
                "ON CONFLICT (event_id, ts) DO NOTHING"
            )
            await conn.execute(insert, {"event_id": "00000000-0000-0000-0000-000000000001"})
            count = await conn.scalar(text("SELECT count(*) FROM requests"))
            assert count == 1
    finally:
        await engine.dispose()

    await asyncio.to_thread(command.downgrade, config, "base")
    engine = create_async_engine(postgres_url)
    try:
        async with engine.connect() as conn:
            assert await conn.scalar(text("SELECT to_regclass('public.requests')")) is None
    finally:
        await engine.dispose()


_SESSION_INSERT = (
    "INSERT INTO sessions (id, world_id, first_seen, last_seen, ip{extra_cols}) "
    "VALUES (gen_random_uuid(), 'w', {first_seen}, now(), '203.0.113.7'{extra_vals})"
)


async def test_sessions_table_defaults(postgres_url: str) -> None:
    await asyncio.to_thread(command.upgrade, _alembic_config(postgres_url), "head")

    engine = create_async_engine(postgres_url)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(_SESSION_INSERT.format(extra_cols="", first_seen="now()", extra_vals=""))
            )
            row = (
                await conn.execute(
                    text("SELECT request_count, closed, interest_score, asn, country FROM sessions")
                )
            ).one()
            await conn.execute(text("DELETE FROM sessions"))
    finally:
        await engine.dispose()
    assert tuple(row) == (0, False, 0.0, None, None)


@pytest.mark.parametrize(
    ("extra_cols", "extra_vals", "first_seen"),
    [
        (", interest_score", ", 1.5", "now()"),
        (", abuse_score", ", 101", "now()"),
        ("", "", "now() + interval '1 hour'"),  # last_seen before first_seen
    ],
    ids=["interest_score>1", "abuse_score>100", "last_seen<first_seen"],
)
async def test_sessions_table_rejects_invalid_rows(
    postgres_url: str, extra_cols: str, extra_vals: str, first_seen: str
) -> None:
    await asyncio.to_thread(command.upgrade, _alembic_config(postgres_url), "head")
    statement = _SESSION_INSERT.format(
        extra_cols=extra_cols, first_seen=first_seen, extra_vals=extra_vals
    )

    engine = create_async_engine(postgres_url)
    try:
        async with engine.connect() as conn:
            with pytest.raises(IntegrityError):
                await conn.execute(text(statement))
    finally:
        await engine.dispose()
