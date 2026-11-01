from sqlalchemy.ext.asyncio import AsyncSession

from domain.db import create_engine, create_session_factory

URL = "postgresql+asyncpg://u:p@localhost:5432/mirage"


async def test_engine_uses_asyncpg_and_pre_ping() -> None:
    engine = create_engine(URL)
    try:
        assert engine.dialect.driver == "asyncpg"
        assert engine.pool._pre_ping is True
        assert engine.pool.size() == 5  # type: ignore[attr-defined]
    finally:
        await engine.dispose()


async def test_session_factory_builds_async_sessions_without_connecting() -> None:
    engine = create_engine(URL)
    try:
        factory = create_session_factory(engine)

        async with factory() as session:
            assert isinstance(session, AsyncSession)
            assert session.sync_session.expire_on_commit is False
    finally:
        await engine.dispose()
