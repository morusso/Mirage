from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


def create_engine(url: str, *, pool_size: int = 5, echo: bool = False) -> AsyncEngine:
    """Async engine for PostgreSQL (asyncpg).

    ``pool_pre_ping`` makes the pool survive database restarts: a dead connection
    is replaced instead of failing the first query after the outage.
    """
    return create_async_engine(url, pool_size=pool_size, pool_pre_ping=True, echo=echo)


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    # expire_on_commit=False: objects stay usable after commit without implicit
    # lazy loads, which are not allowed in async code.
    return async_sessionmaker(engine, expire_on_commit=False)
