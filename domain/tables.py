"""Core table definitions mirroring the Alembic migrations.

Migrations are the source of truth for the schema; these objects only let workers
build INSERT statements without raw SQL. Keep them in sync when a migration changes
a table.
"""

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Integer,
    MetaData,
    SmallInteger,
    Table,
    Text,
    Uuid,
)
from sqlalchemy.dialects.postgresql import INET, JSONB

metadata = MetaData()

requests = Table(
    "requests",
    metadata,
    Column("id", BigInteger, primary_key=True, autoincrement=True),
    Column("ts", DateTime(timezone=True), primary_key=True),
    Column("event_id", Uuid, nullable=False),
    Column("session_id", Uuid, nullable=False),
    Column("world_id", Text, nullable=False),
    Column("persona", Text),
    Column("ip", INET, nullable=False),
    Column("port", Integer),
    Column("ja4", Text),
    Column("method", Text, nullable=False),
    Column("path", Text, nullable=False),
    Column("query", Text, nullable=False),
    Column("headers", JSONB, nullable=False),
    Column("body_excerpt", Text, nullable=False),
    Column("body_size", Integer, nullable=False),
    Column("body_sha256", Text),
    Column("body_truncated", Boolean, nullable=False),
    Column("tier", SmallInteger),
    Column("status", SmallInteger),
    Column("latency_ms", Integer),
    Column("tokens_used", Integer),
)
