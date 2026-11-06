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
    Float,
    Integer,
    MetaData,
    SmallInteger,
    Table,
    Text,
    Uuid,
)
from sqlalchemy.dialects.postgresql import CIDR, INET, JSONB

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

# One row per detection rule that fired on a request (written by the detector worker).
# No foreign key: requests is a hypertable (see migration 0004); the request is identified
# by (request_id, request_ts).
detections = Table(
    "detections",
    metadata,
    Column("id", BigInteger, primary_key=True, autoincrement=True),
    Column("request_id", BigInteger, nullable=False),
    Column("request_ts", DateTime(timezone=True), nullable=False),
    Column("session_id", Uuid, nullable=False),
    Column("rule", Text, nullable=False),
    Column("category", Text, nullable=False),
    Column("severity", Text, nullable=False),
    Column("matched_excerpt", Text, nullable=False, server_default=""),
)

# One row per attacker session (migration 0003). Created by the enrichment worker, kept up
# to date by the sessionizer and classifier.
sessions = Table(
    "sessions",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("world_id", Text, nullable=False),
    Column("first_seen", DateTime(timezone=True), nullable=False),
    Column("last_seen", DateTime(timezone=True), nullable=False),
    Column("ip", INET, nullable=False),
    Column("subnet", CIDR),
    Column("asn", Integer),
    Column("country", Text),
    Column("city", Text),
    Column("reverse_dns", Text),
    Column("abuse_score", SmallInteger),
    Column("request_count", Integer, nullable=False, server_default="0"),
    Column("known_tool", Text),
    Column("classification", Text),
    Column("interest_score", Float, nullable=False, server_default="0"),
    Column("closed", Boolean, nullable=False, server_default="false"),
)
