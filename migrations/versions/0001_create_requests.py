"""create requests table

Revision ID: 0001
Revises:
Create Date: 2026-11-01

The table is converted to a TimescaleDB hypertable in the next migration, which is
why the primary key is (id, ts): a unique index on a hypertable must contain the
partitioning column. ``session_id`` has no foreign key yet - ``sessions`` arrives
in a later stage.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "requests",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        # Stream event id: lets the persister insert idempotently when an entry
        # is redelivered after a crash (INSERT ... ON CONFLICT DO NOTHING).
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("session_id", sa.Uuid(), nullable=False),
        sa.Column("world_id", sa.Text(), nullable=False),
        sa.Column("persona", sa.Text(), nullable=True),
        sa.Column("ip", postgresql.INET(), nullable=False),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("ja4", sa.Text(), nullable=True),
        sa.Column("method", sa.Text(), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("query", sa.Text(), nullable=False, server_default=""),
        sa.Column("headers", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("body_excerpt", sa.Text(), nullable=False, server_default=""),
        sa.Column("body_size", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("body_sha256", sa.Text(), nullable=True),
        sa.Column("body_truncated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("tier", sa.SmallInteger(), nullable=True),
        sa.Column("status", sa.SmallInteger(), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("tokens_used", sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint("id", "ts"),
        sa.CheckConstraint("tier BETWEEN 0 AND 2", name="ck_requests_tier"),
    )
    op.create_index("uq_requests_event_id_ts", "requests", ["event_id", "ts"], unique=True)
    op.create_index("ix_requests_session_id_ts", "requests", ["session_id", sa.text("ts DESC")])
    op.create_index("ix_requests_ip_ts", "requests", ["ip", sa.text("ts DESC")])


def downgrade() -> None:
    op.drop_table("requests")
