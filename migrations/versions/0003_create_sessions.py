"""create sessions table

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-02

One row per attacker session. Rows are created and kept up to date by workers
(enrichment, sessionizer, classifier), never by the request path.

There is deliberately no foreign key from ``requests.session_id``: requests are
persisted as soon as they leave the stream, usually before any worker has created
the session row, and a missing session must not make the persister fail.

Beyond the planned columns this adds ``city``, ``subnet``, ``reverse_dns`` and
``abuse_score``: the enrichment steps of this stage produce them, and a session
should carry its country, ASN and reputation together.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: str | Sequence[str] | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("world_id", sa.Text(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ip", postgresql.INET(), nullable=False),
        sa.Column("subnet", postgresql.CIDR(), nullable=True),
        sa.Column("asn", sa.Integer(), nullable=True),
        sa.Column("country", sa.Text(), nullable=True),
        sa.Column("city", sa.Text(), nullable=True),
        sa.Column("reverse_dns", sa.Text(), nullable=True),
        sa.Column("abuse_score", sa.SmallInteger(), nullable=True),
        sa.Column("request_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("known_tool", sa.Text(), nullable=True),
        sa.Column("classification", sa.Text(), nullable=True),
        sa.Column("interest_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("closed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint("interest_score BETWEEN 0 AND 1", name="ck_sessions_interest_score"),
        sa.CheckConstraint("abuse_score BETWEEN 0 AND 100", name="ck_sessions_abuse_score"),
        sa.CheckConstraint("last_seen >= first_seen", name="ck_sessions_seen_order"),
    )

    op.create_index(
        "ix_sessions_open_last_seen",
        "sessions",
        ["last_seen"],
        postgresql_where=sa.text("NOT closed"),
    )
    op.create_index("ix_sessions_ip", "sessions", ["ip"])
    op.create_index("ix_sessions_first_seen", "sessions", [sa.text("first_seen DESC")])


def downgrade() -> None:
    op.drop_table("sessions")
