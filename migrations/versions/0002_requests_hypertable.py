"""convert requests to a TimescaleDB hypertable

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-01

Partitioned by ``ts`` in 1-day chunks: at the target 500 req/s that is a few
tens of millions of rows per chunk at most, and retention (stage 6) can drop
whole chunks cheaply.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0002"
down_revision: str | Sequence[str] | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS timescaledb")
    op.execute(
        "SELECT create_hypertable('requests', 'ts', "
        "chunk_time_interval => INTERVAL '1 day', migrate_data => true)"
    )


def downgrade() -> None:
    # TimescaleDB cannot turn a hypertable back into a plain table, and the
    # extension may serve other objects, so both stay. Downgrading further
    # drops the table itself (0001), hypertable or not.
    pass
