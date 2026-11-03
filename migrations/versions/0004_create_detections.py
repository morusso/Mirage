"""create detections table

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-03

One row per detection rule that fired on a request. Written by the detector
worker, never by the request path.

Differences from the planned schema, all forced by ``requests`` being a hypertable:

- No foreign key to ``requests``. Its primary key is (id, ts) and TimescaleDB
  does not support foreign keys that point at a hypertable. The request is
  identified by (``request_id``, ``request_ts``) instead; ``request_ts`` also
  lets a lookup hit a single chunk.
- ``session_id`` is copied from the request so session views need no join.

The unique index on (request_id, request_ts, rule) makes the detector idempotent:
an event redelivered after a crash is re-evaluated and its detections are inserted
with ON CONFLICT DO NOTHING. A rule therefore records at most one match per
request (the first one), which is all an analyst needs.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | Sequence[str] | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "detections",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("request_id", sa.BigInteger(), nullable=False),
        sa.Column("request_ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("session_id", sa.Uuid(), nullable=False),
        sa.Column("rule", sa.Text(), nullable=False),
        sa.Column("category", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        # Attacker-controlled text, truncated by the detector. Escape on display.
        sa.Column("matched_excerpt", sa.Text(), nullable=False, server_default=""),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')", name="ck_detections_severity"
        ),
    )
    op.create_index(
        "uq_detections_request_rule",
        "detections",
        ["request_id", "request_ts", "rule"],
        unique=True,
    )
    op.create_index("ix_detections_session_id", "detections", ["session_id"])
    # Dashboards: detections per category over time.
    op.create_index("ix_detections_category_request_ts", "detections", ["category", "request_ts"])


def downgrade() -> None:
    op.drop_table("detections")
