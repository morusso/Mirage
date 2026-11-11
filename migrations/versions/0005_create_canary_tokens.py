"""create canary_tokens table

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-11

Every bait secret handed out in a fake world (API keys, passwords, cloud tokens) is a
unique canary bound to that world. If one shows up somewhere else, the world id says which
attacker session leaked it.

- ``token`` is the primary key: a lookup on use is by token value alone.
- ``kind`` is free text on purpose (api_key, aws_access_key, db_password, jwt...); new bait
  kinds should not need a migration.
- ``triggered_at`` is NULL until the token is seen in use; it records the first use only.
- No foreign key to ``sessions``: a world can outlive or precede its sessions, and the
  link is by ``world_id``.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | Sequence[str] | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "canary_tokens",
        sa.Column("token", sa.Text(), nullable=False),
        sa.Column("world_id", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("triggered_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("token"),
        sa.CheckConstraint(
            "triggered_at IS NULL OR triggered_at >= created_at",
            name="ck_canary_tokens_triggered_after_created",
        ),
    )
    # "Which tokens does this world hold?" and "which worlds leaked something".
    op.create_index("ix_canary_tokens_world_id", "canary_tokens", ["world_id"])


def downgrade() -> None:
    op.drop_table("canary_tokens")
