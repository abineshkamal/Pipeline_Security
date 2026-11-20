"""scans of a specific branch/tag/commit (ref_override) are kept out of the project's current posture

Revision ID: f5a6b7c8d9e0
Revises: e3f4a5b6c7d8
Create Date: 2026-11-20 01:30:00
"""
import json

from alembic import op
import sqlalchemy as sa


revision = 'f5a6b7c8d9e0'
down_revision = 'e3f4a5b6c7d8'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('scans', schema=None) as b:
        b.add_column(sa.Column('ref_override', sa.String(length=200), nullable=False, server_default=''))
    conn = op.get_bind()
    for sid, opts in conn.execute(sa.text("SELECT id, options FROM scans")).fetchall():
        try:
            o = json.loads(opts) if isinstance(opts, str) else (opts or {})
        except ValueError:
            continue
        if isinstance(o, dict) and o.get("ref"):
            conn.execute(sa.text("UPDATE scans SET ref_override = :r WHERE id = :i"), {"r": str(o["ref"])[:200], "i": sid})


def downgrade() -> None:
    with op.batch_alter_table('scans', schema=None) as b:
        b.drop_column('ref_override')
