"""organization policies and action advisories

Revision ID: c7a1d2e3f4b5
Revises: b4f75f2ee56c
Create Date: 2026-11-19 20:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = 'c7a1d2e3f4b5'
down_revision = 'b4f75f2ee56c'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('org_policies',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.Column('policy_id', sa.String(length=40), nullable=False),
    sa.Column('title', sa.String(length=200), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('source', sa.Text(), nullable=False),
    sa.Column('definition', sa.JSON(), nullable=False),
    sa.Column('created_by', sa.String(length=32), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('organization_id', 'policy_id', name='uq_org_policy_id')
    )
    with op.batch_alter_table('org_policies', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_org_policies_organization_id'), ['organization_id'], unique=False)

    op.create_table('action_advisories',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.Column('advisory_id', sa.String(length=80), nullable=False),
    sa.Column('action', sa.String(length=200), nullable=False),
    sa.Column('title', sa.String(length=300), nullable=False),
    sa.Column('severity', sa.String(length=10), nullable=False),
    sa.Column('bad_refs', sa.JSON(), nullable=False),
    sa.Column('all_tags_affected', sa.Boolean(), nullable=False),
    sa.Column('window_start', sa.String(length=10), nullable=False),
    sa.Column('window_end', sa.String(length=10), nullable=False),
    sa.Column('references', sa.JSON(), nullable=False),
    sa.Column('guidance', sa.Text(), nullable=False),
    sa.Column('created_by', sa.String(length=32), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('action_advisories', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_action_advisories_organization_id'), ['organization_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('action_advisories', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_action_advisories_organization_id'))
    op.drop_table('action_advisories')
    with op.batch_alter_table('org_policies', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_org_policies_organization_id'))
    op.drop_table('org_policies')
