"""ticketing integrations (Jira / ServiceNow) and ticket links

Revision ID: e3f4a5b6c7d8
Revises: d8e2f1a0b6c7
Create Date: 2026-11-20 00:30:00
"""
from alembic import op
import sqlalchemy as sa


revision = 'e3f4a5b6c7d8'
down_revision = 'd8e2f1a0b6c7'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('ticket_integrations',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('kind', sa.String(length=12), nullable=False),
    sa.Column('base_url', sa.String(length=500), nullable=False),
    sa.Column('target', sa.String(length=100), nullable=False),
    sa.Column('issue_type', sa.String(length=60), nullable=False),
    sa.Column('username', sa.String(length=320), nullable=False),
    sa.Column('secret_encrypted', sa.Text(), nullable=False),
    sa.Column('close_action', sa.String(length=60), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'))
    with op.batch_alter_table('ticket_integrations', schema=None) as b:
        b.create_index(b.f('ix_ticket_integrations_organization_id'), ['organization_id'], unique=False)
    op.create_table('ticket_links',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.Column('project_id', sa.String(length=32), nullable=False),
    sa.Column('integration_id', sa.String(length=32), nullable=True),
    sa.Column('fingerprint', sa.String(length=64), nullable=False),
    sa.Column('rule_id', sa.String(length=40), nullable=False),
    sa.Column('title', sa.String(length=300), nullable=False),
    sa.Column('system', sa.String(length=12), nullable=False),
    sa.Column('key', sa.String(length=100), nullable=False),
    sa.Column('external_id', sa.String(length=100), nullable=False),
    sa.Column('url', sa.String(length=600), nullable=False),
    sa.Column('status', sa.String(length=10), nullable=False),
    sa.Column('created_by_email', sa.String(length=320), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('resolved_scan_id', sa.String(length=32), nullable=False),
    sa.Column('sync_detail', sa.String(length=300), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['integration_id'], ['ticket_integrations.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id'))
    with op.batch_alter_table('ticket_links', schema=None) as b:
        b.create_index(b.f('ix_ticket_links_organization_id'), ['organization_id'], unique=False)
        b.create_index(b.f('ix_ticket_links_project_id'), ['project_id'], unique=False)
        b.create_index(b.f('ix_ticket_links_fingerprint'), ['fingerprint'], unique=False)


def downgrade() -> None:
    op.drop_table('ticket_links')
    op.drop_table('ticket_integrations')
