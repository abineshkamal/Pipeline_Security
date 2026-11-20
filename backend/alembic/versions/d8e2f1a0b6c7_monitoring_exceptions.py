"""scheduled scans, drift alerts, notification channels and risk exceptions

Revision ID: d8e2f1a0b6c7
Revises: c7a1d2e3f4b5
Create Date: 2026-11-19 23:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = 'd8e2f1a0b6c7'
down_revision = 'c7a1d2e3f4b5'
branch_labels = None
depends_on = None


def _fk_org():
    return sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE')


def _index(table, col):
    with op.batch_alter_table(table, schema=None) as b:
        b.create_index(b.f(f'ix_{table}_{col}'), [col], unique=False)


def upgrade() -> None:
    with op.batch_alter_table('projects', schema=None) as b:
        b.add_column(sa.Column('schedule', sa.String(length=10), nullable=False, server_default=''))
        b.add_column(sa.Column('next_scan_at', sa.DateTime(timezone=True), nullable=True))

    op.create_table('risk_exceptions',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.Column('project_id', sa.String(length=32), nullable=False),
    sa.Column('scope', sa.String(length=10), nullable=False),
    sa.Column('rule_id', sa.String(length=40), nullable=False),
    sa.Column('fingerprint', sa.String(length=64), nullable=False),
    sa.Column('workflow', sa.String(length=500), nullable=False),
    sa.Column('title', sa.String(length=300), nullable=False),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.Column('compensating_controls', sa.Text(), nullable=False),
    sa.Column('owner', sa.String(length=200), nullable=False),
    sa.Column('expires_on', sa.String(length=10), nullable=False),
    sa.Column('status', sa.String(length=10), nullable=False),
    sa.Column('requested_by', sa.String(length=32), nullable=True),
    sa.Column('requested_by_email', sa.String(length=320), nullable=False),
    sa.Column('requested_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('decided_by_email', sa.String(length=320), nullable=False),
    sa.Column('decided_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('decision_note', sa.Text(), nullable=False),
    _fk_org(),
    sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['requested_by'], ['users.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id'))
    _index('risk_exceptions', 'organization_id')
    _index('risk_exceptions', 'project_id')

    op.create_table('notification_channels',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('kind', sa.String(length=10), nullable=False),
    sa.Column('url_encrypted', sa.Text(), nullable=False),
    sa.Column('url_hint', sa.String(length=120), nullable=False),
    sa.Column('min_severity', sa.String(length=10), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    _fk_org(),
    sa.PrimaryKeyConstraint('id'))
    _index('notification_channels', 'organization_id')

    op.create_table('drift_alerts',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.Column('project_id', sa.String(length=32), nullable=False),
    sa.Column('scan_id', sa.String(length=32), nullable=False),
    sa.Column('previous_scan_id', sa.String(length=32), nullable=False),
    sa.Column('severity', sa.String(length=10), nullable=False),
    sa.Column('title', sa.String(length=300), nullable=False),
    sa.Column('items', sa.JSON(), nullable=False),
    sa.Column('deliveries', sa.JSON(), nullable=False),
    sa.Column('acknowledged_by', sa.String(length=320), nullable=False),
    sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    _fk_org(),
    sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'))
    _index('drift_alerts', 'organization_id')
    _index('drift_alerts', 'project_id')
    _index('drift_alerts', 'created_at')


def downgrade() -> None:
    for t in ('drift_alerts', 'notification_channels', 'risk_exceptions'):
        op.drop_table(t)
    with op.batch_alter_table('projects', schema=None) as b:
        b.drop_column('next_scan_at')
        b.drop_column('schedule')
