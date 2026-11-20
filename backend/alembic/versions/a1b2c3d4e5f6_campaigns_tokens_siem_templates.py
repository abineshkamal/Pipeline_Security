"""fix campaigns, org settings, API tokens, SIEM sinks, golden templates

Revision ID: a1b2c3d4e5f6
Revises: f5a6b7c8d9e0
Create Date: 2026-11-20 10:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = 'a1b2c3d4e5f6'
down_revision = 'f5a6b7c8d9e0'
branch_labels = None
depends_on = None

S, T, B, I, J = sa.String, sa.Text, sa.Boolean, sa.Integer, sa.JSON


def D():
    return sa.DateTime(timezone=True)


def _org():
    return [sa.Column('organization_id', S(32), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False)]


def _idx(table, col, unique=False):
    with op.batch_alter_table(table) as b:
        b.create_index(b.f(f'ix_{table}_{col}'), [col], unique=unique)


def upgrade() -> None:
    op.create_table('fix_campaigns', sa.Column('id', S(32), primary_key=True), *_org(),
                    sa.Column('name', S(200), nullable=False), sa.Column('rule_ids', J, nullable=False),
                    sa.Column('credential_id', S(32), sa.ForeignKey('credentials.id', ondelete='SET NULL'), nullable=True),
                    sa.Column('dry_run', B, nullable=False), sa.Column('status', S(12), nullable=False),
                    sa.Column('created_by_email', S(320), nullable=False), sa.Column('created_at', D(), nullable=False),
                    sa.Column('finished_at', D(), nullable=True))
    _idx('fix_campaigns', 'organization_id')
    op.create_table('campaign_items', sa.Column('id', S(32), primary_key=True),
                    sa.Column('campaign_id', S(32), sa.ForeignKey('fix_campaigns.id', ondelete='CASCADE'), nullable=False),
                    sa.Column('project_id', S(32), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
                    sa.Column('scan_id', S(32), nullable=False), sa.Column('status', S(14), nullable=False),
                    sa.Column('findings', I, nullable=False), sa.Column('fixes_applied', I, nullable=False), sa.Column('files', I, nullable=False),
                    sa.Column('needs_review', I, nullable=False), sa.Column('pr_url', S(500), nullable=False), sa.Column('pr_number', I, nullable=True),
                    sa.Column('branch', S(200), nullable=False), sa.Column('detail', T, nullable=False), sa.Column('remaining', I, nullable=True),
                    sa.Column('updated_at', D(), nullable=False))
    _idx('campaign_items', 'campaign_id')
    op.create_table('org_settings', sa.Column('organization_id', S(32), sa.ForeignKey('organizations.id', ondelete='CASCADE'), primary_key=True),
                    sa.Column('data', J, nullable=False), sa.Column('updated_at', D(), nullable=False))
    op.create_table('api_tokens', sa.Column('id', S(32), primary_key=True), *_org(),
                    sa.Column('user_id', S(32), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
                    sa.Column('name', S(200), nullable=False), sa.Column('role', S(20), nullable=False),
                    sa.Column('token_hash', S(64), nullable=False), sa.Column('prefix', S(16), nullable=False),
                    sa.Column('expires_at', D(), nullable=True), sa.Column('last_used_at', D(), nullable=True),
                    sa.Column('revoked', B, nullable=False), sa.Column('created_at', D(), nullable=False))
    _idx('api_tokens', 'organization_id')
    _idx('api_tokens', 'token_hash', unique=True)
    op.create_table('siem_sinks', sa.Column('id', S(32), primary_key=True), *_org(),
                    sa.Column('name', S(200), nullable=False), sa.Column('kind', S(12), nullable=False),
                    sa.Column('url_encrypted', T, nullable=False), sa.Column('url_hint', S(120), nullable=False),
                    sa.Column('secret_encrypted', T, nullable=False), sa.Column('events', J, nullable=False),
                    sa.Column('enabled', B, nullable=False), sa.Column('delivered', I, nullable=False), sa.Column('failed', I, nullable=False),
                    sa.Column('last_error', S(300), nullable=False), sa.Column('created_at', D(), nullable=False))
    _idx('siem_sinks', 'organization_id')
    op.create_table('golden_templates', sa.Column('id', S(32), primary_key=True), *_org(),
                    sa.Column('name', S(200), nullable=False),
                    sa.Column('source_project_id', S(32), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
                    sa.Column('workflow_path', S(500), nullable=False), sa.Column('applies_to', S(200), nullable=False),
                    sa.Column('approved_refs', J, nullable=False), sa.Column('created_at', D(), nullable=False))
    _idx('golden_templates', 'organization_id')


def downgrade() -> None:
    for t in ('golden_templates', 'siem_sinks', 'api_tokens', 'org_settings', 'campaign_items', 'fix_campaigns'):
        op.drop_table(t)
