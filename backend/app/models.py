"""SQLAlchemy ORM models. Every tenant-owned row carries organization_id for isolation."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def _id() -> str:
    return uuid.uuid4().hex


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


ROLES = ("admin", "analyst", "viewer")


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    name: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(200), default="")
    password_hash: Mapped[str] = mapped_column(String(200))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    memberships: Mapped[list[Membership]] = relationship(back_populates="user", cascade="all, delete-orphan")


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("user_id", "organization_id"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(20))  # admin | analyst | viewer
    user: Mapped[User] = relationship(back_populates="memberships")
    organization: Mapped[Organization] = relationship()


class Credential(Base):
    """An encrypted connector secret (e.g. GitHub PAT). Plaintext is never stored or returned by the API."""
    __tablename__ = "credentials"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    provider: Mapped[str] = mapped_column(String(30), default="github")
    secret_encrypted: Mapped[str] = mapped_column(Text)
    hint: Mapped[str] = mapped_column(String(20), default="")  # last 4 chars, for display only
    created_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    source_type: Mapped[str] = mapped_column(String(20))  # github | upload
    repo_full_name: Mapped[str] = mapped_column(String(300), default="")  # owner/repo for github
    ref: Mapped[str] = mapped_column(String(200), default="")  # branch/tag; empty = default branch
    credential_id: Mapped[str | None] = mapped_column(ForeignKey("credentials.id", ondelete="SET NULL"), nullable=True)
    schedule: Mapped[str] = mapped_column(String(10), default="")  # "" | daily | weekly
    next_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued|running|completed|failed
    progress: Mapped[str] = mapped_column(String(200), default="")
    error: Mapped[str] = mapped_column(Text, default="")
    options: Mapped[dict] = mapped_column(JSON, default=dict)
    upload_path: Mapped[str] = mapped_column(String(500), default="")
    # set when a specific branch/tag/commit was scanned (release comparison); such scans never become the project's
    # current posture, raise drift alerts or close tickets
    ref_override: Mapped[str] = mapped_column(String(200), default="")
    commit_sha: Mapped[str] = mapped_column(String(64), default="")
    posture_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)  # counts, category scores
    inventory: Mapped[dict] = mapped_column(JSON, default=dict)  # workflows, actions, triggers, metadata
    controls: Mapped[list] = mapped_column(JSON, default=list)  # per-rule control results
    tool_runs: Mapped[list] = mapped_column(JSON, default=list)  # external tool execution status
    attack_graph: Mapped[dict] = mapped_column(JSON, default=dict)  # nodes, edges, paths
    ai_analysis: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[str] = mapped_column(String(40), index=True)
    category: Mapped[str] = mapped_column(String(20), index=True)
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(10))
    confidence: Mapped[str] = mapped_column(String(10), default="high")
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    evidence_type: Mapped[str] = mapped_column(String(20))  # configuration | inferred | tool
    message: Mapped[str] = mapped_column(Text)
    file_path: Mapped[str] = mapped_column(String(500), default="")
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    snippet: Mapped[str] = mapped_column(Text, default="")
    workflow: Mapped[str] = mapped_column(String(300), default="")
    job: Mapped[str] = mapped_column(String(200), default="")
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    extra: Mapped[dict] = mapped_column(JSON, default=dict)
    triage_status: Mapped[str] = mapped_column(String(20), default="open")  # open|confirmed|false_positive|accepted_risk|fixed
    validation_status: Mapped[str] = mapped_column(String(30), default="unvalidated")
    triage_note: Mapped[str] = mapped_column(Text, default="")
    ai_notes: Mapped[dict] = mapped_column(JSON, default=dict)


class OrgPolicy(Base):
    """Organization-defined detection rule (policy-as-code), evaluated on every scan."""
    __tablename__ = "org_policies"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    policy_id: Mapped[str] = mapped_column(String(40))  # e.g. ORG-PUB-001, unique per organization
    title: Mapped[str] = mapped_column(String(200))
    enabled: Mapped[bool] = mapped_column(default=True)
    source: Mapped[str] = mapped_column(Text)  # YAML/JSON as written by the author
    definition: Mapped[dict] = mapped_column(JSON, default=dict)  # validated, normalized
    created_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    __table_args__ = (UniqueConstraint("organization_id", "policy_id", name="uq_org_policy_id"),)


class ActionAdvisory(Base):
    """Organization-added supply-chain advisory for a GitHub Action (adds to the built-in feed)."""
    __tablename__ = "action_advisories"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    advisory_id: Mapped[str] = mapped_column(String(80))  # CVE / GHSA / internal id
    action: Mapped[str] = mapped_column(String(200))  # owner/repo, lowercase
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(10), default="high")
    bad_refs: Mapped[list] = mapped_column(JSON, default=list)
    all_tags_affected: Mapped[bool] = mapped_column(default=False)
    window_start: Mapped[str] = mapped_column(String(10), default="")  # YYYY-MM-DD (UTC)
    window_end: Mapped[str] = mapped_column(String(10), default="")
    references: Mapped[list] = mapped_column(JSON, default=list)
    guidance: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def as_advisory(self) -> dict:
        return {"id": self.advisory_id, "action": self.action, "title": self.title, "severity": self.severity, "bad_refs": self.bad_refs,
                "all_tags_affected": self.all_tags_affected, "window_start": self.window_start, "window_end": self.window_end,
                "references": self.references, "guidance": self.guidance}


class RiskException(Base):
    """A time-boxed, approved acceptance of a finding (or of a rule in one project). Requester and approver must differ."""
    __tablename__ = "risk_exceptions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    scope: Mapped[str] = mapped_column(String(10), default="finding")  # finding | rule
    rule_id: Mapped[str] = mapped_column(String(40))
    fingerprint: Mapped[str] = mapped_column(String(64), default="")  # scope=finding
    workflow: Mapped[str] = mapped_column(String(500), default="")  # scope=rule: optional workflow file filter
    title: Mapped[str] = mapped_column(String(300), default="")
    reason: Mapped[str] = mapped_column(Text)
    compensating_controls: Mapped[str] = mapped_column(Text, default="")
    owner: Mapped[str] = mapped_column(String(200))
    expires_on: Mapped[str] = mapped_column(String(10))  # YYYY-MM-DD, inclusive
    status: Mapped[str] = mapped_column(String(10), default="pending")  # pending | approved | rejected | revoked
    requested_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    requested_by_email: Mapped[str] = mapped_column(String(320), default="")
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    decided_by_email: Mapped[str] = mapped_column(String(320), default="")
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decision_note: Mapped[str] = mapped_column(Text, default="")


class NotificationChannel(Base):
    """Where drift alerts are delivered. The URL is a credential (Slack/Teams webhook) and is stored encrypted."""
    __tablename__ = "notification_channels"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(10))  # slack | teams | webhook
    url_encrypted: Mapped[str] = mapped_column(Text)
    url_hint: Mapped[str] = mapped_column(String(120), default="")
    min_severity: Mapped[str] = mapped_column(String(10), default="high")  # deliver alerts at or above this level
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DriftAlert(Base):
    """Posture got worse between two consecutive completed scans of a project."""
    __tablename__ = "drift_alerts"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    previous_scan_id: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(10))
    title: Mapped[str] = mapped_column(String(300))
    items: Mapped[list] = mapped_column(JSON, default=list)
    deliveries: Mapped[list] = mapped_column(JSON, default=list)
    acknowledged_by: Mapped[str] = mapped_column(String(320), default="")
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class TicketIntegration(Base):
    """Jira or ServiceNow connection used to open tickets from findings. The API secret is stored encrypted."""
    __tablename__ = "ticket_integrations"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(12))  # jira | servicenow
    base_url: Mapped[str] = mapped_column(String(500))
    target: Mapped[str] = mapped_column(String(100))  # Jira project key | ServiceNow table
    issue_type: Mapped[str] = mapped_column(String(60), default="Bug")  # Jira only
    username: Mapped[str] = mapped_column(String(320))
    secret_encrypted: Mapped[str] = mapped_column(Text)
    close_action: Mapped[str] = mapped_column(String(60), default="")  # Jira transition name | ServiceNow state value
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TicketLink(Base):
    """A ticket opened for a finding; followed across scans by finding fingerprint and closed when the finding is gone."""
    __tablename__ = "ticket_links"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    integration_id: Mapped[str | None] = mapped_column(ForeignKey("ticket_integrations.id", ondelete="SET NULL"), nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    rule_id: Mapped[str] = mapped_column(String(40))
    title: Mapped[str] = mapped_column(String(300))
    system: Mapped[str] = mapped_column(String(12))
    key: Mapped[str] = mapped_column(String(100))  # PROJ-123 | INC0010001
    external_id: Mapped[str] = mapped_column(String(100), default="")  # ServiceNow sys_id
    url: Mapped[str] = mapped_column(String(600))
    status: Mapped[str] = mapped_column(String(10), default="open")  # open | resolved
    created_by_email: Mapped[str] = mapped_column(String(320), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_scan_id: Mapped[str] = mapped_column(String(32), default="")
    sync_detail: Mapped[str] = mapped_column(String(300), default="")


class FixCampaign(Base):
    """One rule-based fix rolled out as pull requests across many repositories."""
    __tablename__ = "fix_campaigns"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    rule_ids: Mapped[list] = mapped_column(JSON, default=list)
    credential_id: Mapped[str | None] = mapped_column(ForeignKey("credentials.id", ondelete="SET NULL"), nullable=True)
    dry_run: Mapped[bool] = mapped_column(default=False)
    status: Mapped[str] = mapped_column(String(12), default="running")  # running | done
    created_by_email: Mapped[str] = mapped_column(String(320), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CampaignItem(Base):
    __tablename__ = "campaign_items"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("fix_campaigns.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    scan_id: Mapped[str] = mapped_column(String(32), default="")
    status: Mapped[str] = mapped_column(String(14), default="pending")  # pending|planned|no_changes|pr_open|merged|closed|failed
    findings: Mapped[int] = mapped_column(Integer, default=0)
    fixes_applied: Mapped[int] = mapped_column(Integer, default=0)
    files: Mapped[int] = mapped_column(Integer, default=0)
    needs_review: Mapped[int] = mapped_column(Integer, default=0)
    pr_url: Mapped[str] = mapped_column(String(500), default="")
    pr_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    branch: Mapped[str] = mapped_column(String(200), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    remaining: Mapped[int | None] = mapped_column(Integer, nullable=True)  # findings of the rule(s) in the latest scan
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OrgSettings(Base):
    """Per-organization settings document (remediation SLA targets, ...)."""
    __tablename__ = "org_settings"
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ApiToken(Base):
    """Scoped, revocable API key for automation. Only a SHA-256 hash is stored; the key is shown once."""
    __tablename__ = "api_tokens"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))  # creator; acts on their behalf
    name: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(20))  # viewer | analyst | admin (capped by the creator's role at use time)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    prefix: Mapped[str] = mapped_column(String(16))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SiemSink(Base):
    """Destination for audit events and drift alerts (Splunk HEC, Datadog logs or a signed generic webhook)."""
    __tablename__ = "siem_sinks"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(12))  # splunk | datadog | webhook
    url_encrypted: Mapped[str] = mapped_column(Text)
    url_hint: Mapped[str] = mapped_column(String(120), default="")
    secret_encrypted: Mapped[str] = mapped_column(Text, default="")  # HEC token / DD API key / HMAC secret
    events: Mapped[list] = mapped_column(JSON, default=list)  # audit | alert ; empty = all
    enabled: Mapped[bool] = mapped_column(default=True)
    delivered: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str] = mapped_column(String(300), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GoldenTemplate(Base):
    """An approved workflow (in a tracked repository) that other repositories should call instead of copying."""
    __tablename__ = "golden_templates"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    source_project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    workflow_path: Mapped[str] = mapped_column(String(500))
    applies_to: Mapped[str] = mapped_column(String(200), default="")  # regex on workflow path/name; empty = similarity only
    approved_refs: Mapped[list] = mapped_column(JSON, default=list)  # allowed @refs of the reusable workflow; empty = any
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    organization_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    user_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    user_email: Mapped[str] = mapped_column(String(320), default="")
    action: Mapped[str] = mapped_column(String(80))
    target: Mapped[str] = mapped_column(String(300), default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    ip: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
