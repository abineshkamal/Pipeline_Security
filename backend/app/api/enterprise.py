"""Least-privilege permissions, fix campaigns, action reputation + allowlist, remediation SLAs, API tokens, SIEM export,
plain-English policy drafting and golden templates."""
from __future__ import annotations

import hashlib
import json
import secrets as pysecrets
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..connectors.github import GitHubClient
from ..db import get_db
from ..deps import ROLE_RANK, OrgContext, get_owned, org_context, require
from ..insights import reputation as rep
from ..insights.fixes import FIX_LABELS, FIXABLE_RULES
from ..insights.permissions import workflow_report
from ..insights.policy_author import draft as draft_policy
from ..insights.templates import evaluate as evaluate_template
from ..models import (ActionAdvisory, ApiToken, AuditLog, CampaignItem, Credential, FixCampaign, GoldenTemplate, Project, Scan,
                      SiemSink, utcnow)
from ..scanner.model import parse_workflow
from ..security import decrypt_secret, encrypt_secret
from ..services import campaigns as camp
from ..services import sla as sla_svc
from ..services.audit import record
from ..services.exceptions import latest_scan
from ..services.monitoring import UnsafeURL, url_hint, validate_webhook_url
from ..services.scan_runner import load_workflow_sources
from ..services.siem import KINDS, deliver
from .governance import PolicyTestIn, test_policy

router = APIRouter(prefix="/api", tags=["enterprise"])


def _iso(d):
    return d.isoformat() if d else None


def _no_token(request: Request, what: str):
    if getattr(request.state, "api_token", None) is not None:
        raise HTTPException(403, f"{what} needs an interactive session, not an API token")


def _latest_scans(db, org_id: str) -> list[tuple[Project, Scan]]:
    out = []
    for p in db.execute(select(Project).where(Project.organization_id == org_id)).scalars():
        s = latest_scan(db, p.id)
        if s:
            out.append((p, s))
    return out


# ---------------------------------------------------------------- least-privilege permissions

@router.get("/scans/{scan_id}/permissions")
def least_privilege(scan_id: str, pipeline: str | None = Query(default=None, max_length=500), ctx: OrgContext = Depends(org_context),
                    db: Session = Depends(get_db)):
    s = get_owned(db, Scan, scan_id, ctx)
    src = load_workflow_sources(s.id)
    if src is None:
        raise HTTPException(409, "workflow files for this scan are not stored; re-run the scan")
    inv = {w["path"]: w for w in (s.inventory or {}).get("workflows", [])}
    jobs = []
    for path, text in sorted(src.items()):
        if pipeline and path != pipeline:
            continue
        wf = parse_workflow(path, text)
        if wf.data:
            jobs.extend(workflow_report(wf, inv.get(path)))
    return {"jobs": jobs, "counts": {"jobs": len(jobs), "over_privileged": sum(1 for j in jobs if j["excess_write_scopes"]),
                                     "undeclared": sum(1 for j in jobs if not j["explicit"]), "high_confidence": sum(1 for j in jobs if j["confidence"] == "high")}}


# ---------------------------------------------------------------- fix campaigns

class CampaignIn(BaseModel):
    name: str = Field(min_length=3, max_length=200)
    rule_ids: list[str] = Field(min_length=1, max_length=4)
    project_ids: list[str] = Field(min_length=1, max_length=300)
    credential_id: str | None = None
    dry_run: bool = False


def _camp_out(db, c: FixCampaign, items: bool = False) -> dict:
    its = db.execute(select(CampaignItem).where(CampaignItem.campaign_id == c.id)).scalars().all()
    names = {p.id: p.name for p in db.execute(select(Project).where(Project.id.in_([i.project_id for i in its] or [""]))).scalars()}
    st = {k: sum(1 for i in its if i.status == k) for k in ("pending", "planned", "no_changes", "pr_open", "merged", "closed", "failed")}
    out = {"id": c.id, "name": c.name, "rule_ids": c.rule_ids, "dry_run": c.dry_run, "status": c.status, "created_by": c.created_by_email,
           "created_at": _iso(c.created_at), "finished_at": _iso(c.finished_at), "projects": len(its), "by_status": st,
           "fixes_applied": sum(i.fixes_applied for i in its), "remaining": sum(i.remaining or 0 for i in its if i.remaining is not None)}
    if items:
        out["items"] = [{"id": i.id, "project_id": i.project_id, "project": names.get(i.project_id, ""), "scan_id": i.scan_id, "status": i.status,
                         "findings": i.findings, "fixes_applied": i.fixes_applied, "files": i.files, "needs_review": i.needs_review,
                         "pr_url": i.pr_url, "pr_number": i.pr_number, "branch": i.branch, "detail": i.detail, "remaining": i.remaining,
                         "updated_at": _iso(i.updated_at)} for i in its]
    return out


@router.get("/campaigns/rules")
def campaign_rules():
    return [{"rule_id": r, "label": FIX_LABELS[r]} for r in sorted(FIXABLE_RULES)]


@router.get("/campaigns/candidates")
def campaign_candidates(rule_ids: str = Query(..., max_length=200), ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    rules = [r for r in rule_ids.split(",") if r in FIXABLE_RULES]
    if not rules:
        raise HTTPException(422, f"rule_ids must be among {sorted(FIXABLE_RULES)}")
    return camp.candidates(db, ctx.org_id, rules)


@router.post("/campaigns", status_code=201)
def create_campaign(body: CampaignIn, request: Request, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    if any(r not in FIXABLE_RULES for r in body.rule_ids):
        raise HTTPException(422, f"only auto-fixable rules: {sorted(FIXABLE_RULES)}")
    if not body.dry_run:
        _no_token(request, "opening pull requests across repositories")
        if not body.credential_id:
            raise HTTPException(422, "credential_id (a token with Contents + Pull requests write) is required unless dry_run")
        get_owned(db, Credential, body.credential_id, ctx)
    ps = [get_owned(db, Project, pid, ctx) for pid in dict.fromkeys(body.project_ids)]
    c = FixCampaign(organization_id=ctx.org_id, name=body.name, rule_ids=body.rule_ids, credential_id=body.credential_id, dry_run=body.dry_run,
                    created_by_email=ctx.user.email)
    db.add(c)
    db.flush()
    for p in ps:
        db.add(CampaignItem(campaign_id=c.id, project_id=p.id,
                            status="pending" if p.source_type == "github" or body.dry_run else "no_changes",
                            detail="" if p.source_type == "github" or body.dry_run else "ZIP projects cannot receive pull requests"))
    db.commit()
    camp.start(c.id)
    record(db, ctx.org_id, ctx.user, "campaign.create", f"campaign:{c.id}", {"rules": body.rule_ids, "projects": len(ps), "dry_run": body.dry_run}, ctx.ip)
    return _camp_out(db, c)


@router.get("/campaigns")
def list_campaigns(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    cs = db.execute(select(FixCampaign).where(FixCampaign.organization_id == ctx.org_id).order_by(FixCampaign.created_at.desc())).scalars().all()
    return [_camp_out(db, c) for c in cs]


@router.get("/campaigns/{campaign_id}")
def get_campaign(campaign_id: str, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    return _camp_out(db, get_owned(db, FixCampaign, campaign_id, ctx), items=True)


@router.post("/campaigns/{campaign_id}/refresh")
def refresh_campaign(campaign_id: str, ctx: OrgContext = Depends(require("analyst")), db: Session = Depends(get_db)):
    c = get_owned(db, FixCampaign, campaign_id, ctx)
    camp.refresh(db, c)
    return _camp_out(db, c, items=True)


# ---------------------------------------------------------------- action reputation + allowlist

def _reputation(db, ctx: OrgContext, refresh: bool) -> dict:
    scans = _latest_scans(db, ctx.org_id)
    cred = next((db.get(Credential, p.credential_id) for p, _ in scans if p.credential_id), None)
    gh = GitHubClient(decrypt_secret(cred.secret_encrypted) if cred and cred.organization_id == ctx.org_id else None)
    try:
        advs = [a.as_advisory() for a in db.execute(select(ActionAdvisory).where(ActionAdvisory.organization_id == ctx.org_id)).scalars()]
        return rep.reputation(gh, scans, advs, refresh)
    finally:
        gh.close()


@router.get("/actions/reputation")
def action_reputation(refresh: bool = False, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    return _reputation(db, ctx, refresh)


class AllowlistIn(BaseModel):
    min_tier: str = Field(default="acceptable", pattern="^(trusted|acceptable|review|risky)$")
    sha_only: bool = False
    verified_allowed: bool = False


@router.post("/actions/allowlist")
def action_allowlist(body: AllowlistIn, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    r = _reputation(db, ctx, False)
    out = rep.allowlist(r["actions"], body.min_tier, body.sha_only, body.verified_allowed)
    out["pending_metadata"] = r["pending"]
    return out


# ---------------------------------------------------------------- remediation SLAs

@router.get("/sla")
def sla_report(window_days: int = Query(default=90, ge=7, le=365), ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    return sla_svc.compute(db, ctx.org_id, window_days)


class TargetsIn(BaseModel):
    critical: int = Field(ge=1, le=365)
    high: int = Field(ge=1, le=365)
    medium: int = Field(ge=1, le=730)
    low: int = Field(ge=1, le=730)


@router.put("/sla/targets")
def sla_targets(body: TargetsIn, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    t = sla_svc.set_targets(db, ctx.org_id, body.model_dump())
    record(db, ctx.org_id, ctx.user, "sla.targets", f"org:{ctx.org_id}", t, ctx.ip)
    return t


# ---------------------------------------------------------------- API tokens

class TokenIn(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    role: str = Field(default="viewer", pattern="^(viewer|analyst|admin)$")
    expires_in_days: int | None = Field(default=90, ge=1, le=730)


def _tok_out(t: ApiToken, names: dict | None = None) -> dict:
    return {"id": t.id, "name": t.name, "role": t.role, "prefix": t.prefix, "created_by": (names or {}).get(t.user_id, ""),
            "created_at": _iso(t.created_at), "expires_at": _iso(t.expires_at), "last_used_at": _iso(t.last_used_at), "revoked": t.revoked}


@router.get("/tokens")
def list_tokens(ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    from ..models import User
    ts = db.execute(select(ApiToken).where(ApiToken.organization_id == ctx.org_id).order_by(ApiToken.created_at.desc())).scalars().all()
    names = dict(db.execute(select(User.id, User.email).where(User.id.in_([t.user_id for t in ts] or [""]))).all())
    return [_tok_out(t, names) for t in ts]


@router.post("/tokens", status_code=201)
def create_token(body: TokenIn, request: Request, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    _no_token(request, "creating API tokens")
    if ROLE_RANK[body.role] > ROLE_RANK[ctx.role]:
        raise HTTPException(403, "a token cannot have more rights than you")
    raw = "pt_" + pysecrets.token_urlsafe(32)
    t = ApiToken(organization_id=ctx.org_id, user_id=ctx.user.id, name=body.name, role=body.role,
                 token_hash=hashlib.sha256(raw.encode()).hexdigest(), prefix=raw[:10],
                 expires_at=utcnow() + timedelta(days=body.expires_in_days) if body.expires_in_days else None)
    db.add(t)
    db.commit()
    record(db, ctx.org_id, ctx.user, "token.create", f"token:{t.id}", {"name": t.name, "role": t.role, "expires_at": _iso(t.expires_at)}, ctx.ip)
    return {**_tok_out(t, {ctx.user.id: ctx.user.email}), "token": raw, "note": "Copy it now: it is not shown again."}


@router.delete("/tokens/{token_id}", status_code=204)
def revoke_token(token_id: str, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    t = get_owned(db, ApiToken, token_id, ctx)
    t.revoked = True
    db.commit()
    record(db, ctx.org_id, ctx.user, "token.revoke", f"token:{t.id}", {"name": t.name}, ctx.ip)


# ---------------------------------------------------------------- SIEM export

class SinkIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    kind: str = Field(pattern="^(splunk|datadog|webhook)$")
    url: str = Field(min_length=12, max_length=1000)
    secret: str = Field(default="", max_length=500)
    events: list[str] = Field(default_factory=list)


def _sink_out(s: SiemSink) -> dict:
    return {"id": s.id, "name": s.name, "kind": s.kind, "url_hint": s.url_hint, "events": s.events, "enabled": s.enabled,
            "delivered": s.delivered, "failed": s.failed, "last_error": s.last_error, "has_secret": bool(s.secret_encrypted), "created_at": _iso(s.created_at)}


@router.get("/siem/sinks")
def list_sinks(ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    return [_sink_out(s) for s in db.execute(select(SiemSink).where(SiemSink.organization_id == ctx.org_id)).scalars()]


@router.post("/siem/sinks", status_code=201)
def create_sink(body: SinkIn, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    if body.kind in ("splunk", "datadog") and not body.secret:
        raise HTTPException(422, "Splunk needs the HEC token and Datadog the API key in `secret`")
    if any(e not in ("audit", "alert") for e in body.events):
        raise HTTPException(422, "events must be audit and/or alert")
    try:
        url = validate_webhook_url(body.url)
    except UnsafeURL as exc:
        raise HTTPException(422, str(exc)) from exc
    s = SiemSink(organization_id=ctx.org_id, name=body.name, kind=body.kind, url_encrypted=encrypt_secret(url), url_hint=url_hint(url),
                 secret_encrypted=encrypt_secret(body.secret) if body.secret else "", events=body.events)
    db.add(s)
    db.commit()
    record(db, ctx.org_id, ctx.user, "siem.create", f"siem:{s.id}", {"kind": s.kind, "events": s.events}, ctx.ip)
    return _sink_out(s)


@router.delete("/siem/sinks/{sink_id}", status_code=204)
def delete_sink(sink_id: str, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    s = get_owned(db, SiemSink, sink_id, ctx)
    db.delete(s)
    db.commit()
    record(db, ctx.org_id, ctx.user, "siem.delete", f"siem:{sink_id}", {"name": s.name}, ctx.ip)


@router.post("/siem/sinks/{sink_id}/test")
def test_sink(sink_id: str, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    s = get_owned(db, SiemSink, sink_id, ctx)
    ok, detail = deliver(s, "test", {"message": "PipelineTrust test event", "organization": ctx.org_id})
    return {"ok": ok, "detail": detail}


@router.get("/audit/export.jsonl")
def audit_export(days: int = Query(default=30, ge=1, le=365), ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    since = utcnow() - timedelta(days=days)
    rows = db.execute(select(AuditLog).where(AuditLog.organization_id == ctx.org_id, AuditLog.created_at >= since).order_by(AuditLog.id)).scalars()
    body = "\n".join(json.dumps({"id": a.id, "at": _iso(a.created_at), "user": a.user_email, "action": a.action, "target": a.target,
                                 "details": a.details, "ip": a.ip, "source": "pipelinetrust"}) for a in rows)
    record(db, ctx.org_id, ctx.user, "audit.export", f"org:{ctx.org_id}", {"days": days}, ctx.ip)
    return PlainTextResponse(body + "\n" if body else "", media_type="application/x-ndjson",
                             headers={"Content-Disposition": f'attachment; filename="pipelinetrust-audit-{days}d.jsonl"'})


# ---------------------------------------------------------------- plain-English policies

class DraftIn(BaseModel):
    description: str = Field(min_length=8, max_length=2000)


@router.post("/policies/draft")
def policy_draft(body: DraftIn, ctx: OrgContext = Depends(require("analyst")), db: Session = Depends(get_db)):
    d = draft_policy(body.description)
    if d["source"]:
        d["test"] = test_policy(PolicyTestIn(source=d["source"]), ctx, db)
    record(db, ctx.org_id, ctx.user, "policy.draft", f"org:{ctx.org_id}", {"method": d["method"], "ok": bool(d["source"])}, ctx.ip)
    return d


# ---------------------------------------------------------------- golden templates

class TemplateIn(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    source_project_id: str
    workflow_path: str = Field(min_length=5, max_length=500, pattern=r"^\.github/workflows/[^/]+\.ya?ml$")
    applies_to: str = Field(default="", max_length=200)
    approved_refs: list[str] = Field(default_factory=list, max_length=20)


def _tpl_out(t: GoldenTemplate, names: dict) -> dict:
    return {"id": t.id, "name": t.name, "source_project_id": t.source_project_id, "source_project": names.get(t.source_project_id, ""),
            "workflow_path": t.workflow_path, "applies_to": t.applies_to, "approved_refs": t.approved_refs, "created_at": _iso(t.created_at)}


@router.get("/templates")
def list_templates(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    names = dict(db.execute(select(Project.id, Project.name).where(Project.organization_id == ctx.org_id)).all())
    return [_tpl_out(t, names) for t in db.execute(select(GoldenTemplate).where(GoldenTemplate.organization_id == ctx.org_id)).scalars()]


@router.post("/templates", status_code=201)
def create_template(body: TemplateIn, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    import re
    p = get_owned(db, Project, body.source_project_id, ctx)
    if body.applies_to:
        try:
            re.compile(body.applies_to)
        except re.error as exc:
            raise HTTPException(422, f"applies_to is not a valid regex: {exc}") from exc
    s = latest_scan(db, p.id)
    if not s or body.workflow_path not in (load_workflow_sources(s.id) or {}):
        raise HTTPException(422, f"{body.workflow_path} not found in the latest scan of {p.name} (scan it first)")
    t = GoldenTemplate(organization_id=ctx.org_id, name=body.name, source_project_id=p.id, workflow_path=body.workflow_path,
                       applies_to=body.applies_to, approved_refs=[r.strip() for r in body.approved_refs if r.strip()])
    db.add(t)
    db.commit()
    record(db, ctx.org_id, ctx.user, "template.create", f"template:{t.id}", {"name": t.name, "workflow": t.workflow_path}, ctx.ip)
    return _tpl_out(t, {p.id: p.name})


@router.delete("/templates/{template_id}", status_code=204)
def delete_template(template_id: str, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    t = get_owned(db, GoldenTemplate, template_id, ctx)
    db.delete(t)
    db.commit()
    record(db, ctx.org_id, ctx.user, "template.delete", f"template:{template_id}", {"name": t.name}, ctx.ip)


@router.get("/templates/compliance")
def template_compliance(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    scans = _latest_scans(db, ctx.org_id)
    projects = [{"project": p, "scan": s, "sources": load_workflow_sources(s.id)} for p, s in scans]
    by_id = {pr["project"].id: pr for pr in projects}
    out = []
    for t in db.execute(select(GoldenTemplate).where(GoldenTemplate.organization_id == ctx.org_id)).scalars():
        src_p = by_id.get(t.source_project_id)
        text = ((src_p or {}).get("sources") or {}).get(t.workflow_path)
        base = {"id": t.id, "name": t.name, "workflow_path": t.workflow_path, "source_project": src_p["project"].name if src_p else ""}
        if not text:
            out.append({**base, "error": "template workflow not found in the source project's latest scan"})
            continue
        r = evaluate_template({"name": t.name, "repo": src_p["project"].repo_full_name, "workflow_path": t.workflow_path, "applies_to": t.applies_to,
                               "approved_refs": t.approved_refs, "source_project_id": t.source_project_id}, text, projects)
        out.append({**base, **r})
    return out
