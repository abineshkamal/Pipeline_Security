"""Release diff, attacker walkthroughs, runtime evidence, runner inventory, executive report and ticketing."""
from __future__ import annotations

import json
import time

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..connectors.github import GitHubClient
from ..db import get_db
from ..deps import OrgContext, get_owned, org_context, require
from ..insights.fixes import FIXABLE_RULES
from ..insights.pipeline_diff import diff_pipelines
from ..insights.runtime import run_evidence, runner_inventory
from ..insights.story import walkthrough
from ..models import Credential, Finding, Project, Scan, TicketIntegration, TicketLink
from ..reports import executive
from ..security import decrypt_secret, encrypt_secret
from ..services.audit import record
from ..services.monitoring import UnsafeURL, validate_webhook_url
from ..services.scan_runner import artifacts_dir
from ..services.tickets import TicketError, create_ticket, link_out, mark_findings, test_integration

router = APIRouter(prefix="/api", tags=["analysis"])
CACHE_SECONDS = 900


def _completed(db, scan_id: str, ctx: OrgContext) -> Scan:
    s = get_owned(db, Scan, scan_id, ctx)
    if s.status != "completed":
        raise HTTPException(409, "scan is not completed")
    return s


def _findings(db, s: Scan) -> list[Finding]:
    return db.execute(select(Finding).where(Finding.scan_id == s.id)).scalars().all()


# ---------------------------------------------------------------- release / change diff

@router.get("/scans/{scan_id}/pipeline-diff/{base_id}")
def pipeline_diff(scan_id: str, base_id: str, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    """Changes from `base_id` (older) to `scan_id` (newer) in the pipeline inventory, attack paths and findings."""
    new, old = _completed(db, scan_id, ctx), _completed(db, base_id, ctx)
    if new.project_id != old.project_id:
        raise HTTPException(400, "scans belong to different projects")
    d = diff_pipelines(old, _findings(db, old), new, _findings(db, new))
    d["project"] = {"id": new.project_id, "name": db.get(Project, new.project_id).name}
    return d


# ---------------------------------------------------------------- attacker walkthrough

@router.get("/scans/{scan_id}/attack-paths/{path_id}/story")
def path_story(scan_id: str, path_id: str, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    s = _completed(db, scan_id, ctx)
    out = walkthrough(s, _findings(db, s), path_id, FIXABLE_RULES)
    if not out:
        raise HTTPException(404, "attack path not found")
    return out


# ---------------------------------------------------------------- runtime evidence (GitHub)

def _gh_for(db, p: Project) -> GitHubClient:
    token = None
    if p.credential_id:
        c = db.get(Credential, p.credential_id)
        if c and c.organization_id == p.organization_id:
            token = decrypt_secret(c.secret_encrypted)
    return GitHubClient(token)


def _cached(scan: Scan, name: str, refresh: bool, compute):
    path = artifacts_dir(scan.id) / f"{name}.json"
    if not refresh:
        try:
            d = json.loads(path.read_text("utf-8"))
            if time.time() - d.get("_at", 0) < CACHE_SECONDS:
                return d
        except (OSError, ValueError):
            pass
    d = compute()
    d["_at"] = time.time()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(d), "utf-8")
    return d


def _github_scan(db, scan_id, ctx) -> tuple[Scan, Project]:
    s = _completed(db, scan_id, ctx)
    p = db.get(Project, s.project_id)
    if p.source_type != "github":
        raise HTTPException(400, "runtime evidence needs a GitHub project (ZIP assessments have no run history)")
    return s, p


@router.get("/scans/{scan_id}/runtime")
def runtime(scan_id: str, refresh: bool = False, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    s, p = _github_scan(db, scan_id, ctx)
    fs = _findings(db, s)

    def compute():
        gh = _gh_for(db, p)
        try:
            return run_evidence(gh, p.repo_full_name, s.inventory or {}, fs)
        finally:
            gh.close()
    return _cached(s, "runtime", refresh, compute)


@router.get("/scans/{scan_id}/runners")
def runners(scan_id: str, refresh: bool = False, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    s, p = _github_scan(db, scan_id, ctx)

    def compute():
        gh = _gh_for(db, p)
        try:
            return runner_inventory(gh, p.repo_full_name, s.inventory or {}, (s.inventory or {}).get("visibility") == "public")
        finally:
            gh.close()
    return _cached(s, "runners", refresh, compute)


# ---------------------------------------------------------------- executive report

@router.get("/reports/executive.{fmt}")
def executive_report(fmt: str, days: int = Query(default=30, ge=7, le=365), ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    if fmt not in ("html", "json"):
        raise HTTPException(404, "format must be html or json")
    d = executive.build(db, ctx.org_id, days)
    record(db, ctx.org_id, ctx.user, "report.executive", f"org:{ctx.org_id}", {"days": days, "format": fmt}, ctx.ip)
    if fmt == "json":
        return JSONResponse(d)
    return HTMLResponse(executive.render(d), headers={"Content-Disposition": f'inline; filename="executive-report-{days}d.html"'})


# ---------------------------------------------------------------- ticketing

class IntegrationIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    kind: str = Field(pattern="^(jira|servicenow)$")
    base_url: str = Field(min_length=10, max_length=500)
    target: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_]+$", description="Jira project key or ServiceNow table")
    issue_type: str = Field(default="Bug", max_length=60)
    username: str = Field(min_length=1, max_length=320)
    secret: str = Field(min_length=4, max_length=500)
    close_action: str = Field(default="", max_length=60)


def _int_out(i: TicketIntegration) -> dict:
    return {"id": i.id, "name": i.name, "kind": i.kind, "base_url": i.base_url, "target": i.target, "issue_type": i.issue_type,
            "username": i.username, "close_action": i.close_action, "enabled": i.enabled, "created_at": i.created_at.isoformat()}


@router.get("/integrations/tickets")
def list_integrations(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    return [_int_out(i) for i in db.execute(select(TicketIntegration).where(TicketIntegration.organization_id == ctx.org_id)).scalars()]


@router.post("/integrations/tickets", status_code=201)
def create_integration(body: IntegrationIn, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    try:
        url = validate_webhook_url(body.base_url).rstrip("/")
    except UnsafeURL as exc:
        raise HTTPException(422, str(exc)) from exc
    i = TicketIntegration(organization_id=ctx.org_id, name=body.name, kind=body.kind, base_url=url, target=body.target,
                          issue_type=body.issue_type or "Bug", username=body.username, secret_encrypted=encrypt_secret(body.secret),
                          close_action=body.close_action)
    db.add(i)
    db.commit()
    record(db, ctx.org_id, ctx.user, "integration.create", f"integration:{i.id}", {"kind": i.kind, "target": i.target}, ctx.ip)
    return _int_out(i)


@router.delete("/integrations/tickets/{integration_id}", status_code=204)
def delete_integration(integration_id: str, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    i = get_owned(db, TicketIntegration, integration_id, ctx)
    db.delete(i)
    db.commit()
    record(db, ctx.org_id, ctx.user, "integration.delete", f"integration:{integration_id}", {"name": i.name}, ctx.ip)


@router.post("/integrations/tickets/{integration_id}/test")
def test_ticket_integration(integration_id: str, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    try:
        return test_integration(get_owned(db, TicketIntegration, integration_id, ctx))
    except UnsafeURL as exc:
        return {"ok": False, "detail": str(exc)}


class TicketIn(BaseModel):
    integration_id: str
    finding_ids: list[str] = Field(min_length=1, max_length=50)


@router.post("/tickets")
def open_tickets(body: TicketIn, ctx: OrgContext = Depends(require("analyst")), db: Session = Depends(get_db)):
    it = get_owned(db, TicketIntegration, body.integration_id, ctx)
    if not it.enabled:
        raise HTTPException(409, "integration is disabled")
    created, skipped, errors = [], [], []
    for fid in dict.fromkeys(body.finding_ids):
        f = get_owned(db, Finding, fid, ctx)
        scan = db.get(Scan, f.scan_id)
        project = db.get(Project, scan.project_id)
        existing = db.execute(select(TicketLink).where(TicketLink.project_id == project.id, TicketLink.fingerprint == f.fingerprint,
                                                       TicketLink.status == "open")).scalars().first()
        if existing:
            skipped.append({"finding_id": fid, "key": existing.key, "url": existing.url})
            continue
        try:
            t = create_ticket(it, f, project, scan)
        except (TicketError, UnsafeURL, Exception) as exc:  # noqa: BLE001 - report per finding
            errors.append({"finding_id": fid, "detail": f"{type(exc).__name__}: {exc}"[:240]})
            continue
        lk = TicketLink(organization_id=ctx.org_id, project_id=project.id, integration_id=it.id, fingerprint=f.fingerprint, rule_id=f.rule_id,
                        title=f.title[:300], system=it.kind, key=t["key"][:100], external_id=t["external_id"][:100], url=t["url"][:600],
                        created_by_email=ctx.user.email)
        db.add(lk)
        db.commit()
        mark_findings([f], [lk])
        db.commit()
        created.append(link_out(lk))
    record(db, ctx.org_id, ctx.user, "tickets.create", f"integration:{it.id}", {"created": len(created), "errors": len(errors)}, ctx.ip)
    return {"created": created, "skipped": skipped, "errors": errors}


@router.get("/tickets")
def list_tickets(project_id: str | None = None, status: str = Query(default="all", pattern="^(all|open|resolved)$"),
                 ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    q = select(TicketLink).where(TicketLink.organization_id == ctx.org_id)
    if project_id:
        q = q.where(TicketLink.project_id == project_id)
    if status != "all":
        q = q.where(TicketLink.status == status)
    names = dict(db.execute(select(Project.id, Project.name).where(Project.organization_id == ctx.org_id)).all())
    return [{**link_out(lk), "project": names.get(lk.project_id, "")} for lk in db.execute(q.order_by(TicketLink.created_at.desc()).limit(500)).scalars()]
