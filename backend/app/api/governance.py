"""Organization governance: custom policies (policy-as-code) and the compromised-action watch."""
from __future__ import annotations

import re

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..deps import OrgContext, get_owned, org_context, require
from ..models import ActionAdvisory, Credential, OrgPolicy, Project, Scan, utcnow
from ..scanner.advisories import VERDICT_TEXT, all_advisories, match
from ..scanner.policies import EXAMPLES, OPERATORS, TARGET_FIELDS, PolicyError, evaluate_policy, parse_policy
from ..security import decrypt_secret
from ..services.audit import record

router = APIRouter(prefix="/api", tags=["governance"])


# ---------------------------------------------------------------- policies

def _policy_out(p: OrgPolicy) -> dict:
    d = p.definition or {}
    return {"id": p.id, "policy_id": p.policy_id, "title": p.title, "enabled": p.enabled, "source": p.source,
            "severity": d.get("severity"), "category": d.get("category"), "target": d.get("target"),
            "created_at": p.created_at.isoformat(), "updated_at": p.updated_at.isoformat()}


class PolicyIn(BaseModel):
    source: str = Field(min_length=10, max_length=20000)
    enabled: bool = True


def _parse(source: str) -> dict:
    try:
        return parse_policy(source)
    except PolicyError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/policies")
def list_policies(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    rows = db.execute(select(OrgPolicy).where(OrgPolicy.organization_id == ctx.org_id).order_by(OrgPolicy.policy_id)).scalars()
    return {"policies": [_policy_out(p) for p in rows], "examples": EXAMPLES, "operators": list(OPERATORS), "fields": TARGET_FIELDS}


@router.post("/policies", status_code=201)
def create_policy(body: PolicyIn, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    d = _parse(body.source)
    if db.execute(select(OrgPolicy).where(OrgPolicy.organization_id == ctx.org_id, OrgPolicy.policy_id == d["id"])).scalar_one_or_none():
        raise HTTPException(409, f"a policy with id {d['id']} already exists")
    p = OrgPolicy(organization_id=ctx.org_id, policy_id=d["id"], title=d["title"], enabled=body.enabled, source=body.source,
                  definition=d, created_by=ctx.user.id)
    db.add(p)
    db.commit()
    record(db, ctx.org_id, ctx.user, "policy.create", f"policy:{d['id']}", {"enabled": body.enabled}, ctx.ip)
    return _policy_out(p)


@router.put("/policies/{pid}")
def update_policy(pid: str, body: PolicyIn, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    p = get_owned(db, OrgPolicy, pid, ctx)
    d = _parse(body.source)
    if d["id"] != p.policy_id and db.execute(select(OrgPolicy).where(OrgPolicy.organization_id == ctx.org_id, OrgPolicy.policy_id == d["id"])).scalar_one_or_none():
        raise HTTPException(409, f"a policy with id {d['id']} already exists")
    p.policy_id, p.title, p.source, p.definition, p.enabled, p.updated_at = d["id"], d["title"], body.source, d, body.enabled, utcnow()
    db.commit()
    record(db, ctx.org_id, ctx.user, "policy.update", f"policy:{d['id']}", {"enabled": body.enabled}, ctx.ip)
    return _policy_out(p)


@router.delete("/policies/{pid}", status_code=204)
def delete_policy(pid: str, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    p = get_owned(db, OrgPolicy, pid, ctx)
    db.delete(p)
    db.commit()
    record(db, ctx.org_id, ctx.user, "policy.delete", f"policy:{p.policy_id}", {}, ctx.ip)


class PolicyTestIn(BaseModel):
    source: str = Field(min_length=10, max_length=20000)
    scan_id: str | None = None


@router.post("/policies/test")
def test_policy(body: PolicyTestIn, ctx: OrgContext = Depends(require("analyst")), db: Session = Depends(get_db)):
    """Dry-run a policy against a scan's inventory (default: each project's latest completed scan). Nothing is stored."""
    d = _parse(body.source)
    if body.scan_id:
        scans = [get_owned(db, Scan, body.scan_id, ctx)]
    else:
        scans = []
        for proj in db.execute(select(Project).where(Project.organization_id == ctx.org_id)).scalars():
            s = db.execute(select(Scan).where(Scan.project_id == proj.id, Scan.status == "completed", Scan.ref_override == "").order_by(Scan.created_at.desc()).limit(1)).scalar_one_or_none()
            if s:
                scans.append(s)
    results, total = [], 0
    for s in scans:
        control, fs = evaluate_policy(d, s.inventory or {})
        total += len(fs)
        proj = db.get(Project, s.project_id)
        results.append({"scan_id": s.id, "project": proj.name, "status": control["status"], "note": control["note"],
                        "violations": [{"message": f.message, "file": f.file_path, "line": f.line, "job": f.job} for f in fs[:100]]})
    return {"policy": d, "violations": total, "scans": results}


# ---------------------------------------------------------------- advisories + watch

class AdvisoryIn(BaseModel):
    advisory_id: str = Field(min_length=3, max_length=80)
    action: str = Field(max_length=200)
    title: str = Field(min_length=3, max_length=300)
    severity: str = Field(default="high", pattern="^(critical|high|medium|low)$")
    bad_refs: list[str] = Field(default_factory=list, max_length=200)
    all_tags_affected: bool = False
    window_start: str = Field(default="", pattern=r"^(\d{4}-\d{2}-\d{2})?$")
    window_end: str = Field(default="", pattern=r"^(\d{4}-\d{2}-\d{2})?$")
    references: list[str] = Field(default_factory=list, max_length=20)
    guidance: str = Field(default="", max_length=2000)

    @field_validator("action")
    @classmethod
    def owner_repo(cls, v: str) -> str:
        v = v.strip().lower()
        if not re.fullmatch(r"[a-z0-9_.-]+/[a-z0-9_.-]+", v):
            raise ValueError("action must be owner/repo")
        return v


def _org_advisories(db: Session, org_id: str) -> list[ActionAdvisory]:
    return list(db.execute(select(ActionAdvisory).where(ActionAdvisory.organization_id == org_id).order_by(ActionAdvisory.created_at.desc())).scalars())


@router.get("/advisories")
def list_advisories(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    custom = _org_advisories(db, ctx.org_id)
    out = all_advisories([a.as_advisory() for a in custom])
    ids = {a.advisory_id: a.id for a in custom}
    for a in out:
        a["record_id"] = ids.get(a["id"]) if a["source"] == "organization" else None
    return out


@router.post("/advisories", status_code=201)
def create_advisory(body: AdvisoryIn, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    a = ActionAdvisory(organization_id=ctx.org_id, created_by=ctx.user.id, **body.model_dump())
    db.add(a)
    db.commit()
    record(db, ctx.org_id, ctx.user, "advisory.create", f"advisory:{a.advisory_id}", {"action": a.action}, ctx.ip)
    return a.as_advisory()


@router.delete("/advisories/{aid}", status_code=204)
def delete_advisory(aid: str, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    a = get_owned(db, ActionAdvisory, aid, ctx)
    db.delete(a)
    db.commit()
    record(db, ctx.org_id, ctx.user, "advisory.delete", f"advisory:{a.advisory_id}", {}, ctx.ip)


@router.get("/watch/exposures")
def exposures(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    """Match every project's latest inventory against all advisories - no re-scan needed when an advisory is added."""
    advs = all_advisories([a.as_advisory() for a in _org_advisories(db, ctx.org_id)])
    out, scanned = [], 0
    for proj in db.execute(select(Project).where(Project.organization_id == ctx.org_id).order_by(Project.name)).scalars():
        s = db.execute(select(Scan).where(Scan.project_id == proj.id, Scan.status == "completed", Scan.ref_override == "").order_by(Scan.created_at.desc()).limit(1)).scalar_one_or_none()
        if not s:
            continue
        scanned += 1
        names = {w["path"]: w.get("name") or w["path"] for w in (s.inventory or {}).get("workflows", [])}
        for a in (s.inventory or {}).get("actions", []):
            hit = match(a["uses"], advs)
            if not hit:
                continue
            adv, sev, verdict = hit
            occ = a.get("occurrences") or [{"workflow": w, "job": "", "line": None} for w in a.get("workflows", [])]
            for o in occ:
                out.append({"project_id": proj.id, "project": proj.name, "repo": proj.repo_full_name, "source_type": proj.source_type,
                            "scan_id": s.id, "scanned_at": s.created_at.isoformat(), "workflow": o["workflow"],
                            "workflow_name": names.get(o["workflow"], o["workflow"]), "job": o.get("job"), "line": o.get("line"),
                            "uses": a["uses"], "advisory": adv["id"], "advisory_title": adv["title"], "severity": sev, "verdict": verdict,
                            "verdict_text": VERDICT_TEXT[verdict], "window_start": adv.get("window_start"), "window_end": adv.get("window_end"),
                            "guidance": adv.get("guidance")})
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    out.sort(key=lambda x: (rank.get(x["severity"], 9), x["project"], x["workflow"]))
    return {"exposures": out, "projects_checked": scanned, "advisories": len(advs)}


class RunsIn(BaseModel):
    project_id: str
    workflow: str = Field(max_length=500)
    advisory: str = Field(max_length=80)


@router.post("/watch/runs")
def runs_in_window(body: RunsIn, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    """List the workflow's GitHub Actions runs inside the advisory's incident window (needs Actions: read for private repos)."""
    proj = get_owned(db, Project, body.project_id, ctx)
    if proj.source_type != "github" or not proj.repo_full_name:
        raise HTTPException(400, "run history is only available for GitHub projects")
    adv = next((a for a in all_advisories([x.as_advisory() for x in _org_advisories(db, ctx.org_id)]) if a["id"] == body.advisory), None)
    if not adv or not adv.get("window_start"):
        raise HTTPException(400, "advisory has no incident window")
    if not body.workflow.startswith(".github/workflows/"):
        raise HTTPException(400, "workflow must be a .github/workflows/ path")
    token = None
    if proj.credential_id:
        c = db.get(Credential, proj.credential_id)
        if c and c.organization_id == ctx.org_id:
            token = decrypt_secret(c.secret_encrypted)
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "PipelineTrust-Watch"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    wf_file = body.workflow.rsplit("/", 1)[-1]
    window = f"{adv['window_start']}..{adv.get('window_end') or adv['window_start']}"
    try:
        with httpx.Client(base_url=get_settings().github_api_url.rstrip("/"), headers=headers, timeout=30) as c:
            r = c.get(f"/repos/{proj.repo_full_name}/actions/workflows/{wf_file}/runs", params={"created": window, "per_page": 100})
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"GitHub API error: {type(exc).__name__}: {exc}"[:300]) from exc
    if r.status_code == 404:
        return {"window": window, "total": 0, "runs": [], "note": "Workflow not found on GitHub (renamed or deleted?)."}
    if r.status_code != 200:
        raise HTTPException(400, f"GitHub API HTTP {r.status_code}: the credential may lack Actions: read")
    d = r.json()
    runs = [{"id": x["id"], "created_at": x["created_at"], "event": x.get("event"), "branch": x.get("head_branch"),
             "conclusion": x.get("conclusion"), "url": x.get("html_url"), "actor": (x.get("actor") or {}).get("login")}
            for x in d.get("workflow_runs", [])]
    record(db, ctx.org_id, ctx.user, "watch.runs", f"project:{proj.id}", {"advisory": adv["id"], "workflow": body.workflow, "runs": d.get("total_count", len(runs))}, ctx.ip)
    return {"window": window, "total": d.get("total_count", len(runs)), "runs": runs,
            "note": "Runs in this window may have executed the compromised code: rotate the secrets those jobs could read and review their logs." if runs else ""}
