from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..connectors.base import ConnectorError, registry
from ..connectors.github import REPO_RE, GitHubClient
from ..db import get_db
from ..deps import OrgContext, get_owned, org_context, require
from ..models import Credential, Finding, Project, Scan
from ..security import decrypt_secret, encrypt_secret
from ..services.audit import record

router = APIRouter(prefix="/api", tags=["projects"])


# ---------------------------------------------------------------- credentials

class CredentialIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    provider: str = Field(default="github", pattern="^(github)$")
    secret: str = Field(min_length=8, max_length=500)


def _cred_out(c: Credential) -> dict:
    return {"id": c.id, "name": c.name, "provider": c.provider, "hint": c.hint, "created_at": c.created_at.isoformat()}


@router.get("/credentials")
def list_credentials(ctx: OrgContext = Depends(require("analyst")), db: Session = Depends(get_db)):
    return [_cred_out(c) for c in db.execute(select(Credential).where(Credential.organization_id == ctx.org_id)).scalars()]


@router.post("/credentials", status_code=201)
def create_credential(body: CredentialIn, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    c = Credential(organization_id=ctx.org_id, name=body.name, provider=body.provider, secret_encrypted=encrypt_secret(body.secret.strip()),
                   hint="..." + body.secret.strip()[-4:], created_by=ctx.user.id)
    db.add(c)
    db.commit()
    record(db, ctx.org_id, ctx.user, "credential.create", f"credential:{c.id}", {"name": c.name, "provider": c.provider}, ctx.ip)
    return _cred_out(c)


@router.delete("/credentials/{cred_id}", status_code=204)
def delete_credential(cred_id: str, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    c = get_owned(db, Credential, cred_id, ctx)
    db.delete(c)
    db.commit()
    record(db, ctx.org_id, ctx.user, "credential.delete", f"credential:{cred_id}", {"name": c.name}, ctx.ip)


@router.post("/credentials/{cred_id}/test")
def test_credential(cred_id: str, ctx: OrgContext = Depends(require("analyst")), db: Session = Depends(get_db)):
    c = get_owned(db, Credential, cred_id, ctx)
    gh = GitHubClient(decrypt_secret(c.secret_encrypted))
    try:
        return gh.token_info()
    finally:
        gh.close()


@router.get("/credentials/{cred_id}/repos")
def discover_repos(cred_id: str, org: str | None = None, ctx: OrgContext = Depends(require("analyst")), db: Session = Depends(get_db)):
    """Repository inventory (asset discovery) visible to the credential."""
    c = get_owned(db, Credential, cred_id, ctx)
    gh = GitHubClient(decrypt_secret(c.secret_encrypted))
    try:
        repos = gh.list_repos(org)
    except ConnectorError as exc:
        raise HTTPException(400, str(exc)) from exc
    finally:
        gh.close()
    record(db, ctx.org_id, ctx.user, "assets.discover", f"credential:{cred_id}", {"org": org, "count": len(repos)}, ctx.ip)
    return repos


@router.get("/connectors")
def connectors():
    return [{"name": c.name, "display_name": c.display_name, "status": c.status} for c in registry().values()]


# ---------------------------------------------------------------- projects

class ProjectIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    source_type: str = Field(pattern="^(github|upload)$")
    repo_full_name: str = Field(default="", max_length=300)
    ref: str = Field(default="", max_length=200, pattern=r"^[A-Za-z0-9._/\-]*$")
    credential_id: str | None = None


def project_out(p: Project, db: Session) -> dict:
    last = db.execute(select(Scan).where(Scan.project_id == p.id).order_by(Scan.created_at.desc()).limit(1)).scalar_one_or_none()
    count = db.execute(select(func.count()).select_from(Scan).where(Scan.project_id == p.id)).scalar()
    return {"id": p.id, "name": p.name, "description": p.description, "source_type": p.source_type, "repo_full_name": p.repo_full_name,
            "ref": p.ref, "credential_id": p.credential_id, "created_at": p.created_at.isoformat(), "scan_count": count,
            "schedule": p.schedule, "next_scan_at": p.next_scan_at.isoformat() if p.next_scan_at else None,
            "last_scan": {"id": last.id, "status": last.status, "posture_score": last.posture_score,
                          "created_at": last.created_at.isoformat(), "severity_counts": (last.summary or {}).get("severity_counts")} if last else None}


@router.get("/projects")
def list_projects(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    ps = db.execute(select(Project).where(Project.organization_id == ctx.org_id).order_by(Project.created_at.desc())).scalars()
    return [project_out(p, db) for p in ps]


@router.post("/projects", status_code=201)
def create_project(body: ProjectIn, ctx: OrgContext = Depends(require("analyst")), db: Session = Depends(get_db)):
    if body.source_type == "github":
        if not REPO_RE.match(body.repo_full_name):
            raise HTTPException(422, "repo_full_name must be owner/repo")
    if body.credential_id:
        get_owned(db, Credential, body.credential_id, ctx)  # must belong to the same org
    p = Project(organization_id=ctx.org_id, name=body.name, description=body.description, source_type=body.source_type,
                repo_full_name=body.repo_full_name if body.source_type == "github" else "", ref=body.ref,
                credential_id=body.credential_id)
    db.add(p)
    db.commit()
    record(db, ctx.org_id, ctx.user, "project.create", f"project:{p.id}", {"name": p.name, "source": p.source_type}, ctx.ip)
    return project_out(p, db)


@router.get("/projects/{project_id}")
def get_project(project_id: str, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    return project_out(get_owned(db, Project, project_id, ctx), db)


@router.delete("/projects/{project_id}", status_code=204)
def delete_project(project_id: str, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    p = get_owned(db, Project, project_id, ctx)
    db.delete(p)
    db.commit()
    record(db, ctx.org_id, ctx.user, "project.delete", f"project:{project_id}", {"name": p.name}, ctx.ip)


@router.get("/projects/{project_id}/trend")
def project_trend(project_id: str, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    get_owned(db, Project, project_id, ctx)
    scans = db.execute(select(Scan).where(Scan.project_id == project_id, Scan.status == "completed", Scan.ref_override == "").order_by(Scan.created_at)).scalars()
    out = []
    for s in scans:
        sm = s.summary or {}
        out.append({"scan_id": s.id, "at": s.created_at.isoformat(), "posture_score": s.posture_score,
                    "coverage": (sm.get("coverage") or {}).get("percent"), **(sm.get("severity_counts") or {}),
                    "categories": {c["category"]: c.get("score") for c in sm.get("categories", [])}})
    return out


# ---------------------------------------------------------------- dashboard

@router.get("/dashboard")
def dashboard(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    projects = db.execute(select(Project).where(Project.organization_id == ctx.org_id)).scalars().all()
    latest = []
    for p in projects:
        s = db.execute(select(Scan).where(Scan.project_id == p.id, Scan.status == "completed", Scan.ref_override == "").order_by(Scan.created_at.desc()).limit(1)).scalar_one_or_none()
        if s:
            latest.append((p, s))
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    cat_scores: dict[str, list] = {}
    for _p, s in latest:
        for k, v in ((s.summary or {}).get("severity_counts") or {}).items():
            sev[k] = sev.get(k, 0) + v
        for c in (s.summary or {}).get("categories", []):
            if c.get("score") is not None:
                cat_scores.setdefault(c["category"], []).append(c["score"])
    open_findings = db.execute(select(func.count()).select_from(Finding).where(
        Finding.organization_id == ctx.org_id, Finding.scan_id.in_([s.id for _p, s in latest] or [""]),
        Finding.triage_status.in_(["open", "confirmed"]))).scalar()
    scores = [s.posture_score for _p, s in latest if s.posture_score is not None]
    recent = db.execute(select(Scan, Project).join(Project, Project.id == Scan.project_id)
                        .where(Scan.organization_id == ctx.org_id).order_by(Scan.created_at.desc()).limit(10)).all()
    return {
        "projects": len(projects), "assessed_projects": len(latest),
        "average_posture": round(sum(scores) / len(scores), 1) if scores else None,
        "severity_counts": sev, "open_findings": open_findings,
        "category_scores": {k: round(sum(v) / len(v), 1) for k, v in sorted(cat_scores.items(), key=lambda kv: int(kv[0].split("-")[-1]))},
        "projects_at_risk": sorted([{"project_id": p.id, "name": p.name, "posture_score": s.posture_score, "scan_id": s.id,
                                     "critical": ((s.summary or {}).get("severity_counts") or {}).get("critical", 0)} for p, s in latest],
                                   key=lambda x: (x["posture_score"] if x["posture_score"] is not None else 101))[:10],
        "recent_scans": [{"id": s.id, "project": p.name, "project_id": p.id, "status": s.status, "posture_score": s.posture_score,
                          "created_at": s.created_at.isoformat()} for s, p in recent],
    }
