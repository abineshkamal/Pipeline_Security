from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..deps import OrgContext, get_owned, org_context, require
from ..models import Finding, Project, Scan
from ..reports.render import render_html, render_json, render_sarif
from ..scanner.rules import load_rules
from ..scanner.tools import ALL_TOOLS, DEFAULT_TOOLS, tool_inventory
from ..services.audit import record
from ..services.jobs import enqueue_scan
from ..services.scan_runner import artifacts_dir, finding_to_dict, run_ai_for_scan

router = APIRouter(prefix="/api", tags=["scans"])

TRIAGE = {"open", "confirmed", "false_positive", "accepted_risk", "fixed"}
VALIDATION = {"unvalidated", "config_evidence", "needs_validation", "validated", "not_reproducible"}


class ScanOptions(BaseModel):
    tools: list[str] = Field(default_factory=lambda: list(DEFAULT_TOOLS))
    run_tools: bool = True
    ai: bool = True


def _clean_options(o: ScanOptions) -> dict:
    bad = [t for t in o.tools if t not in ALL_TOOLS]
    if bad:
        raise HTTPException(422, f"unknown tools: {', '.join(bad)}")
    return o.model_dump()


def scan_out(s: Scan, full: bool = False) -> dict:
    base = {"id": s.id, "project_id": s.project_id, "status": s.status, "progress": s.progress, "error": s.error,
            "posture_score": s.posture_score, "commit_sha": s.commit_sha, "options": s.options,
            "created_at": s.created_at.isoformat(), "started_at": s.started_at.isoformat() if s.started_at else None,
            "finished_at": s.finished_at.isoformat() if s.finished_at else None,
            "severity_counts": (s.summary or {}).get("severity_counts"), "grade": (s.summary or {}).get("grade")}
    if full:
        base.update(summary=s.summary, inventory=s.inventory, controls=s.controls, tool_runs=s.tool_runs,
                    attack_graph=s.attack_graph, ai_analysis=s.ai_analysis)
    return base


@router.get("/rules")
def rules():
    return [cls.describe() for cls in load_rules().values()]


@router.get("/tools")
def tools(_ctx: OrgContext = Depends(org_context)):
    return tool_inventory()


@router.post("/projects/{project_id}/scans", status_code=202)
def start_scan(project_id: str, opts: ScanOptions | None = None, ctx: OrgContext = Depends(require("analyst")), db: Session = Depends(get_db)):
    p = get_owned(db, Project, project_id, ctx)
    if p.source_type != "github":
        raise HTTPException(400, "upload projects are scanned by uploading a ZIP to /scans/upload")
    s = Scan(organization_id=ctx.org_id, project_id=p.id, options=_clean_options(opts or ScanOptions()), created_by=ctx.user.id)
    db.add(s)
    db.commit()
    mode = enqueue_scan(s.id)
    record(db, ctx.org_id, ctx.user, "scan.start", f"scan:{s.id}", {"project": p.name, "queue": mode}, ctx.ip)
    return scan_out(s)


@router.post("/projects/{project_id}/scans/upload", status_code=202)
async def upload_scan(project_id: str, file: UploadFile = File(...), tools: str = Query(default=",".join(DEFAULT_TOOLS)),
                      ai: bool = True, ctx: OrgContext = Depends(require("analyst")), db: Session = Depends(get_db)):
    p = get_owned(db, Project, project_id, ctx)
    opts = _clean_options(ScanOptions(tools=[t for t in tools.split(",") if t], run_tools=bool(tools), ai=ai))
    s = get_settings()
    limit = s.max_upload_mb * 1024 * 1024
    updir = s.data_dir / "uploads"
    updir.mkdir(parents=True, exist_ok=True)
    dest = updir / f"{uuid.uuid4().hex}.zip"
    size = 0
    with open(dest, "wb") as out:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                out.close()
                dest.unlink(missing_ok=True)
                raise HTTPException(413, f"archive exceeds {s.max_upload_mb} MiB")
            out.write(chunk)
    with open(dest, "rb") as fh:
        magic = fh.read(4)
    if magic != b"PK\x03\x04":
        dest.unlink(missing_ok=True)
        raise HTTPException(422, "file is not a ZIP archive")
    scan = Scan(organization_id=ctx.org_id, project_id=p.id, options=opts, upload_path=str(dest), created_by=ctx.user.id)
    db.add(scan)
    db.commit()
    mode = enqueue_scan(scan.id)
    record(db, ctx.org_id, ctx.user, "scan.upload", f"scan:{scan.id}", {"project": p.name, "bytes": size, "filename": (file.filename or "")[:120], "queue": mode}, ctx.ip)
    return scan_out(scan)


@router.get("/projects/{project_id}/scans")
def list_scans(project_id: str, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    get_owned(db, Project, project_id, ctx)
    return [scan_out(s) for s in db.execute(select(Scan).where(Scan.project_id == project_id, Scan.organization_id == ctx.org_id)
                                            .order_by(Scan.created_at.desc())).scalars()]


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    s = get_owned(db, Scan, scan_id, ctx)
    out = scan_out(s, full=True)
    p = db.get(Project, s.project_id)
    out["project"] = {"id": p.id, "name": p.name, "source_type": p.source_type, "repo_full_name": p.repo_full_name}
    return out


@router.delete("/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: str, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    s = get_owned(db, Scan, scan_id, ctx)
    db.delete(s)
    db.commit()
    record(db, ctx.org_id, ctx.user, "scan.delete", f"scan:{scan_id}", {}, ctx.ip)


@router.get("/scans/{scan_id}/findings")
def list_findings(scan_id: str, category: str | None = None, severity: str | None = None, triage: str | None = None,
                  rule_id: str | None = None, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    get_owned(db, Scan, scan_id, ctx)
    q = select(Finding).where(Finding.scan_id == scan_id, Finding.organization_id == ctx.org_id)
    if category:
        q = q.where(Finding.category == category)
    if severity:
        q = q.where(Finding.severity.in_(severity.split(",")))
    if triage:
        q = q.where(Finding.triage_status.in_(triage.split(",")))
    if rule_id:
        q = q.where(Finding.rule_id == rule_id)
    return [finding_to_dict(f) for f in db.execute(q.order_by(Finding.risk_score.desc(), Finding.file_path, Finding.line)).scalars()]


class TriageIn(BaseModel):
    triage_status: str | None = None
    validation_status: str | None = None
    triage_note: str | None = Field(default=None, max_length=4000)


@router.patch("/findings/{finding_id}")
def triage_finding(finding_id: str, body: TriageIn, ctx: OrgContext = Depends(require("analyst")), db: Session = Depends(get_db)):
    f = get_owned(db, Finding, finding_id, ctx)
    changes = {}
    if body.triage_status is not None:
        if body.triage_status not in TRIAGE:
            raise HTTPException(422, f"triage_status must be one of {sorted(TRIAGE)}")
        changes["triage_status"] = (f.triage_status, body.triage_status)
        f.triage_status = body.triage_status
    if body.validation_status is not None:
        if body.validation_status not in VALIDATION:
            raise HTTPException(422, f"validation_status must be one of {sorted(VALIDATION)}")
        changes["validation_status"] = (f.validation_status, body.validation_status)
        f.validation_status = body.validation_status
    if body.triage_note is not None:
        f.triage_note = body.triage_note
        changes["note"] = True
    db.commit()
    record(db, ctx.org_id, ctx.user, "finding.triage", f"finding:{finding_id}", changes, ctx.ip)
    return finding_to_dict(f)


@router.post("/scans/{scan_id}/ai")
def rerun_ai(scan_id: str, ctx: OrgContext = Depends(require("analyst")), db: Session = Depends(get_db)):
    s = get_owned(db, Scan, scan_id, ctx)
    if s.status != "completed":
        raise HTTPException(409, "scan is not completed")
    a = run_ai_for_scan(db, s)
    record(db, ctx.org_id, ctx.user, "scan.ai_rerun", f"scan:{scan_id}", {"mode": a.get("mode"), "provider": a.get("provider")}, ctx.ip)
    return a


@router.get("/scans/{scan_id}/compare/{other_id}")
def compare(scan_id: str, other_id: str, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    """Diff two scans of the same project by finding fingerprint (new / fixed / persisting)."""
    a, b = get_owned(db, Scan, scan_id, ctx), get_owned(db, Scan, other_id, ctx)
    if a.project_id != b.project_id:
        raise HTTPException(400, "scans belong to different projects")
    fa = {f.fingerprint: f for f in db.execute(select(Finding).where(Finding.scan_id == a.id)).scalars()}
    fb = {f.fingerprint: f for f in db.execute(select(Finding).where(Finding.scan_id == b.id)).scalars()}
    brief = lambda f: {"id": f.id, "rule_id": f.rule_id, "title": f.title, "severity": f.severity, "file_path": f.file_path, "line": f.line}  # noqa: E731
    return {"new": [brief(fa[k]) for k in fa.keys() - fb.keys()], "fixed": [brief(fb[k]) for k in fb.keys() - fa.keys()],
            "persisting": len(fa.keys() & fb.keys()), "score_delta": round((a.posture_score or 0) - (b.posture_score or 0), 1)}


def _report_data(db, s: Scan) -> dict:
    p = db.get(Project, s.project_id)
    findings = [finding_to_dict(f) for f in db.execute(select(Finding).where(Finding.scan_id == s.id)
                                                       .order_by(Finding.risk_score.desc())).scalars()]
    return {"scan": scan_out(s, full=True), "project": {"name": p.name, "repo": p.repo_full_name, "source": p.source_type},
            "findings": findings, "rules": {rid: c.describe() for rid, c in load_rules().items()}}


@router.get("/scans/{scan_id}/report.{fmt}")
def report(scan_id: str, fmt: str, include_false_positives: bool = False, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    s = get_owned(db, Scan, scan_id, ctx)
    if s.status != "completed":
        raise HTTPException(409, "scan is not completed")
    data = _report_data(db, s)
    if not include_false_positives:
        data["findings"] = [f for f in data["findings"] if f["triage_status"] != "false_positive"]
    record(db, ctx.org_id, ctx.user, "report.export", f"scan:{scan_id}", {"format": fmt}, ctx.ip)
    name = f"pipelinetrust-{data['project']['name'].replace(' ', '_')[:40]}-{scan_id[:8]}"
    headers = {"Content-Disposition": f'attachment; filename="{name}.{fmt}"'}
    if fmt == "html":
        return HTMLResponse(render_html(data), headers=headers)
    if fmt == "json":
        return JSONResponse(render_json(data), headers=headers)
    if fmt == "sarif":
        return JSONResponse(render_sarif(data), headers=headers, media_type="application/sarif+json")
    raise HTTPException(404, "format must be html, json or sarif")


@router.get("/scans/{scan_id}/sbom")
def sbom(scan_id: str, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    get_owned(db, Scan, scan_id, ctx)
    path: Path = artifacts_dir(scan_id) / "sbom.cdx.json"
    if not path.exists():
        raise HTTPException(404, "no SBOM was generated for this scan")
    return FileResponse(path, media_type="application/vnd.cyclonedx+json", filename=f"sbom-{scan_id[:8]}.cdx.json")
