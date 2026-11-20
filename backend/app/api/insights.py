"""Scan insights: secret blast radius, what-if simulation, verified fixes (+ pull requests), compliance packs and Q&A."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..connectors.github import GitHubClient
from ..db import get_db
from ..deps import OrgContext, get_owned, org_context, require
from ..insights import ask as ask_mod
from ..insights import compliance, fixes, whatif
from ..insights.secrets import secret_exposure
from ..models import ActionAdvisory, Credential, Finding, Project, Scan
from ..security import decrypt_secret
from ..services.audit import record
from ..services.scan_runner import load_workflow_sources, save_workflow_sources

router = APIRouter(prefix="/api", tags=["insights"])


def _completed(db: Session, scan_id: str, ctx: OrgContext) -> Scan:
    s = get_owned(db, Scan, scan_id, ctx)
    if s.status != "completed":
        raise HTTPException(409, "scan is not completed")
    return s


def _findings(db: Session, scan: Scan, ctx: OrgContext) -> list[Finding]:
    return list(db.execute(select(Finding).where(Finding.scan_id == scan.id, Finding.organization_id == ctx.org_id)
                           .order_by(Finding.risk_score.desc())).scalars())


def _token(db: Session, cred_id: str | None, ctx: OrgContext) -> str | None:
    if not cred_id:
        return None
    c = db.get(Credential, cred_id)
    if not c or c.organization_id != ctx.org_id:
        raise HTTPException(404, "credential not found")
    return decrypt_secret(c.secret_encrypted)


# ---------------------------------------------------------------- secrets

@router.get("/scans/{scan_id}/secrets")
def secrets_map(scan_id: str, pipeline: str | None = Query(default=None, max_length=500),
                ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    s = _completed(db, scan_id, ctx)
    out = secret_exposure(s, _findings(db, s, ctx))
    if pipeline:
        keep = []
        for sec in out["secrets"]:
            uses = [u for u in sec["uses"] if u["workflow"] == pipeline]
            if uses:
                keep.append({**sec, "uses": uses})
        out = {**out, "secrets": keep, "pipeline": pipeline}
    return out


# ---------------------------------------------------------------- what-if

class WhatIfIn(BaseModel):
    finding_ids: list[str] = Field(default_factory=list, max_length=2000)


@router.post("/scans/{scan_id}/whatif")
def what_if(scan_id: str, body: WhatIfIn, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    s = _completed(db, scan_id, ctx)
    return whatif.simulate(s, _findings(db, s, ctx), set(body.finding_ids))


@router.get("/scans/{scan_id}/whatif/recommendations")
def what_if_recommendations(scan_id: str, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    s = _completed(db, scan_id, ctx)
    return whatif.recommendations(s, _findings(db, s, ctx), fixes.FIXABLE_RULES)


# ---------------------------------------------------------------- fixes

def _plan(db: Session, s: Scan, ctx: OrgContext, finding_ids: list[str] | None, pipeline: str | None) -> tuple[dict, Project]:
    p = db.get(Project, s.project_id)
    token = _token(db, p.credential_id, ctx) if p.credential_id else None
    src = load_workflow_sources(s.id)
    if src is None and p.source_type == "github" and p.repo_full_name:
        paths = [w["path"] for w in (s.inventory or {}).get("workflows", [])]
        try:
            src = fixes.fetch_sources(p.repo_full_name, s.commit_sha, paths, token)
        except Exception:  # noqa: BLE001 - network failure: report below
            src = {}
        if src:
            save_workflow_sources(s.id, src)
    if not src:
        raise HTTPException(409, "workflow files for this scan are not available; re-run the scan to enable fixes")
    fs = _findings(db, s, ctx)
    if finding_ids:
        want = set(finding_ids)
        fs = [f for f in fs if f.id in want]
    if pipeline:
        fs = [f for f in fs if f.file_path == pipeline]
    advs = [a.as_advisory() for a in db.execute(select(ActionAdvisory).where(ActionAdvisory.organization_id == ctx.org_id)).scalars()]
    gh = GitHubClient(token)
    try:
        plan = fixes.plan_fixes(src, fs, s.inventory or {}, gh.resolve_sha, advs)
    finally:
        gh.close()
    return plan, p


def _ids(raw: str | None) -> list[str] | None:
    return [x for x in (raw or "").split(",") if x] or None


@router.get("/scans/{scan_id}/fixes")
def fix_preview(scan_id: str, pipeline: str | None = Query(default=None, max_length=500), finding_ids: str | None = Query(default=None, max_length=20000),
                ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    s = _completed(db, scan_id, ctx)
    plan, _ = _plan(db, s, ctx, _ids(finding_ids), pipeline)
    plan["fixable_rules"] = {r: fixes.FIX_LABELS[r] for r in sorted(fixes.FIXABLE_RULES)}
    return plan


@router.get("/scans/{scan_id}/fixes.patch")
def fix_patch(scan_id: str, pipeline: str | None = Query(default=None, max_length=500), finding_ids: str | None = Query(default=None, max_length=20000),
              ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    s = _completed(db, scan_id, ctx)
    plan, _ = _plan(db, s, ctx, _ids(finding_ids), pipeline)
    record(db, ctx.org_id, ctx.user, "fixes.export", f"scan:{scan_id}", {"files": plan["summary"]["files"], "applied": plan["summary"]["applied"]}, ctx.ip)
    return PlainTextResponse(plan["patch"] or "", media_type="text/x-diff",
                             headers={"Content-Disposition": f'attachment; filename="pipelinetrust-fixes-{scan_id[:8]}.patch"'})


class PullRequestIn(BaseModel):
    credential_id: str
    finding_ids: list[str] = Field(default_factory=list, max_length=2000)
    pipeline: str | None = Field(default=None, max_length=500)
    title: str = Field(default="Harden GitHub Actions workflows (PipelineTrust)", max_length=200)


@router.post("/scans/{scan_id}/fixes/pull-request")
def fix_pull_request(scan_id: str, body: PullRequestIn, ctx: OrgContext = Depends(require("analyst")), db: Session = Depends(get_db)):
    s = _completed(db, scan_id, ctx)
    p = db.get(Project, s.project_id)
    if p.source_type != "github" or not p.repo_full_name:
        raise HTTPException(400, "pull requests are only available for GitHub projects; download the patch instead")
    token = _token(db, body.credential_id, ctx)
    plan, _ = _plan(db, s, ctx, body.finding_ids or None, body.pipeline)
    files = {f["path"]: f["patched"] for f in plan["files"] if not f["parse_error"] and f["verified"]}
    if not files:
        raise HTTPException(409, "no verified fixes to submit")
    applied = [x for x in plan["fixes"] if x["status"] == "applied" and x["file"] in files]
    review = [x for x in applied if x["review"]]
    body_md = ("Automated, rule-based fixes generated by PipelineTrust and verified by re-running its workflow rules on the "
               f"patched files (scan `{s.id[:8]}`, commit `{(s.commit_sha or '')[:10]}`).\n\n"
               + "\n".join(f"- **{x['label']}** - `{x['file']}`{':' + str(x['line']) if x['line'] else ''} ({x['rule_id']})" for x in applied[:60])
               + ("\n\n### Please review\n" + "\n".join(f"- `{x['file']}`: {x['review']}" for x in review) if review else ""))
    try:
        pr = fixes.open_pull_request(p.repo_full_name, s.commit_sha, files, token, body.title, body_md)
    except fixes.GitHubWriteError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - network errors
        raise HTTPException(502, f"GitHub API error: {type(exc).__name__}") from exc
    record(db, ctx.org_id, ctx.user, "fixes.pull_request", f"scan:{scan_id}", {"url": pr["url"], "files": len(files), "fixes": len(applied)}, ctx.ip)
    return {**pr, "files": len(files), "fixes": len(applied)}


# ---------------------------------------------------------------- compliance

@router.get("/compliance/frameworks")
def frameworks(_ctx: OrgContext = Depends(org_context)):
    return [{"id": k, "name": v["name"], "requirements": len(v["controls"])} for k, v in compliance.FRAMEWORKS.items()]


@router.get("/scans/{scan_id}/compliance/{framework}")
def compliance_pack(scan_id: str, framework: str, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    if framework not in compliance.FRAMEWORKS:
        raise HTTPException(404, "unknown framework")
    s = _completed(db, scan_id, ctx)
    return compliance.assess(s, _findings(db, s, ctx), framework)


@router.get("/scans/{scan_id}/compliance/{framework}/export.{fmt}")
def compliance_export(scan_id: str, framework: str, fmt: str, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    if framework not in compliance.FRAMEWORKS or fmt not in ("html", "csv", "json"):
        raise HTTPException(404, "unknown framework or format")
    s = _completed(db, scan_id, ctx)
    pack = compliance.assess(s, _findings(db, s, ctx), framework)
    p = db.get(Project, s.project_id)
    record(db, ctx.org_id, ctx.user, "report.export", f"scan:{scan_id}", {"format": f"compliance-{framework}.{fmt}"}, ctx.ip)
    name = f"pipelinetrust-{framework}-{scan_id[:8]}.{fmt}"
    disp = {"Content-Disposition": f'attachment; filename="{name}"'}
    if fmt == "json":
        return JSONResponse(pack, headers=disp)
    if fmt == "csv":
        return PlainTextResponse(compliance.to_csv(pack), media_type="text/csv", headers=disp)
    return HTMLResponse(compliance.to_html(pack, p.name, p.repo_full_name, s.created_at.isoformat(), s.commit_sha), headers=disp)


# ---------------------------------------------------------------- ask

class AskIn(BaseModel):
    question: str = Field(min_length=3, max_length=500)
    mode: str = Field(default="auto", pattern="^(auto|llm|deterministic)$")


@router.get("/ask/examples")
def ask_examples(_ctx: OrgContext = Depends(org_context)):
    return ask_mod.EXAMPLES


@router.post("/scans/{scan_id}/ask")
def ask(scan_id: str, body: AskIn, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    s = _completed(db, scan_id, ctx)
    res = ask_mod.ask(s, _findings(db, s, ctx), body.question, body.mode)
    record(db, ctx.org_id, ctx.user, "scan.ask", f"scan:{scan_id}", {"mode": res.get("mode"), "chars": len(body.question)}, ctx.ip)
    return res
