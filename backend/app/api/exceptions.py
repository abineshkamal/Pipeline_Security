"""Risk exceptions with a reason, an owner, an expiry date and four-eyes approval."""
from __future__ import annotations

from datetime import date, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import OrgContext, get_owned, org_context, require
from ..models import Finding, Project, RiskException, Scan
from ..services.audit import record
from ..services.exceptions import MAX_DAYS, days_left, decide, matched_count, state, sync_project, today

router = APIRouter(prefix="/api", tags=["exceptions"])


def _out(db, ex: RiskException, names: dict[str, str] | None = None) -> dict:
    st = state(ex)
    return {"id": ex.id, "project_id": ex.project_id, "project": (names or {}).get(ex.project_id) or db.get(Project, ex.project_id).name,
            "scope": ex.scope, "rule_id": ex.rule_id, "fingerprint": ex.fingerprint, "workflow": ex.workflow, "title": ex.title,
            "reason": ex.reason, "compensating_controls": ex.compensating_controls, "owner": ex.owner, "expires_on": ex.expires_on,
            "status": ex.status, "state": st, "days_left": days_left(ex) if st in ("active", "pending") else None,
            "expiring_soon": st == "active" and days_left(ex) <= 14,
            "requested_by": ex.requested_by_email, "requested_at": ex.requested_at.isoformat(),
            "decided_by": ex.decided_by_email, "decided_at": ex.decided_at.isoformat() if ex.decided_at else None,
            "decision_note": ex.decision_note, "matched_findings": matched_count(db, ex)}


@router.get("/exceptions")
def list_exceptions(state_filter: str = Query(default="all", alias="state", pattern="^(all|pending|active|expired|rejected|revoked)$"),
                    project_id: str | None = None, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    q = select(RiskException).where(RiskException.organization_id == ctx.org_id)
    if project_id:
        q = q.where(RiskException.project_id == project_id)
    names = dict(db.execute(select(Project.id, Project.name).where(Project.organization_id == ctx.org_id)).all())
    out = [_out(db, e, names) for e in db.execute(q.order_by(RiskException.requested_at.desc())).scalars()]
    if state_filter != "all":
        out = [e for e in out if e["state"] == state_filter]
    return out


class ExceptionIn(BaseModel):
    finding_id: str
    scope: str = Field(default="finding", pattern="^(finding|rule_in_workflow|rule)$")
    reason: str = Field(min_length=10, max_length=4000)
    compensating_controls: str = Field(default="", max_length=4000)
    owner: str = Field(min_length=2, max_length=200)
    expires_on: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")


@router.post("/exceptions", status_code=201)
def request_exception(body: ExceptionIn, ctx: OrgContext = Depends(require("analyst")), db: Session = Depends(get_db)):
    f = get_owned(db, Finding, body.finding_id, ctx)
    scan = db.get(Scan, f.scan_id)
    try:
        exp = date.fromisoformat(body.expires_on)
    except ValueError as exc:
        raise HTTPException(422, "expires_on is not a valid date") from exc
    t = date.fromisoformat(today())
    if exp <= t or exp > t + timedelta(days=MAX_DAYS):
        raise HTTPException(422, f"expires_on must be after today and at most {MAX_DAYS} days ahead")
    scope = "finding" if body.scope == "finding" else "rule"
    workflow = f.file_path if body.scope == "rule_in_workflow" else ""
    if body.scope == "rule_in_workflow" and not f.file_path:
        raise HTTPException(422, "this finding has no file; use scope 'rule' or 'finding'")
    dup = db.execute(select(RiskException).where(
        RiskException.project_id == scan.project_id, RiskException.rule_id == f.rule_id, RiskException.scope == scope,
        RiskException.fingerprint == (f.fingerprint if scope == "finding" else ""), RiskException.workflow == workflow,
        RiskException.status.in_(["pending", "approved"]))).scalars().all()
    if any(state(d) in ("pending", "active") for d in dup):
        raise HTTPException(409, "an exception for this is already pending or active")
    label = {"finding": "this finding", "rule_in_workflow": f"all {f.rule_id} findings in {workflow}", "rule": f"all {f.rule_id} findings in the project"}
    ex = RiskException(organization_id=ctx.org_id, project_id=scan.project_id, scope=scope, rule_id=f.rule_id,
                       fingerprint=f.fingerprint if scope == "finding" else "", workflow=workflow,
                       title=f"{f.rule_id} {f.title} - {label[body.scope]}"[:300], reason=body.reason,
                       compensating_controls=body.compensating_controls, owner=body.owner, expires_on=body.expires_on,
                       requested_by=ctx.user.id, requested_by_email=ctx.user.email)
    db.add(ex)
    db.commit()
    record(db, ctx.org_id, ctx.user, "exception.request", f"exception:{ex.id}",
           {"rule": f.rule_id, "scope": body.scope, "expires_on": body.expires_on, "finding": f.id}, ctx.ip)
    return _out(db, ex)


class DecisionIn(BaseModel):
    decision: str = Field(pattern="^(approve|reject)$")
    note: str = Field(default="", max_length=2000)


@router.post("/exceptions/{exception_id}/decision")
def decide_exception(exception_id: str, body: DecisionIn, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    ex = get_owned(db, RiskException, exception_id, ctx)
    if ex.status != "pending":
        raise HTTPException(409, f"exception is {ex.status}, not pending")
    if ex.requested_by == ctx.user.id:
        raise HTTPException(403, "four-eyes rule: the requester cannot approve or reject their own exception")
    if body.decision == "approve" and ex.expires_on <= today():
        raise HTTPException(409, "the requested expiry date has passed; ask for a new exception")
    decide(ex, body.decision == "approve", ctx.user.email, body.note)
    db.commit()
    res = sync_project(db, ex.project_id) if body.decision == "approve" else {}
    record(db, ctx.org_id, ctx.user, f"exception.{body.decision}", f"exception:{ex.id}", {"note": bool(body.note), **res}, ctx.ip)
    return {**_out(db, ex), "applied": res}


@router.post("/exceptions/{exception_id}/revoke")
def revoke_exception(exception_id: str, ctx: OrgContext = Depends(require("analyst")), db: Session = Depends(get_db)):
    ex = get_owned(db, RiskException, exception_id, ctx)
    if ex.requested_by != ctx.user.id and not ctx.can("admin"):
        raise HTTPException(403, "only the requester or an admin can revoke an exception")
    if ex.status not in ("pending", "approved"):
        raise HTTPException(409, f"exception is already {ex.status}")
    ex.status = "revoked"
    db.commit()
    res = sync_project(db, ex.project_id)
    record(db, ctx.org_id, ctx.user, "exception.revoke", f"exception:{ex.id}", res, ctx.ip)
    return {**_out(db, ex), "applied": res}
