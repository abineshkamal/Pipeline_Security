"""Risk exceptions: an approved, time-boxed acceptance of a finding (or of one rule in a project / workflow).

An active exception marks matching findings `accepted_risk` and records the exception on the finding
(`extra.exception`). When it expires or is revoked the findings it covered are reopened, so accepted risk never
silently becomes permanent. Exceptions do not change control status or the posture score: the risk still exists.
"""
from __future__ import annotations

from datetime import date, datetime, timezone

from sqlalchemy import select

from ..models import Finding, RiskException, Scan, utcnow

MAX_DAYS = 365


def today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def state(ex: RiskException, on: str | None = None) -> str:
    """pending | active | expired | rejected | revoked"""
    if ex.status == "approved":
        return "active" if ex.expires_on >= (on or today()) else "expired"
    return ex.status


def days_left(ex: RiskException) -> int:
    return (date.fromisoformat(ex.expires_on) - date.fromisoformat(today())).days


def matches(ex: RiskException, f: Finding) -> bool:
    if ex.rule_id != f.rule_id:
        return False
    if ex.scope == "finding":
        return ex.fingerprint == f.fingerprint
    return not ex.workflow or f.file_path == ex.workflow


def latest_scan(db, project_id: str) -> Scan | None:
    return db.execute(select(Scan).where(Scan.project_id == project_id, Scan.status == "completed", Scan.ref_override == "")
                      .order_by(Scan.created_at.desc()).limit(1)).scalar_one_or_none()


def apply_to_findings(db, project_id: str, findings: list[Finding]) -> dict:
    """Mark findings covered by an active exception; reopen findings whose exception is no longer active."""
    exs = db.execute(select(RiskException).where(RiskException.project_id == project_id, RiskException.status == "approved")).scalars().all()
    active = [e for e in exs if state(e) == "active"]
    covered = reopened = 0
    for f in findings:
        ex = next((e for e in active if matches(e, f)), None)
        marker = (f.extra or {}).get("exception")
        if ex:
            if f.triage_status in ("false_positive", "fixed"):
                continue  # an analyst decision that is stronger than an exception
            if f.triage_status != "accepted_risk" or not marker or marker.get("id") != ex.id:
                covered += 1
            f.triage_status = "accepted_risk"
            f.extra = {**(f.extra or {}), "exception": {"id": ex.id, "expires_on": ex.expires_on, "owner": ex.owner,
                                                        "approved_by": ex.decided_by_email, "scope": ex.scope}}
        elif marker:
            extra = dict(f.extra or {})
            extra.pop("exception", None)
            f.extra = extra
            if f.triage_status == "accepted_risk":
                f.triage_status = "open"
                reopened += 1
    return {"covered": covered, "reopened": reopened}


def sync_project(db, project_id: str) -> dict:
    scan = latest_scan(db, project_id)
    if not scan:
        return {"covered": 0, "reopened": 0}
    fs = db.execute(select(Finding).where(Finding.scan_id == scan.id)).scalars().all()
    out = apply_to_findings(db, project_id, fs)
    db.commit()
    return out


def matched_count(db, ex: RiskException) -> int:
    scan = latest_scan(db, ex.project_id)
    if not scan:
        return 0
    fs = db.execute(select(Finding).where(Finding.scan_id == scan.id, Finding.rule_id == ex.rule_id)).scalars().all()
    return sum(1 for f in fs if matches(ex, f))


def expire_due(db) -> int:
    """Reopen findings of exceptions that expired since the last run (called by the scheduler)."""
    exs = db.execute(select(RiskException).where(RiskException.status == "approved", RiskException.expires_on < today())).scalars().all()
    projects = set()
    for ex in exs:
        scan = latest_scan(db, ex.project_id)
        if scan and db.execute(select(Finding.id).where(Finding.scan_id == scan.id, Finding.triage_status == "accepted_risk")
                               .limit(1)).first():
            projects.add(ex.project_id)
    for pid in projects:
        sync_project(db, pid)
    return len(projects)


def decide(ex: RiskException, approve: bool, approver_email: str, note: str) -> None:
    ex.status = "approved" if approve else "rejected"
    ex.decided_by_email = approver_email
    ex.decided_at = utcnow()
    ex.decision_note = note
