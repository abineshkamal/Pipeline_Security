"""Organization-wide view: bulk import of a GitHub organization, risk leaderboard, scan schedules, drift alerts and
notification channels."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..connectors.base import ConnectorError
from ..connectors.github import GitHubClient
from ..db import get_db
from ..deps import OrgContext, get_owned, org_context, require
from ..models import Credential, DriftAlert, NotificationChannel, Project, RiskException, Scan, utcnow
from ..scanner.tools import DEFAULT_TOOLS
from ..security import decrypt_secret, encrypt_secret
from ..services import jobs
from ..services.audit import record
from ..services.exceptions import state as ex_state
from ..services.monitoring import SEV_RANK, UnsafeURL, deliver, ensure_insights, url_hint, validate_webhook_url
from ..services.scheduler import INTERVALS, next_run

router = APIRouter(prefix="/api", tags=["portfolio"])
OWNER_RE = r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$"


def _iso(d):
    return d.isoformat() if d else None


# ---------------------------------------------------------------- import a GitHub organization

class ImportIn(BaseModel):
    owner: str = Field(pattern=OWNER_RE, description="GitHub organization or user")
    credential_id: str | None = None
    include_archived: bool = False
    include_forks: bool = False
    max_repos: int = Field(default=50, ge=1, le=300)
    scan_now: bool = True
    schedule: str = Field(default="", pattern="^(|daily|weekly)$")


def _queue(db, ctx: OrgContext, p: Project, trigger: str) -> str:
    s = Scan(organization_id=ctx.org_id, project_id=p.id, created_by=ctx.user.id,
             options={"tools": list(DEFAULT_TOOLS), "run_tools": True, "ai": True, "trigger": trigger})
    db.add(s)
    db.commit()
    jobs.enqueue_scan(s.id)
    return s.id


@router.post("/portfolio/import")
def import_owner(body: ImportIn, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    """Discover every repository of a GitHub organization (or user) and create a project for each one not yet tracked."""
    token = None
    if body.credential_id:
        token = decrypt_secret(get_owned(db, Credential, body.credential_id, ctx).secret_encrypted)
    gh = GitHubClient(token)
    try:
        repos = gh.list_owner_repos(body.owner, limit=300)
    except ConnectorError as exc:
        raise HTTPException(400, str(exc)) from exc
    finally:
        gh.close()
    eligible = [r for r in repos if (body.include_archived or not r.get("archived")) and (body.include_forks or not r.get("fork"))]
    filtered = len(repos) - len(eligible)
    existing = {p.repo_full_name.lower() for p in db.execute(select(Project).where(Project.organization_id == ctx.org_id,
                                                                                    Project.source_type == "github")).scalars()}
    created, skipped_existing, scans = [], 0, []
    for r in eligible:
        if r["full_name"].lower() in existing:
            skipped_existing += 1
            continue
        if len(created) >= body.max_repos:
            break
        p = Project(organization_id=ctx.org_id, name=r["full_name"].split("/", 1)[1], source_type="github", repo_full_name=r["full_name"],
                    description=f"Imported from {body.owner}" + (" (archived)" if r.get("archived") else ""), credential_id=body.credential_id,
                    schedule=body.schedule, next_scan_at=next_run(body.schedule))
        db.add(p)
        db.commit()
        existing.add(r["full_name"].lower())
        created.append({"id": p.id, "name": p.name, "repo": p.repo_full_name, "private": r.get("private")})
        if body.scan_now:
            scans.append(_queue(db, ctx, p, "import"))
    warning = ""
    if body.scan_now and not token and len(created) > 3:
        warning = ("No token: GitHub allows 60 unauthenticated API calls per hour and each scan uses about 15, so some scans will "
                   "fail with a rate-limit error. Add a read-only token and re-run the failed scans.")
    record(db, ctx.org_id, ctx.user, "portfolio.import", f"github:{body.owner}",
           {"found": len(repos), "created": len(created), "scans": len(scans), "schedule": body.schedule}, ctx.ip)
    return {"owner": body.owner, "found": len(repos), "eligible": len(eligible), "skipped_filtered": filtered,
            "skipped_existing": skipped_existing, "created": created, "scans_queued": len(scans),
            "more_available": len(eligible) - skipped_existing - len(created) > 0, "warning": warning}


# ---------------------------------------------------------------- leaderboard

@router.get("/portfolio")
def portfolio(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    projects = db.execute(select(Project).where(Project.organization_id == ctx.org_id)).scalars().all()
    alerts = dict(db.execute(select(DriftAlert.project_id, func.count()).where(DriftAlert.organization_id == ctx.org_id,
                                                                              DriftAlert.acknowledged_at.is_(None))
                             .group_by(DriftAlert.project_id)).all())
    exs = db.execute(select(RiskException).where(RiskException.organization_id == ctx.org_id)).scalars().all()
    rows = []
    for p in projects:
        scans = db.execute(select(Scan).where(Scan.project_id == p.id).order_by(Scan.created_at.desc()).limit(20)).scalars().all()
        done = [s for s in scans if s.status == "completed" and not s.ref_override]
        last, prev = (done[0] if done else None), (done[1] if len(done) > 1 else None)
        ins = ensure_insights(db, last) if last else {}
        sm = (last.summary or {}) if last else {}
        mine = [e for e in exs if e.project_id == p.id]
        rows.append({
            "project_id": p.id, "name": p.name, "repo": p.repo_full_name, "source_type": p.source_type,
            "team": p.repo_full_name.split("/")[0] if p.repo_full_name else "Uploaded",
            "scan_id": last.id if last else None, "scanned_at": _iso(last.created_at) if last else None,
            "posture_score": last.posture_score if last else None, "grade": sm.get("grade"),
            "score_delta": round(last.posture_score - prev.posture_score, 1) if last and prev and None not in (last.posture_score, prev.posture_score) else None,
            "severity_counts": sm.get("severity_counts") or {}, "attack_paths": ins.get("attack_paths", 0),
            "outsider_secrets": ins.get("outsider_secrets", 0), "stale_secrets": ins.get("stale_secrets", 0),
            "open_findings": ins.get("open_findings", 0), "workflows": len((last.inventory or {}).get("workflows", [])) if last else 0,
            "exceptions_active": sum(1 for e in mine if ex_state(e) == "active"), "exceptions_pending": sum(1 for e in mine if e.status == "pending"),
            "open_alerts": alerts.get(p.id, 0), "schedule": p.schedule, "next_scan_at": _iso(p.next_scan_at),
            "last_status": scans[0].status if scans else None, "last_error": scans[0].error[:200] if scans and scans[0].status == "failed" else "",
        })
    rows.sort(key=lambda r: (r["posture_score"] is None, r["posture_score"] if r["posture_score"] is not None else 0,
                             -(r["severity_counts"].get("critical", 0)), -r["attack_paths"]))
    for i, r in enumerate(rows, 1):
        r["rank"] = i
    teams: dict[str, dict] = {}
    for r in rows:
        t = teams.setdefault(r["team"], {"team": r["team"], "projects": 0, "assessed": 0, "scores": [], "critical": 0, "high": 0,
                                         "attack_paths": 0, "outsider_secrets": 0, "open_alerts": 0})
        t["projects"] += 1
        t["critical"] += r["severity_counts"].get("critical", 0)
        t["high"] += r["severity_counts"].get("high", 0)
        t["attack_paths"] += r["attack_paths"]
        t["outsider_secrets"] += r["outsider_secrets"]
        t["open_alerts"] += r["open_alerts"]
        if r["posture_score"] is not None:
            t["assessed"] += 1
            t["scores"].append(r["posture_score"])
    team_rows = []
    for t in teams.values():
        sc = t.pop("scores")
        team_rows.append({**t, "average_score": round(sum(sc) / len(sc), 1) if sc else None, "worst_score": min(sc) if sc else None})
    team_rows.sort(key=lambda t: (t["average_score"] is None, t["average_score"] or 0))
    assessed = [r for r in rows if r["posture_score"] is not None]
    return {
        "totals": {"projects": len(rows), "assessed": len(assessed),
                   "average_score": round(sum(r["posture_score"] for r in assessed) / len(assessed), 1) if assessed else None,
                   "critical": sum(r["severity_counts"].get("critical", 0) for r in rows),
                   "attack_paths": sum(r["attack_paths"] for r in rows), "outsider_secrets": sum(r["outsider_secrets"] for r in rows),
                   "stale_secrets": sum(r["stale_secrets"] for r in rows), "open_alerts": sum(r["open_alerts"] for r in rows),
                   "scheduled": sum(1 for r in rows if r["schedule"]), "never_scanned": sum(1 for r in rows if not r["scan_id"]),
                   "failed_last_scan": sum(1 for r in rows if r["last_status"] == "failed")},
        "projects": rows, "teams": team_rows,
    }


class BulkScanIn(BaseModel):
    project_ids: list[str] = Field(min_length=1, max_length=300)


@router.post("/portfolio/scan")
def bulk_scan(body: BulkScanIn, ctx: OrgContext = Depends(require("analyst")), db: Session = Depends(get_db)):
    queued, skipped = [], []
    for pid in dict.fromkeys(body.project_ids):
        p = get_owned(db, Project, pid, ctx)
        busy = db.execute(select(Scan.id).where(Scan.project_id == p.id, Scan.status.in_(["queued", "running"])).limit(1)).first()
        if p.source_type != "github" or busy:
            skipped.append({"id": p.id, "name": p.name, "reason": "already scanning" if busy else "ZIP projects need an upload"})
            continue
        queued.append(_queue(db, ctx, p, "bulk"))
    record(db, ctx.org_id, ctx.user, "portfolio.scan", "projects", {"queued": len(queued), "skipped": len(skipped)}, ctx.ip)
    return {"queued": len(queued), "scan_ids": queued, "skipped": skipped}


# ---------------------------------------------------------------- schedules

class ScheduleIn(BaseModel):
    schedule: str = Field(pattern="^(|daily|weekly)$")
    project_ids: list[str] | None = Field(default=None, max_length=300)


def _set_schedule(p: Project, schedule: str) -> None:
    if schedule and p.source_type != "github":
        raise HTTPException(400, f"{p.name}: only GitHub projects can be scanned on a schedule")
    if schedule != p.schedule or (schedule and not p.next_scan_at):
        p.schedule, p.next_scan_at = schedule, next_run(schedule)


@router.put("/projects/{project_id}/schedule")
def set_schedule(project_id: str, body: ScheduleIn, ctx: OrgContext = Depends(require("analyst")), db: Session = Depends(get_db)):
    p = get_owned(db, Project, project_id, ctx)
    _set_schedule(p, body.schedule)
    db.commit()
    record(db, ctx.org_id, ctx.user, "project.schedule", f"project:{p.id}", {"schedule": p.schedule}, ctx.ip)
    return {"project_id": p.id, "schedule": p.schedule, "next_scan_at": _iso(p.next_scan_at)}


@router.put("/portfolio/schedule")
def bulk_schedule(body: ScheduleIn, ctx: OrgContext = Depends(require("analyst")), db: Session = Depends(get_db)):
    if not body.project_ids:
        raise HTTPException(422, "project_ids is required")
    ps = [get_owned(db, Project, pid, ctx) for pid in dict.fromkeys(body.project_ids)]
    changed = 0
    for p in ps:
        if p.source_type == "github":
            _set_schedule(p, body.schedule)
            changed += 1
    db.commit()
    record(db, ctx.org_id, ctx.user, "portfolio.schedule", "projects", {"schedule": body.schedule, "projects": changed}, ctx.ip)
    return {"updated": changed, "schedule": body.schedule, "intervals": list(INTERVALS)}


# ---------------------------------------------------------------- drift alerts

def _alert_out(a: DriftAlert, names: dict[str, str]) -> dict:
    return {"id": a.id, "project_id": a.project_id, "project": names.get(a.project_id, ""), "scan_id": a.scan_id,
            "previous_scan_id": a.previous_scan_id, "severity": a.severity, "title": a.title, "items": a.items,
            "deliveries": a.deliveries, "created_at": _iso(a.created_at), "acknowledged_by": a.acknowledged_by,
            "acknowledged_at": _iso(a.acknowledged_at)}


@router.get("/alerts")
def list_alerts(status: str = Query(default="open", pattern="^(open|all)$"), project_id: str | None = None,
                ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    q = select(DriftAlert).where(DriftAlert.organization_id == ctx.org_id)
    if status == "open":
        q = q.where(DriftAlert.acknowledged_at.is_(None))
    if project_id:
        q = q.where(DriftAlert.project_id == project_id)
    names = dict(db.execute(select(Project.id, Project.name).where(Project.organization_id == ctx.org_id)).all())
    return [_alert_out(a, names) for a in db.execute(q.order_by(DriftAlert.created_at.desc()).limit(200)).scalars()]


@router.post("/alerts/{alert_id}/ack")
def ack_alert(alert_id: str, ctx: OrgContext = Depends(require("analyst")), db: Session = Depends(get_db)):
    a = get_owned(db, DriftAlert, alert_id, ctx)
    if not a.acknowledged_at:
        a.acknowledged_at, a.acknowledged_by = utcnow(), ctx.user.email
        db.commit()
        record(db, ctx.org_id, ctx.user, "alert.ack", f"alert:{a.id}", {}, ctx.ip)
    return _alert_out(a, {a.project_id: db.get(Project, a.project_id).name})


# ---------------------------------------------------------------- notification channels

class ChannelIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    kind: str = Field(pattern="^(slack|teams|webhook)$")
    url: str = Field(min_length=12, max_length=1000)
    min_severity: str = Field(default="high", pattern="^(critical|high|medium|low)$")


def _chan_out(c: NotificationChannel) -> dict:
    return {"id": c.id, "name": c.name, "kind": c.kind, "url_hint": c.url_hint, "min_severity": c.min_severity,
            "enabled": c.enabled, "created_at": _iso(c.created_at)}


@router.get("/notifications/channels")
def list_channels(ctx: OrgContext = Depends(require("analyst")), db: Session = Depends(get_db)):
    return [_chan_out(c) for c in db.execute(select(NotificationChannel).where(NotificationChannel.organization_id == ctx.org_id)
                                             .order_by(NotificationChannel.created_at)).scalars()]


@router.post("/notifications/channels", status_code=201)
def create_channel(body: ChannelIn, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    try:
        url = validate_webhook_url(body.url)
    except UnsafeURL as exc:
        raise HTTPException(422, str(exc)) from exc
    c = NotificationChannel(organization_id=ctx.org_id, name=body.name, kind=body.kind, url_encrypted=encrypt_secret(url),
                            url_hint=url_hint(url), min_severity=body.min_severity)
    db.add(c)
    db.commit()
    record(db, ctx.org_id, ctx.user, "channel.create", f"channel:{c.id}", {"name": c.name, "kind": c.kind}, ctx.ip)
    return _chan_out(c)


class ChannelPatch(BaseModel):
    enabled: bool | None = None
    min_severity: str | None = Field(default=None, pattern="^(critical|high|medium|low)$")


@router.patch("/notifications/channels/{channel_id}")
def update_channel(channel_id: str, body: ChannelPatch, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    c = get_owned(db, NotificationChannel, channel_id, ctx)
    if body.enabled is not None:
        c.enabled = body.enabled
    if body.min_severity:
        c.min_severity = body.min_severity
    db.commit()
    record(db, ctx.org_id, ctx.user, "channel.update", f"channel:{c.id}", body.model_dump(exclude_none=True), ctx.ip)
    return _chan_out(c)


@router.delete("/notifications/channels/{channel_id}", status_code=204)
def delete_channel(channel_id: str, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    c = get_owned(db, NotificationChannel, channel_id, ctx)
    db.delete(c)
    db.commit()
    record(db, ctx.org_id, ctx.user, "channel.delete", f"channel:{channel_id}", {"name": c.name}, ctx.ip)


@router.post("/notifications/channels/{channel_id}/test")
def test_channel(channel_id: str, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    c = get_owned(db, NotificationChannel, channel_id, ctx)
    demo = DriftAlert(id="test", organization_id=ctx.org_id, project_id="", scan_id="", previous_scan_id="", severity="high",
                      title="Test message - PipelineTrust can reach this channel",
                      items=[{"kind": "test", "severity": "high", "text": "Drift alerts for this organization will be posted here."}])
    res = deliver(c, demo, Project(id="", name="(test)", repo_full_name=""))
    record(db, ctx.org_id, ctx.user, "channel.test", f"channel:{c.id}", {"ok": res["ok"], "detail": res["detail"]}, ctx.ip)
    return res


@router.get("/notifications/severities")
def severities():
    return sorted(SEV_RANK, key=lambda k: -SEV_RANK[k])
