"""Remediation SLAs: how long findings stay open, per severity and team, against organization targets.

A finding's life is followed by fingerprint across a project's mainline scans: first seen = first scan containing it,
fixed = first later scan without it. Accepted-risk (exceptions) and false positives are not counted as overdue.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from ..models import Finding, OrgSettings, Project, Scan, utcnow

DEFAULT_TARGETS = {"critical": 7, "high": 30, "medium": 90, "low": 180}
SEVS = ("critical", "high", "medium", "low")


def _aware(d: datetime) -> datetime:
    return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d


def get_targets(db, org_id: str) -> dict[str, int]:
    s = db.get(OrgSettings, org_id)
    return {**DEFAULT_TARGETS, **((s.data or {}).get("sla") or {})} if s else dict(DEFAULT_TARGETS)


def set_targets(db, org_id: str, targets: dict[str, int]) -> dict[str, int]:
    s = db.get(OrgSettings, org_id) or OrgSettings(organization_id=org_id, data={})
    s.data = {**(s.data or {}), "sla": {k: int(targets[k]) for k in SEVS if k in targets}}
    s.updated_at = utcnow()
    db.add(s)
    db.commit()
    return get_targets(db, org_id)


def compute(db, org_id: str, window_days: int = 90) -> dict:
    targets = get_targets(db, org_id)
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=window_days)
    projects = db.execute(select(Project).where(Project.organization_id == org_id)).scalars().all()
    open_rows, fixed_rows = [], []
    for p in projects:
        scans = db.execute(select(Scan).where(Scan.project_id == p.id, Scan.status == "completed", Scan.ref_override == "")
                           .order_by(Scan.created_at)).scalars().all()
        if not scans:
            continue
        team = p.repo_full_name.split("/")[0] if p.repo_full_name else "Uploaded"
        first_seen: dict[str, datetime] = {}
        info: dict[str, tuple] = {}
        prev: set[str] = set()
        for s in scans:
            rows = db.execute(select(Finding.fingerprint, Finding.severity, Finding.rule_id, Finding.title, Finding.triage_status, Finding.id,
                                     Finding.file_path).where(Finding.scan_id == s.id)).all()
            cur = {r[0] for r in rows if r[1] in SEVS}
            at = _aware(s.created_at)
            for r in rows:
                if r[1] in SEVS:
                    first_seen.setdefault(r[0], at)
                    info[r[0]] = r
            for fp in prev - cur:  # fixed in this scan
                sev = info[fp][1]
                if at >= since and info[fp][4] != "false_positive":
                    fixed_rows.append({"severity": sev, "team": team, "days": (at - first_seen[fp]).total_seconds() / 86400,
                                       "within": (at - first_seen[fp]).days <= targets[sev]})
                first_seen.pop(fp, None)
            prev = cur
        last = scans[-1]
        for fp in prev:
            fp_, sev, rule, title, tri, fid, path = info[fp]
            if tri in ("false_positive", "accepted_risk", "fixed"):
                continue
            age = (now - first_seen[fp]).days
            open_rows.append({"finding_id": fid, "scan_id": last.id, "project_id": p.id, "project": p.name, "team": team, "severity": sev,
                              "rule_id": rule, "title": title, "file_path": path, "age_days": age, "target_days": targets[sev],
                              "overdue": age > targets[sev], "due_in": targets[sev] - age})
    by_sev = {}
    for sev in SEVS:
        o = [r for r in open_rows if r["severity"] == sev]
        f = [r for r in fixed_rows if r["severity"] == sev]
        by_sev[sev] = {"target_days": targets[sev], "open": len(o), "overdue": sum(1 for r in o if r["overdue"]),
                       "oldest_days": max((r["age_days"] for r in o), default=None),
                       "fixed": len(f), "mttr_days": round(sum(r["days"] for r in f) / len(f), 1) if f else None,
                       "within_target_pct": round(100 * sum(1 for r in f if r["within"]) / len(f)) if f else None}
    teams: dict[str, dict] = {}
    for r in open_rows:
        t = teams.setdefault(r["team"], {"team": r["team"], "open": 0, "overdue": 0, "overdue_critical": 0, "fixed": 0, "mttr": []})
        t["open"] += 1
        t["overdue"] += r["overdue"]
        t["overdue_critical"] += r["overdue"] and r["severity"] == "critical"
    for r in fixed_rows:
        t = teams.setdefault(r["team"], {"team": r["team"], "open": 0, "overdue": 0, "overdue_critical": 0, "fixed": 0, "mttr": []})
        t["fixed"] += 1
        t["mttr"].append(r["days"])
    team_rows = [{**{k: v for k, v in t.items() if k != "mttr"}, "mttr_days": round(sum(t["mttr"]) / len(t["mttr"]), 1) if t["mttr"] else None}
                 for t in teams.values()]
    team_rows.sort(key=lambda t: (-t["overdue_critical"], -t["overdue"]))
    overdue = sorted((r for r in open_rows if r["overdue"]), key=lambda r: (SEVS.index(r["severity"]), -r["age_days"]))
    due_soon = sorted((r for r in open_rows if not r["overdue"] and r["due_in"] <= 7), key=lambda r: r["due_in"])
    return {"targets": targets, "window_days": window_days, "by_severity": by_sev, "teams": team_rows,
            "totals": {"open": len(open_rows), "overdue": len(overdue), "fixed": len(fixed_rows),
                       "within_target_pct": round(100 * sum(1 for r in fixed_rows if r["within"]) / len(fixed_rows)) if fixed_rows else None},
            "overdue": overdue[:300], "due_soon": due_soon[:100],
            "note": "Age counts from the first scan that found the issue, so it depends on how often projects are scanned - schedule scans for accurate SLAs."}
