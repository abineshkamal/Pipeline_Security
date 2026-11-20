"""Continuous monitoring: drift between consecutive scans of a project, and alert delivery to Slack / Teams / webhooks.

Only regressions raise an alert (new attack path, new critical/high finding, a secret newly reachable by outsiders,
a score drop). Improvements are never alerted, so a nightly scan stays quiet until something gets worse.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
from urllib.parse import urlparse

import httpx
from sqlalchemy import select

from ..config import get_settings
from ..insights.secrets import secret_exposure
from ..models import DriftAlert, Finding, NotificationChannel, Project, Scan
from ..security import decrypt_secret

log = logging.getLogger("pipelinetrust.monitoring")

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SCORE_DROP_MIN = 1.0  # points; smaller movements are noise from coverage changes
IGNORED_TRIAGE = ("false_positive", "accepted_risk", "fixed")


def path_severity(risk: float) -> str:
    return "critical" if risk >= 8 else "high" if risk >= 6 else "medium" if risk >= 4 else "low"


def scan_insights(scan: Scan, findings: list[Finding]) -> dict:
    """Small roll-up stored on the scan summary so portfolio views need no per-project recomputation."""
    sx = secret_exposure(scan, findings)
    return {"attack_paths": len((scan.attack_graph or {}).get("paths", [])), "secrets": len(sx["secrets"]),
            "outsider_secrets": sx["outsider_reachable"], "stale_secrets": sx["rotation"]["counts"]["stale"],
            "rotate_first": sx["rotation"]["rotate_first"][:20],
            "open_findings": sum(1 for f in findings if f.triage_status in ("open", "confirmed")),
            "accepted_risk": sum(1 for f in findings if f.triage_status == "accepted_risk")}


def ensure_insights(db, scan: Scan) -> dict:
    ins = (scan.summary or {}).get("insights")
    if ins is None:
        fs = db.execute(select(Finding).where(Finding.scan_id == scan.id)).scalars().all()
        ins = scan_insights(scan, fs)
        scan.summary = {**(scan.summary or {}), "insights": ins}
        db.commit()
    return ins


def detect_drift(prev: Scan, prev_findings: list[Finding], cur: Scan, cur_findings: list[Finding]) -> list[dict]:
    items: list[dict] = []
    ps, cs = prev.posture_score, cur.posture_score
    if ps is not None and cs is not None and cs <= ps - SCORE_DROP_MIN:
        drop = round(ps - cs, 1)
        g0, g1 = (prev.summary or {}).get("grade"), (cur.summary or {}).get("grade")
        items.append({"kind": "score_drop", "severity": "high" if drop >= 10 else "medium",
                      "text": f"Posture score fell {drop} points ({ps} → {cs}" + (f", grade {g0} → {g1}" if g0 != g1 else "") + ")"})

    old_fp = {f.fingerprint for f in prev_findings}
    new = [f for f in cur_findings if f.fingerprint not in old_fp and f.severity in ("critical", "high")
           and f.triage_status not in IGNORED_TRIAGE]
    for f in sorted(new, key=lambda x: (-SEV_RANK[x.severity], -x.risk_score))[:15]:
        loc = f"{f.file_path}:{f.line}" if f.file_path and f.line else f.file_path or "repository settings"
        items.append({"kind": "new_finding", "severity": f.severity, "ref": f.id, "rule_id": f.rule_id,
                      "text": f"New {f.severity} finding {f.rule_id}: {f.title} ({loc})"})
    if len(new) > 15:
        items.append({"kind": "more_findings", "severity": "high", "text": f"…and {len(new) - 15} more new critical/high finding(s)"})

    old_paths = {tuple(p["nodes"]) for p in (prev.attack_graph or {}).get("paths", [])}
    for p in (cur.attack_graph or {}).get("paths", []):
        if tuple(p["nodes"]) not in old_paths:
            items.append({"kind": "new_attack_path", "severity": path_severity(p.get("risk", 0)), "ref": p.get("id"),
                          "text": f"New attack path {p.get('id')} (risk {p.get('risk')}): " + " → ".join(p.get("labels", []))})

    old_out = {s["name"] for s in secret_exposure(prev, prev_findings)["secrets"] if s["reach"] == "outsiders"}
    for s in secret_exposure(cur, cur_findings)["secrets"]:
        if s["reach"] == "outsiders" and s["name"] not in old_out:
            items.append({"kind": "secret_exposed", "severity": "critical" if s["level"] == "critical" else "high", "ref": s["name"],
                          "text": f"Secret {s['name']} is now reachable by outsiders (via {s['uses'][0]['workflow']})"})
    return sorted(items, key=lambda i: -SEV_RANK[i["severity"]])


# ---------------------------------------------------------------- delivery

class UnsafeURL(ValueError):
    pass


def validate_webhook_url(url: str) -> str:
    """HTTPS only, and never to loopback / private / link-local addresses (prevents SSRF into the hosting network)."""
    u = urlparse(url.strip())
    if u.scheme != "https" or not u.hostname or u.username or u.password:
        raise UnsafeURL("webhook URL must be https://host/… without credentials")
    if get_settings().allow_private_webhooks:
        return url.strip()
    try:
        addrs = {ai[4][0] for ai in socket.getaddrinfo(u.hostname, u.port or 443, proto=socket.IPPROTO_TCP)}
    except OSError as exc:
        raise UnsafeURL(f"cannot resolve {u.hostname}") from exc
    for a in addrs:
        ip = ipaddress.ip_address(a.split("%")[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise UnsafeURL(f"{u.hostname} resolves to a non-public address")
    return url.strip()


def url_hint(url: str) -> str:
    u = urlparse(url)
    return f"{u.scheme}://{u.hostname}/…{url[-4:]}"


def _link(path: str) -> str:
    base = get_settings().public_url.rstrip("/")
    return f"{base}{path}" if base else ""


def payload(kind: str, alert: DriftAlert, project: Project) -> dict:
    link = _link(f"/scan?id={alert.scan_id}")
    lines = [f"• [{i['severity'].upper()}] {i['text']}" for i in alert.items[:12]]
    if len(alert.items) > 12:
        lines.append(f"• …and {len(alert.items) - 12} more")
    if kind == "slack":
        text = f"*PipelineTrust drift alert* ({alert.severity})\n*{alert.title}*\n" + "\n".join(lines) + (f"\n<{link}|Open the scan>" if link else "")
        return {"text": text}
    if kind == "teams":
        body = [{"type": "TextBlock", "text": f"PipelineTrust drift alert ({alert.severity})", "weight": "Bolder", "size": "Medium"},
                {"type": "TextBlock", "text": alert.title, "wrap": True}] + [{"type": "TextBlock", "text": ln, "wrap": True, "spacing": "Small"} for ln in lines]
        card = {"type": "AdaptiveCard", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "version": "1.4", "body": body}
        if link:
            card["actions"] = [{"type": "Action.OpenUrl", "title": "Open the scan", "url": link}]
        return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}
    return {"event": "drift_alert", "alert_id": alert.id, "severity": alert.severity, "title": alert.title,
            "project": {"id": project.id, "name": project.name, "repository": project.repo_full_name},
            "scan_id": alert.scan_id, "previous_scan_id": alert.previous_scan_id, "items": alert.items, "url": link or None}


def post_json(url: str, body: dict) -> int:
    with httpx.Client(timeout=10, follow_redirects=False) as c:
        return c.post(url, json=body, headers={"User-Agent": "PipelineTrust-Alerts", "X-PipelineTrust-Event": "drift_alert"}).status_code


def deliver(ch: NotificationChannel, alert: DriftAlert, project: Project) -> dict:
    try:
        url = validate_webhook_url(decrypt_secret(ch.url_encrypted))
        code = post_json(url, payload(ch.kind, alert, project))
        ok = 200 <= code < 300
        return {"channel": ch.name, "channel_id": ch.id, "ok": ok, "detail": f"HTTP {code}"}
    except (UnsafeURL, httpx.HTTPError) as exc:
        return {"channel": ch.name, "channel_id": ch.id, "ok": False, "detail": f"{type(exc).__name__}: {exc}"[:200]}


def notify(db, alert: DriftAlert, project: Project) -> list[dict]:
    chans = db.execute(select(NotificationChannel).where(NotificationChannel.organization_id == alert.organization_id,
                                                         NotificationChannel.enabled.is_(True))).scalars().all()
    out = [deliver(ch, alert, project) for ch in chans if SEV_RANK[alert.severity] >= SEV_RANK.get(ch.min_severity, 3)]
    alert.deliveries = out
    db.commit()
    return out


def after_scan(db, scan: Scan) -> DriftAlert | None:
    """Called when a scan completes: store the insight roll-up, compare with the previous scan, alert on regressions."""
    project = db.get(Project, scan.project_id)
    cur_f = db.execute(select(Finding).where(Finding.scan_id == scan.id)).scalars().all()
    scan.summary = {**(scan.summary or {}), "insights": scan_insights(scan, cur_f)}
    db.commit()
    if scan.ref_override:  # a release / branch comparison scan is not a change of the project's posture
        return None
    prev = db.execute(select(Scan).where(Scan.project_id == scan.project_id, Scan.id != scan.id, Scan.status == "completed", Scan.ref_override == "",
                                         Scan.created_at < scan.created_at).order_by(Scan.created_at.desc()).limit(1)).scalar_one_or_none()
    if not prev:
        return None
    prev_f = db.execute(select(Finding).where(Finding.scan_id == prev.id)).scalars().all()
    items = detect_drift(prev, prev_f, scan, cur_f)
    if not items:
        return None
    kinds = {i["kind"] for i in items}
    parts = [f"{sum(1 for i in items if i['kind'] == k)} {label}" for k, label in
             (("new_attack_path", "new attack path(s)"), ("secret_exposed", "newly exposed secret(s)"), ("new_finding", "new critical/high finding(s)"))
             if k in kinds]
    if "score_drop" in kinds:
        parts.append("score drop")
    alert = DriftAlert(organization_id=scan.organization_id, project_id=project.id, scan_id=scan.id, previous_scan_id=prev.id,
                       severity=items[0]["severity"], title=f"{project.name}: posture worsened - " + ", ".join(parts), items=items)
    db.add(alert)
    db.commit()
    notify(db, alert, project)
    from .siem import emit

    emit(alert.organization_id, "alert", {"id": alert.id, "project": project.name, "repository": project.repo_full_name,
                                          "scan_id": alert.scan_id, "severity": alert.severity, "title": alert.title, "items": alert.items})
    return alert
