"""Open Jira / ServiceNow tickets from findings and close them automatically when a re-scan shows the fix.

Tickets follow the finding fingerprint, so a ticket survives re-scans and line moves. When a completed scan of the
project no longer contains the fingerprint, the ticket gets a comment (Jira) / work note (ServiceNow) and, if a close
action is configured, is transitioned / closed.
"""
from __future__ import annotations

import logging

import httpx
from sqlalchemy import select

from ..config import get_settings
from ..models import Finding, Project, Scan, TicketIntegration, TicketLink, utcnow
from ..security import decrypt_secret
from .monitoring import validate_webhook_url

log = logging.getLogger("pipelinetrust.tickets")
SN_URGENCY = {"critical": "1", "high": "1", "medium": "2", "low": "3", "info": "3"}
JIRA_PRIORITY = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low", "info": "Lowest"}


class TicketError(Exception):
    pass


def request(method: str, url: str, auth: tuple[str, str], body: dict | None = None) -> tuple[int, dict]:
    """Single HTTP call (patched in tests). HTTPS only, no redirects, no private addresses unless allowed."""
    validate_webhook_url(url)
    with httpx.Client(timeout=20, follow_redirects=False) as c:
        r = c.request(method, url, json=body, auth=auth, headers={"Accept": "application/json", "User-Agent": "PipelineTrust-Tickets"})
    try:
        data = r.json() if r.content else {}
    except ValueError:
        data = {}
    return r.status_code, data if isinstance(data, dict) else {"items": data}


def _auth(it: TicketIntegration) -> tuple[str, str]:
    return it.username, decrypt_secret(it.secret_encrypted)


def _base(it: TicketIntegration) -> str:
    return it.base_url.rstrip("/")


def _link(path: str) -> str:
    b = get_settings().public_url.rstrip("/")
    return f"{b}{path}" if b else ""


def describe(f: Finding, project: Project, scan: Scan) -> tuple[str, str]:
    loc = f"{f.file_path}:{f.line}" if f.file_path and f.line else f.file_path or "repository settings"
    summary = f"[PipelineTrust] {f.severity.upper()} {f.rule_id}: {f.title} ({project.name})"[:250]
    url = _link(f"/scan?id={scan.id}&finding={f.id}")
    body = "\n".join(x for x in [
        f"Project: {project.name}" + (f" ({project.repo_full_name})" if project.repo_full_name else ""),
        f"Rule: {f.rule_id} - {f.title} ({f.category})", f"Severity: {f.severity} · risk {f.risk_score}", f"Location: {loc}" + (f" · job {f.job}" if f.job else ""),
        "", f.message, "", ("Evidence:\n" + f.snippet[:1500]) if f.snippet else "",
        f"Finding fingerprint: {f.fingerprint} (this ticket is closed automatically when a scan no longer finds it)",
        f"Open in PipelineTrust: {url}" if url else ""] if x is not None)
    return summary, body


def create_ticket(it: TicketIntegration, f: Finding, project: Project, scan: Scan) -> dict:
    summary, body = describe(f, project, scan)
    if it.kind == "jira":
        fields = {"project": {"key": it.target}, "summary": summary, "description": body, "issuetype": {"name": it.issue_type or "Bug"},
                  "labels": ["pipelinetrust", f.rule_id.lower()]}
        code, data = request("POST", f"{_base(it)}/rest/api/2/issue", _auth(it), {"fields": fields})
        if code not in (200, 201) or "key" not in data:
            raise TicketError(f"Jira HTTP {code}: {str(data.get('errors') or data.get('errorMessages') or data)[:200]}")
        return {"key": data["key"], "external_id": str(data.get("id", "")), "url": f"{_base(it)}/browse/{data['key']}"}
    rec = {"short_description": summary, "description": body, "urgency": SN_URGENCY.get(f.severity, "2"), "impact": SN_URGENCY.get(f.severity, "2"),
           "category": "security"}
    code, data = request("POST", f"{_base(it)}/api/now/table/{it.target}", _auth(it), rec)
    res = data.get("result") or {}
    if code not in (200, 201) or not res.get("sys_id"):
        raise TicketError(f"ServiceNow HTTP {code}: {str(data.get('error') or data)[:200]}")
    return {"key": res.get("number") or res["sys_id"], "external_id": res["sys_id"],
            "url": f"{_base(it)}/nav_to.do?uri={it.target}.do?sys_id={res['sys_id']}"}


def resolve_ticket(it: TicketIntegration, link: TicketLink, scan: Scan) -> str:
    note = f"PipelineTrust scan {scan.id} ({scan.commit_sha[:10] or 'latest'}) no longer finds this issue - it appears fixed."
    if it.kind == "jira":
        code, _ = request("POST", f"{_base(it)}/rest/api/2/issue/{link.key}/comment", _auth(it), {"body": note})
        detail = f"comment HTTP {code}"
        if it.close_action:
            c2, data = request("GET", f"{_base(it)}/rest/api/2/issue/{link.key}/transitions", _auth(it))
            tr = next((t for t in data.get("transitions", []) if t.get("name", "").lower() == it.close_action.lower()), None)
            if tr:
                c3, _ = request("POST", f"{_base(it)}/rest/api/2/issue/{link.key}/transitions", _auth(it), {"transition": {"id": tr["id"]}})
                detail += f"; transition '{tr['name']}' HTTP {c3}"
            else:
                detail += f"; transition '{it.close_action}' not available (HTTP {c2})"
        return detail
    body = {"work_notes": note}
    if it.close_action:
        body.update(state=it.close_action, close_notes=note, close_code="Solved (Permanently)")
    code, _ = request("PATCH", f"{_base(it)}/api/now/table/{it.target}/{link.external_id}", _auth(it), body)
    return f"update HTTP {code}"


def test_integration(it: TicketIntegration) -> dict:
    try:
        if it.kind == "jira":
            code, data = request("GET", f"{_base(it)}/rest/api/2/myself", _auth(it))
            who = data.get("emailAddress") or data.get("displayName") or ""
            if code == 200:
                c2, _ = request("GET", f"{_base(it)}/rest/api/2/project/{it.target}", _auth(it))
                return {"ok": c2 == 200, "detail": f"signed in as {who}; project {it.target}: HTTP {c2}"}
        else:
            code, _ = request("GET", f"{_base(it)}/api/now/table/{it.target}?sysparm_limit=1", _auth(it))
            if code == 200:
                return {"ok": True, "detail": f"table {it.target} readable"}
        return {"ok": False, "detail": f"HTTP {code}"}
    except (httpx.HTTPError, ValueError) as exc:
        return {"ok": False, "detail": f"{type(exc).__name__}: {exc}"[:200]}


def link_out(link: TicketLink) -> dict:
    return {"id": link.id, "project_id": link.project_id, "fingerprint": link.fingerprint, "rule_id": link.rule_id, "title": link.title,
            "system": link.system, "key": link.key, "url": link.url, "status": link.status, "created_by": link.created_by_email,
            "created_at": link.created_at.isoformat(), "resolved_at": link.resolved_at.isoformat() if link.resolved_at else None,
            "sync_detail": link.sync_detail}


def mark_findings(findings: list[Finding], links: list[TicketLink]) -> None:
    by_fp = {lk.fingerprint: lk for lk in links}
    for f in findings:
        lk = by_fp.get(f.fingerprint)
        if lk:
            f.extra = {**(f.extra or {}), "ticket": {"key": lk.key, "url": lk.url, "system": lk.system, "status": lk.status}}


def sync_after_scan(db, scan: Scan) -> dict:
    """Tag findings with their ticket; close tickets whose finding disappeared."""
    links = db.execute(select(TicketLink).where(TicketLink.project_id == scan.project_id)).scalars().all()
    if not links or scan.ref_override:  # never close tickets because an old release does not have the finding
        return {"resolved": 0}
    fs = db.execute(select(Finding).where(Finding.scan_id == scan.id)).scalars().all()
    present = {f.fingerprint for f in fs}
    resolved = 0
    for lk in links:
        if lk.status == "open" and lk.fingerprint not in present:
            it = db.get(TicketIntegration, lk.integration_id) if lk.integration_id else None
            try:
                lk.sync_detail = resolve_ticket(it, lk, scan)[:300] if it and it.enabled else "integration removed or disabled - not updated"
            except (httpx.HTTPError, ValueError, TicketError) as exc:
                lk.sync_detail = f"{type(exc).__name__}: {exc}"[:300]
            lk.status, lk.resolved_at, lk.resolved_scan_id = "resolved", utcnow(), scan.id
            resolved += 1
        elif lk.status == "resolved" and lk.fingerprint in present:
            lk.status, lk.sync_detail = "open", f"finding reappeared in scan {scan.id}"  # regression: reopen the link
    mark_findings(fs, links)
    db.commit()
    return {"resolved": resolved}
