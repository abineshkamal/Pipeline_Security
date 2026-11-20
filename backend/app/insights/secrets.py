"""Secret blast-radius map: for every secret, which pipelines and jobs can read it, who can start them, and whether
attacker-controlled code runs next to it.

Reachability follows GitHub's rules: fork pull requests (`pull_request`) do not receive secrets, but privileged
external triggers (pull_request_target, issue_comment, issues, workflow_run, discussion*) run in the base repository
with secrets, so outsiders can reach them.
"""
from __future__ import annotations

from datetime import datetime, timezone

from ..models import Finding

ROTATION_AGING_DAYS = 90
ROTATION_STALE_DAYS = 180

# Findings that put attacker-influenced code or data in a job that holds the secret.
EXPOSING_RULES = {"PT-PPE-001", "PT-PPE-003", "PT-PPE-004", "PT-PPE-005", "PT-CRED-002", "PT-CRED-003", "PT-3P-001", "PT-3P-004"}
MANUAL_TRIGGERS = {"schedule", "workflow_dispatch", "workflow_call", "repository_dispatch"}
REACH_RANK = {"outsiders": 3, "contributors": 2, "maintainers": 1}
LEVEL_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _reach(wf: dict) -> tuple[str, str]:
    priv = wf.get("privileged_triggers") or []
    trig = set(wf.get("triggers") or [])
    if priv:
        return "outsiders", f"{', '.join(priv)} runs with secrets on input from anyone"
    if trig and trig <= MANUAL_TRIGGERS:
        return "maintainers", "only scheduled, manual or called runs"
    return "contributors", "push / same-repository pull request / release"


def _parse(ts: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")) if ts else None
    except ValueError:
        return None


def rotation(name: str, environments: set[str], meta: dict, now: datetime | None = None) -> dict:
    """Last update of the secret GitHub would actually inject (environment > repository > organization)."""
    if name == "GITHUB_TOKEN":
        return {"status": "automatic", "detail": "short-lived token issued per job by GitHub"}
    if meta.get("status") != "ok":
        why = meta.get("detail") or meta.get("status") or "not collected"
        if meta.get("status") in ("forbidden", "error"):
            why += " - add a token with the Secrets: read permission"
        return {"status": "unknown", "detail": f"rotation date not available: {why}"}
    entries = [e for e in meta.get("secrets", []) if e.get("name", "").upper() == name.upper()]
    pick = (next((e for e in entries if e["scope"].startswith("environment:") and e["scope"].split(":", 1)[1] in environments), None)
            or next((e for e in entries if e["scope"] == "repository"), None)
            or next((e for e in entries if e["scope"] == "organization"), None))
    if not pick:
        return {"status": "missing", "detail": "referenced by a workflow but not defined in the repository, its environments or "
                                                "visible organization secrets (the step gets an empty value)"}
    updated = _parse(pick.get("updated_at")) or _parse(pick.get("created_at"))
    if not updated:
        return {"status": "unknown", "detail": "GitHub returned no date", "scope": pick["scope"]}
    age = ((now or datetime.now(timezone.utc)) - updated).days
    status = "stale" if age >= ROTATION_STALE_DAYS else "aging" if age >= ROTATION_AGING_DAYS else "ok"
    return {"status": status, "age_days": age, "updated_at": updated.isoformat(), "scope": pick["scope"],
            "detail": f"last updated {age} day(s) ago ({pick['scope']} secret)"}


def secret_exposure(scan, findings: list[Finding]) -> dict:
    inv = scan.inventory or {}
    wfs = {w["path"]: w for w in inv.get("workflows", [])}
    by_job: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        if f.rule_id in EXPOSING_RULES and f.job and f.triage_status != "false_positive":
            by_job.setdefault((f.file_path, f.job), []).append(f)
    paths = (scan.attack_graph or {}).get("paths", [])
    meta = inv.get("secret_metadata") or ({"status": "skipped", "detail": "offline (ZIP) assessment"} if inv.get("source") == "upload"
                                          else {"status": "unknown", "detail": "scan predates rotation tracking - re-scan"})

    out = []
    for name, refs in (inv.get("secrets") or {}).items():
        uses, pipelines = [], set()
        for ref in refs:
            path, _, job_id = ref.partition("#")
            wf = wfs.get(path)
            if not wf:
                continue
            job = next((j for j in wf.get("jobs") or [] if j["id"] == job_id), {})
            reach, why = _reach(wf)
            exp = by_job.get((path, job_id), [])
            supply = [f for f in exp if f.rule_id in ("PT-3P-001", "PT-3P-004") and f.severity not in ("low", "info")]
            code = [f for f in exp if f not in supply]
            env = job.get("environment") or ""
            if reach == "outsiders" and code:
                level = "critical"
            elif reach == "outsiders" or code or any(f.rule_id == "PT-3P-004" for f in supply):
                level = "high"
            elif supply or reach == "contributors":
                level = "medium"
            else:
                level = "low"
            if env and level in ("high", "medium"):  # environment secrets with protection rules gate the job
                level = {"high": "medium", "medium": "low"}[level]
            pipelines.add(path)
            uses.append({
                "workflow": path, "workflow_name": wf.get("name") or path, "job": job_id, "triggers": wf.get("triggers") or [],
                "reach": reach, "reach_reason": why, "environment": env, "self_hosted": bool(job.get("self_hosted")),
                "write_scopes": job.get("write_scopes") or [], "level": level,
                "exposing_findings": [{"id": f.id, "rule_id": f.rule_id, "title": f.title, "severity": f.severity, "line": f.line} for f in exp],
            })
        if not uses:
            continue
        node = f"secret:{name}"
        n_paths = sum(1 for p in paths if node in p.get("nodes", []))
        level = max((u["level"] for u in uses), key=lambda x: LEVEL_RANK[x])
        reach = max((u["reach"] for u in uses), key=lambda x: REACH_RANK[x])
        rot = rotation(name, {u["environment"] for u in uses if u["environment"]}, meta)
        out.append({"name": name, "level": level, "reach": reach, "pipelines": len(pipelines), "jobs": len(uses),
                    "attack_paths": n_paths, "rotation": rot,
                    "rotate_first": rot["status"] in ("stale", "aging") and level in ("critical", "high"),
                    "uses": sorted(uses, key=lambda u: -LEVEL_RANK[u["level"]])})
    out.sort(key=lambda s: (-LEVEL_RANK[s["level"]], -REACH_RANK[s["reach"]], -s["attack_paths"], -s["jobs"], s["name"]))
    counts = {k: sum(1 for s in out if s["level"] == k) for k in LEVEL_RANK}
    rot_counts = {k: sum(1 for s in out if s["rotation"]["status"] == k) for k in ("stale", "aging", "ok", "missing", "unknown")}
    return {"secrets": out, "counts": counts, "outsider_reachable": sum(1 for s in out if s["reach"] == "outsiders"),
            "rotation": {"status": meta.get("status"), "detail": meta.get("detail", ""), "counts": rot_counts,
                         "aging_days": ROTATION_AGING_DAYS, "stale_days": ROTATION_STALE_DAYS,
                         "rotate_first": [s["name"] for s in out if s["rotate_first"]]}}
