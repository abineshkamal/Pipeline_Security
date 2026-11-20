"""Runtime evidence from GitHub: what actually ran (workflow run history) and which self-hosted runners exist.

Static findings say what *could* happen. Run history shows what *did*: privileged workflows that were really started
from forks or by first-time contributors, dormant pipelines that still hold secrets, and how often each pipeline runs.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from ..connectors.github import GitHubClient
from .secrets import EXPOSING_RULES

PRIVILEGED = {"pull_request_target", "workflow_run", "issue_comment", "issues", "discussion", "discussion_comment"}
OUTSIDE_ASSOC = {"FIRST_TIME_CONTRIBUTOR", "FIRST_TIMER", "NONE", "CONTRIBUTOR"}
DORMANT_DAYS = 90


def _ts(s: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None
    except ValueError:
        return None


def run_evidence(gh: GitHubClient, repo: str, inventory: dict, findings: list, max_runs: int = 300) -> dict:
    runs, page, err = [], 1, ""
    while len(runs) < max_runs:
        r = gh.result(f"/repos/{repo}/actions/runs", per_page=100, page=page)
        if r.status != "ok":
            err = r.detail or r.status
            break
        batch = r.data.get("workflow_runs", [])
        runs.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    if err and not runs:
        return {"status": "error", "detail": err, "workflows": [], "observed": []}
    now = datetime.now(timezone.utc)
    by_path: dict[str, list[dict]] = {}
    for x in runs:
        by_path.setdefault(x.get("path", "").split("@")[0], []).append(x)
    risky_wf: dict[str, set[str]] = {}
    for f in findings:
        if f.rule_id in EXPOSING_RULES and f.triage_status != "false_positive":
            risky_wf.setdefault(f.file_path, set()).add(f.rule_id)
    out, observed = [], []
    oldest = min((_ts(x.get("created_at")) for x in runs if x.get("created_at")), default=None)
    for wf in inventory.get("workflows", []):
        p = wf["path"]
        rs = by_path.get(p, [])
        events = Counter(x.get("event") for x in rs)
        fork = [x for x in rs if (x.get("head_repository") or {}).get("full_name") not in (None, repo)]
        priv_fork = [x for x in fork if x.get("event") in PRIVILEGED]
        outsiders = [x for x in rs if x.get("event") in PRIVILEGED and (x.get("author_association") or "").upper() in OUTSIDE_ASSOC]
        last = max((_ts(x.get("created_at")) for x in rs), default=None)
        holds_secrets = any(j.get("secrets") for j in wf.get("jobs") or [])
        has_priv = bool(wf.get("privileged_triggers"))
        entry = {
            "workflow": p, "name": wf.get("name") or p, "runs": len(rs), "events": dict(events.most_common()),
            "last_run": last.isoformat() if last else None, "days_since_last_run": (now - last).days if last else None,
            "fork_runs": len(fork), "privileged_fork_runs": len(priv_fork), "outsider_privileged_runs": len(outsiders),
            "failure_rate": round(sum(1 for x in rs if x.get("conclusion") == "failure") / len(rs), 2) if rs else None,
            "holds_secrets": holds_secrets, "privileged_triggers": wf.get("privileged_triggers") or [],
            "examples": [{"url": x.get("html_url"), "event": x.get("event"), "actor": (x.get("actor") or {}).get("login"),
                          "head": (x.get("head_repository") or {}).get("full_name"), "created_at": x.get("created_at")} for x in (priv_fork or outsiders)[:5]],
        }
        entry["outsider_privileged_runs"] = len({x.get("id") for x in priv_fork + outsiders})
        flags = []
        if (priv_fork or outsiders) and has_priv:
            flags.append("observed_untrusted_trigger")
            if p in risky_wf:
                n = len({x.get("id") for x in priv_fork + outsiders})
                observed.append({"workflow": p, "name": entry["name"], "runs": n, "rules": sorted(risky_wf[p]),
                                 "text": f"{entry['name']} ran {n} time(s) on a privileged trigger ({', '.join(entry['privileged_triggers'])}) started from a fork "
                                         f"or by a non-member, and has findings {', '.join(sorted(risky_wf[p]))} in the same file: "
                                         "the attack path is reachable in practice, not just in theory."})
        if holds_secrets and (last is None or (now - last).days >= DORMANT_DAYS) and oldest and (now - oldest).days >= DORMANT_DAYS:
            flags.append("dormant_with_secrets")
        if not rs and oldest:
            flags.append("no_runs_in_window")
        entry["flags"] = flags
        out.append(entry)
    out.sort(key=lambda e: (-len(e["flags"]), -e["outsider_privileged_runs"], -e["runs"]))
    return {"status": "ok" if not err else "partial", "detail": err, "runs_analysed": len(runs),
            "window": {"from": oldest.isoformat() if oldest else None, "to": now.isoformat()},
            "dormant_days": DORMANT_DAYS, "workflows": out, "observed": observed,
            "counts": {"observed_untrusted_trigger": sum(1 for e in out if "observed_untrusted_trigger" in e["flags"]),
                       "dormant_with_secrets": sum(1 for e in out if "dormant_with_secrets" in e["flags"])}}


def runner_inventory(gh: GitHubClient, repo: str, inventory: dict, public: bool | None) -> dict:
    """Self-hosted runners and runner groups (needs Administration: read on the repo, org admin for org runners),
    cross-referenced with the jobs that target self-hosted labels."""
    owner = repo.split("/")[0]
    repo_r = gh.result(f"/repos/{repo}/actions/runners", per_page=100)
    org_r = gh.result(f"/orgs/{owner}/actions/runners", per_page=100, none_on_404=True)
    groups_r = gh.result(f"/orgs/{owner}/actions/runner-groups", per_page=100, none_on_404=True)
    runners = []
    for scope, r in (("repository", repo_r), ("organization", org_r)):
        if r.status == "ok":
            for x in r.data.get("runners", []):
                runners.append({"name": x.get("name"), "scope": scope, "os": x.get("os"), "status": x.get("status"), "busy": x.get("busy"),
                                "labels": [lbl.get("name") for lbl in x.get("labels", [])], "ephemeral": x.get("ephemeral")})
    groups = []
    if groups_r.status == "ok":
        for g in groups_r.data.get("runner_groups", []):
            groups.append({"name": g.get("name"), "visibility": g.get("visibility"), "allows_public_repositories": g.get("allows_public_repositories"),
                           "restricted_to_workflows": g.get("restricted_to_workflows"), "default": g.get("default")})
    wfs = {w["path"]: w for w in inventory.get("workflows", [])}
    jobs = []
    for w in wfs.values():
        fork_reachable = public is not False and any(t in (w.get("triggers") or []) for t in ("pull_request", "pull_request_target", "issue_comment", "workflow_run"))
        for j in w.get("jobs") or []:
            if not j.get("self_hosted"):
                continue
            labels = [str(x) for x in (j.get("runs_on") or [])]
            match = [r["name"] for r in runners if set(lb.lower() for lb in labels) <= set(lb.lower() for lb in r["labels"])]
            jobs.append({"workflow": w["path"], "workflow_name": w.get("name") or w["path"], "job": j["id"], "labels": labels,
                         "fork_reachable": fork_reachable, "secrets": j.get("secrets") or [], "matching_runners": match})
    risks = []
    for j in jobs:
        if j["fork_reachable"]:
            risks.append({"severity": "critical" if public else "high", "text": f"{j['workflow_name']} / {j['job']} runs on self-hosted labels "
                          f"{', '.join(j['labels'])} and can be triggered by pull requests or comments - an outsider can run code on your runner."})
    for r in runners:
        if r.get("ephemeral") is False:
            risks.append({"severity": "medium", "text": f"Runner {r['name']} is persistent (not ephemeral): one malicious job can backdoor every later job."})
    for g in groups:
        if g.get("allows_public_repositories"):
            risks.append({"severity": "high", "text": f"Runner group {g['name']} allows public repositories to use its runners."})
        if g.get("visibility") == "all" and not g.get("restricted_to_workflows"):
            risks.append({"severity": "medium", "text": f"Runner group {g['name']} is available to every repository and every workflow."})
    access = {"repository_runners": repo_r.status, "organization_runners": org_r.status, "runner_groups": groups_r.status}
    return {"runners": runners, "groups": groups, "self_hosted_jobs": jobs, "risks": risks, "access": access,
            "note": "" if all(v in ("ok", "none") for v in access.values()) else
            "Some runner data needs a token with Administration: read (repository) or organization admin (org runners and groups); "
            "jobs targeting self-hosted labels are still listed from the workflow files."}
