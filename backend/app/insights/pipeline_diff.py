"""What changed in the build chain between two scans of a project (typically two releases / tags / commits).

Compares the pipeline inventory, not just findings: workflows, triggers, job permissions, secrets, runners,
environments and third-party actions, plus attack paths and findings. Every change is classified as a risk
increase, a decrease or neutral so a release review can focus on what got worse.
"""
from __future__ import annotations

from ..models import Finding, Scan

PRIVILEGED = {"pull_request_target", "workflow_run", "issue_comment", "issues", "discussion", "discussion_comment"}


def _wf_map(scan: Scan) -> dict[str, dict]:
    return {w["path"]: w for w in (scan.inventory or {}).get("workflows", [])}


def _jobs(wf: dict) -> dict[str, dict]:
    return {j["id"]: j for j in wf.get("jobs") or []}


def _actions(scan: Scan) -> dict[str, dict]:
    """action slug (owner/repo[/path]) -> {refs, sha_pinned, workflows}"""
    out: dict[str, dict] = {}
    for a in (scan.inventory or {}).get("actions", []):
        key = a.get("action") or a["uses"].split("@")[0]
        e = out.setdefault(key, {"refs": set(), "pinned": True, "workflows": set(), "first_party": a.get("first_party")})
        e["refs"].add(a.get("ref") or "")
        e["pinned"] = e["pinned"] and bool(a.get("sha_pinned"))
        e["workflows"].update(a.get("workflows") or [])
    return out


def _change(kind: str, risk: str, text: str, workflow: str = "", **extra) -> dict:
    return {"kind": kind, "risk": risk, "text": text, "workflow": workflow, **extra}


def diff_pipelines(old: Scan, old_f: list[Finding], new: Scan, new_f: list[Finding]) -> dict:
    changes: list[dict] = []
    wo, wn = _wf_map(old), _wf_map(new)
    for p in sorted(wn.keys() - wo.keys()):
        w = wn[p]
        priv = set(w.get("privileged_triggers") or [])
        changes.append(_change("workflow_added", "increase" if priv else "neutral",
                               f"New pipeline {w.get('name') or p} (triggers: {', '.join(w.get('triggers') or []) or 'none'})", p))
    for p in sorted(wo.keys() - wn.keys()):
        changes.append(_change("workflow_removed", "decrease", f"Pipeline {wo[p].get('name') or p} removed", p))
    for p in sorted(wo.keys() & wn.keys()):
        a, b = wo[p], wn[p]
        ta, tb = set(a.get("triggers") or []), set(b.get("triggers") or [])
        for t in sorted(tb - ta):
            changes.append(_change("trigger_added", "increase" if t in PRIVILEGED or t in (b.get("external_triggers") or []) else "neutral",
                                   f"Trigger {t} added", p))
        for t in sorted(ta - tb):
            changes.append(_change("trigger_removed", "decrease" if t in PRIVILEGED else "neutral", f"Trigger {t} removed", p))
        if a.get("permissions") != b.get("permissions"):
            changes.append(_change("workflow_permissions", "neutral", f"Workflow-level permissions changed: {a.get('permissions')!r} → {b.get('permissions')!r}", p))
        ja, jb = _jobs(a), _jobs(b)
        for j in sorted(jb.keys() - ja.keys()):
            x = jb[j]
            risky = x.get("self_hosted") or x.get("secrets") or (x.get("write_scopes") or [])
            changes.append(_change("job_added", "increase" if risky else "neutral",
                                   f"New job {j}" + (f" with secrets {', '.join(x['secrets'])}" if x.get("secrets") else "")
                                   + (f", write scopes {', '.join(x['write_scopes'])}" if x.get("write_scopes") else "")
                                   + (" on a self-hosted runner" if x.get("self_hosted") else ""), p, job=j))
        for j in sorted(ja.keys() - jb.keys()):
            changes.append(_change("job_removed", "decrease" if ja[j].get("secrets") or ja[j].get("write_scopes") else "neutral", f"Job {j} removed", p, job=j))
        for j in sorted(ja.keys() & jb.keys()):
            x, y = ja[j], jb[j]
            wa, wb = x.get("write_scopes"), y.get("write_scopes")
            if wa is None and wb is not None:
                changes.append(_change("permissions", "decrease", f"Job {j}: explicit permissions added (write: {', '.join(wb) or 'none'})", p, job=j))
            elif wa is not None and wb is None:
                changes.append(_change("permissions", "increase", f"Job {j}: explicit permissions removed (falls back to the repository default)", p, job=j))
            elif wa is not None and wb is not None:
                for s in sorted(set(wb) - set(wa)):
                    changes.append(_change("permissions", "increase", f"Job {j}: write permission {s} added", p, job=j))
                for s in sorted(set(wa) - set(wb)):
                    changes.append(_change("permissions", "decrease", f"Job {j}: write permission {s} removed", p, job=j))
            for s in sorted(set(y.get("secrets") or []) - set(x.get("secrets") or [])):
                changes.append(_change("secret_added", "increase", f"Job {j} now reads secret {s}", p, job=j, secret=s))
            for s in sorted(set(x.get("secrets") or []) - set(y.get("secrets") or [])):
                changes.append(_change("secret_removed", "decrease", f"Job {j} no longer reads secret {s}", p, job=j, secret=s))
            if bool(x.get("self_hosted")) != bool(y.get("self_hosted")):
                changes.append(_change("runner", "increase" if y.get("self_hosted") else "decrease",
                                       f"Job {j} moved {'to a self-hosted' if y.get('self_hosted') else 'off a self-hosted'} runner ({', '.join(y.get('runs_on') or [])})", p, job=j))
            if (x.get("environment") or "") != (y.get("environment") or ""):
                changes.append(_change("environment", "decrease" if y.get("environment") and not x.get("environment") else
                                       "increase" if x.get("environment") and not y.get("environment") else "neutral",
                                       f"Job {j} environment: {x.get('environment') or 'none'} → {y.get('environment') or 'none'}", p, job=j))

    ao, an = _actions(old), _actions(new)
    for k in sorted(an.keys() - ao.keys()):
        e = an[k]
        changes.append(_change("action_added", "neutral" if e["pinned"] or e["first_party"] else "increase",
                               f"New third-party action {k}@{', '.join(sorted(e['refs']))}" + ("" if e["pinned"] else " (not pinned to a commit)"),
                               ", ".join(sorted(e["workflows"])), action=k))
    for k in sorted(ao.keys() - an.keys()):
        changes.append(_change("action_removed", "decrease", f"Action {k} no longer used", action=k))
    for k in sorted(ao.keys() & an.keys()):
        a, b = ao[k], an[k]
        if a["refs"] != b["refs"]:
            risk = "increase" if a["pinned"] and not b["pinned"] else "decrease" if b["pinned"] and not a["pinned"] else "neutral"
            changes.append(_change("action_ref", risk, f"{k}: {', '.join(sorted(a['refs']))} → {', '.join(sorted(b['refs']))}"
                                   + (" (pin removed)" if risk == "increase" else " (now pinned)" if risk == "decrease" else ""), action=k))

    po = {tuple(p["nodes"]): p for p in (old.attack_graph or {}).get("paths", [])}
    pn = {tuple(p["nodes"]): p for p in (new.attack_graph or {}).get("paths", [])}
    brief_p = lambda p: {"id": p.get("id"), "risk": p.get("risk"), "labels": p.get("labels"), "impact": p.get("impact")}  # noqa: E731
    fo = {f.fingerprint: f for f in old_f if f.triage_status != "false_positive"}
    fn = {f.fingerprint: f for f in new_f if f.triage_status != "false_positive"}
    brief_f = lambda f: {"id": f.id, "rule_id": f.rule_id, "title": f.title, "severity": f.severity,  # noqa: E731
                         "file_path": f.file_path, "line": f.line}
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    new_findings = sorted((brief_f(fn[k]) for k in fn.keys() - fo.keys()), key=lambda x: sev.get(x["severity"], 9))
    fixed = sorted((brief_f(fo[k]) for k in fo.keys() - fn.keys()), key=lambda x: sev.get(x["severity"], 9))
    order = {"increase": 0, "decrease": 1, "neutral": 2}
    changes.sort(key=lambda c: (order[c["risk"]], c["workflow"], c["kind"]))

    def meta(s: Scan) -> dict:
        return {"id": s.id, "ref": (s.options or {}).get("ref") or "", "commit_sha": s.commit_sha, "created_at": s.created_at.isoformat(),
                "posture_score": s.posture_score, "grade": (s.summary or {}).get("grade"), "workflows": len(_wf_map(s)),
                "attack_paths": len((s.attack_graph or {}).get("paths", []))}
    return {
        "from": meta(old), "to": meta(new),
        "score_delta": round((new.posture_score or 0) - (old.posture_score or 0), 1) if None not in (old.posture_score, new.posture_score) else None,
        "counts": {"increase": sum(1 for c in changes if c["risk"] == "increase"), "decrease": sum(1 for c in changes if c["risk"] == "decrease"),
                   "neutral": sum(1 for c in changes if c["risk"] == "neutral"), "new_findings": len(new_findings), "fixed_findings": len(fixed),
                   "new_paths": len(pn.keys() - po.keys()), "removed_paths": len(po.keys() - pn.keys())},
        "changes": changes,
        "new_attack_paths": [brief_p(pn[k]) for k in pn.keys() - po.keys()],
        "removed_attack_paths": [brief_p(po[k]) for k in po.keys() - pn.keys()],
        "new_findings": new_findings[:300], "fixed_findings": fixed[:300],
    }
