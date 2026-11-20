"""Attacker walkthrough for one attack path: what an attacker does at each step, the evidence that makes the step
possible, and the smallest fix that breaks the chain (computed with the what-if simulator, not guessed).

Everything comes from the attack graph and its findings; no step is invented.
"""
from __future__ import annotations

from ..models import Finding
from .whatif import simulate

ACTOR_ACTION = {
    "actor:external": "opens a pull request from a fork, an issue or a comment - no write access needed",
    "actor:insider": "pushes a branch or opens a same-repository pull request",
    "actor:supply": "publishes a malicious version of an action this pipeline uses (or takes over its tag)",
}
CAP_TEXT = [  # (substring of the capability node id, what the attacker gains, the defence at this step)
    ("secret", "reads the secret from the job environment and sends it out", "move the secret to a protected environment with required reviewers; use OIDC instead of static credentials"),
    ("token-default", "uses the job's GITHUB_TOKEN, which has the repository default (write) permissions", "add `permissions: contents: read` at the workflow level and grant writes per job"),
    ("token", "uses the job's write-scoped GITHUB_TOKEN", "narrow the job's `permissions:` to what it needs"),
    ("oidc", "requests an OIDC token and exchanges it for cloud credentials", "restrict the cloud trust policy to the protected branch / environment subject"),
    ("runner", "runs on a self-hosted runner and can persist on it or reach the internal network", "use ephemeral, isolated runners and never let fork pull requests reach self-hosted runners"),
    ("deploy", "runs the deployment step with attacker-controlled code", "gate deployments with a protected environment and required reviewers"),
    ("cache", "poisons the build cache used by later privileged runs", "do not share caches between untrusted and privileged workflows"),
]
TRIGGER_DEFENCE = ("avoid privileged triggers (`pull_request_target`, `workflow_run`, `issue_comment`) for untrusted input, or never check out "
                   "or interpolate untrusted code in them")


def _cap(node: str) -> tuple[str, str]:
    for key, gain, fix in CAP_TEXT:
        if key in node:
            return gain, fix
    return "gains this capability", "remove the capability from the job"


def _brief(f: Finding) -> dict:
    return {"id": f.id, "rule_id": f.rule_id, "title": f.title, "severity": f.severity, "file_path": f.file_path, "line": f.line, "job": f.job}


def walkthrough(scan, findings: list[Finding], path_id: str, fixable_rules: set[str]) -> dict | None:
    graph = scan.attack_graph or {}
    path = next((p for p in graph.get("paths", []) if p.get("id") == path_id), None)
    if not path:
        return None
    nodes = {n["id"]: n for n in graph.get("nodes", [])}
    edges = {(e["source"], e["target"]): e for e in graph.get("edges", [])}
    by_id = {f.id: f for f in findings}
    steps, sentences = [], []
    seq = path["nodes"]
    for i, nid in enumerate(seq):
        n = nodes.get(nid, {"id": nid, "type": nid.split(":")[0], "label": path["labels"][i] if i < len(path.get("labels", [])) else nid})
        e = edges.get((seq[i - 1], nid)) if i else None
        ev = [_brief(by_id[x]) for x in (e or {}).get("finding_ids", []) if x in by_id]
        t = n.get("type")
        if t == "actor":
            action, defence = f"{n['label']} {ACTOR_ACTION.get(nid, '')}".strip(), "restrict who can trigger privileged workflows"
        elif t == "trigger":
            action, defence = f"which starts {n['label']}", TRIGGER_DEFENCE
        elif t == "job":
            action = f"their code or input executes in job {n['label']}" + (f" ({e['label']})" if e and e.get("label") else "")
            defence = "fix the evidence below so untrusted code or input never runs in this job"
        elif t == "capability":
            gain, defence = _cap(nid)
            action = f"the job {gain}: {n['label']}"
        else:
            action, defence = f"outcome: {n['label']}", ""
        if e and e.get("gated"):
            defence = (defence + "; " if defence else "") + f"partly gated by {', '.join(e['gated']) if isinstance(e['gated'], list) else 'an environment'}"
        steps.append({"step": i + 1, "node": nid, "type": t, "label": n["label"], "action": action, "defence": defence, "evidence": ev})
        sentences.append(action)
    story = "1. " + sentences[0][0].upper() + sentences[0][1:] + "".join(f" {k + 2}. {s[0].upper() + s[1:]}" for k, s in enumerate(sentences[1:])) if sentences else ""

    base_ids = [x for x in path.get("finding_ids", []) if x in by_id]
    breakers = []
    for fid in base_ids:
        sim = simulate(scan, findings, {fid})
        if path_id in sim["removed_paths"]:
            f = by_id[fid]
            breakers.append({**_brief(f), "paths_removed": len(sim["removed_paths"]), "score_gain": sim["score_delta"],
                             "auto_fixable": f.rule_id in fixable_rules})
    breakers.sort(key=lambda b: (-b["paths_removed"], -(b["score_gain"] or 0), not b["auto_fixable"]))
    step_fixes = []  # when no single finding breaks the path: fix every finding behind one step
    for st in steps:
        ids = [e["id"] for e in st["evidence"]]
        if len(ids) < 2:
            continue
        sim = simulate(scan, findings, set(ids))
        if path_id in sim["removed_paths"]:
            rules = sorted({e["rule_id"] for e in st["evidence"]})
            step_fixes.append({"step": st["step"], "finding_ids": ids, "rule_ids": rules, "findings": len(ids),
                               "paths_removed": len(sim["removed_paths"]), "score_gain": sim["score_delta"],
                               "auto_fixable": all(r in fixable_rules for r in rules)})
    step_fixes.sort(key=lambda b: (b["findings"], -b["paths_removed"]))
    all_fix = simulate(scan, findings, set(base_ids)) if base_ids else None
    return {
        "path": {"id": path_id, "risk": path.get("risk"), "impact": path.get("impact"), "actor": path.get("actor"), "labels": path.get("labels"),
                 "gated_by": path.get("gated_by", []), "length": path.get("length")},
        "story": story, "steps": steps, "breakers": breakers[:10], "step_fixes": step_fixes[:5],
        "fix_all": {"finding_ids": base_ids, "paths_removed": len(all_fix["removed_paths"]) if all_fix else 0,
                    "score_gain": all_fix["score_delta"] if all_fix else None},
        "note": ("Any one fix below removes this path; the top one also removes the most other paths." if breakers else
                 "No single finding breaks this path, but fixing every finding behind one step does." if step_fixes else
                 "No single finding or step breaks this path on its own; fix the evidence of several steps together."),
    }
