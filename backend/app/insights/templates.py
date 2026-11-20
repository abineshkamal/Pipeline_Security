"""Golden pipeline templates: an approved workflow that repositories should *call* (reusable workflow) instead of
copying. Every project's latest scan is classified per workflow as:

  adopted            calls the template (at an approved ref, if refs are restricted)
  unapproved_ref     calls the template at a ref that is not approved
  copy               an identical copy of the template's steps (should call it instead - copies stop receiving fixes)
  drifted_copy       a modified copy (>= 50% of steps in common): lists missing and extra steps
  not_adopted        matches the template's `applies_to` pattern but neither calls nor copies it
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter

from ..scanner.model import parse_workflow

SIMILAR = 0.5


def _sig(step) -> tuple[str, str]:
    if step.uses:
        target = step.uses.split("@", 1)[0].lower()
        return f"uses:{target}", f"uses {target}"
    run = re.sub(r"\s+", " ", step.run or "").strip()
    return "run:" + hashlib.sha1(run.encode()).hexdigest()[:12], "run: " + (run[:60] + ("…" if len(run) > 60 else ""))


def signature(text: str, path: str) -> tuple[Counter, dict[str, str], bool]:
    wf = parse_workflow(path, text)
    sigs: Counter = Counter()
    labels: dict[str, str] = {}
    for job in wf.jobs:
        for st in job.steps:
            k, lbl = _sig(st)
            sigs[k] += 1
            labels[k] = lbl
    callable_ = "workflow_call" in (wf.triggers or [])
    return sigs, labels, callable_


def similarity(a: Counter, b: Counter) -> float:
    inter = sum((a & b).values())
    union = sum((a | b).values())
    return inter / union if union else 0.0


def evaluate(template: dict, tpl_text: str, projects: list[dict]) -> dict:
    """template: {name, repo, workflow_path, applies_to, approved_refs}; projects: [{project, scan, sources}]"""
    tsig, tlabels, callable_ = signature(tpl_text, template["workflow_path"])
    ref_target = f"{template['repo']}/{template['workflow_path']}".lower() if template.get("repo") else None
    approved = [r.lower() for r in template.get("approved_refs") or []]
    rx = re.compile(template["applies_to"], re.I) if template.get("applies_to") else None
    rows = []
    for pr in projects:
        p, scan, sources = pr["project"], pr["scan"], pr["sources"] or {}
        inv_wfs = {w["path"]: w for w in (scan.inventory or {}).get("workflows", [])}
        for path, w in inv_wfs.items():
            if p.id == template["source_project_id"] and path == template["workflow_path"]:
                continue
            calls = [j.get("reusable") for j in w.get("jobs") or [] if j.get("reusable")]
            hit = next((c for c in calls if ref_target and c.lower().split("@", 1)[0] == ref_target), None)
            row = {"project_id": p.id, "project": p.name, "scan_id": scan.id, "workflow": path, "workflow_name": w.get("name") or path}
            if hit:
                ref = hit.split("@", 1)[1] if "@" in hit else ""
                ok = not approved or ref.lower() in approved
                rows.append({**row, "status": "adopted" if ok else "unapproved_ref", "ref": ref,
                             "detail": f"calls the template at @{ref}" + ("" if ok else f" (approved: {', '.join(template['approved_refs'])})")})
                continue
            text = sources.get(path)
            if text is None:
                if rx and (rx.search(path) or rx.search(w.get("name") or "")):
                    rows.append({**row, "status": "not_adopted", "detail": "matches applies_to; workflow source not stored (re-scan to compare)"})
                continue
            sig, labels, _ = signature(text, path)
            sim = similarity(tsig, sig)
            if sim >= 0.999:
                rows.append({**row, "status": "copy", "similarity": round(sim, 2),
                             "detail": "identical copy of the template's steps" + ("; call it with `uses:` instead" if callable_ else "")})
            elif sim >= SIMILAR:
                missing = [tlabels[k] for k in (tsig - sig)]
                extra = [labels[k] for k in (sig - tsig)]
                rows.append({**row, "status": "drifted_copy", "similarity": round(sim, 2), "missing_steps": missing[:20], "extra_steps": extra[:20],
                             "detail": f"{round(sim * 100)}% of steps in common; {len(missing)} template step(s) missing, {len(extra)} extra"})
            elif rx and (rx.search(path) or rx.search(w.get("name") or "")):
                rows.append({**row, "status": "not_adopted", "similarity": round(sim, 2), "detail": "matches applies_to but does not call or copy the template"})
    order = {"unapproved_ref": 0, "drifted_copy": 1, "not_adopted": 2, "copy": 3, "adopted": 4}
    rows.sort(key=lambda r: (order[r["status"]], r["project"], r["workflow"]))
    return {"callable": callable_, "reusable_ref": ref_target, "steps": sum(tsig.values()), "rows": rows,
            "counts": {k: sum(1 for r in rows if r["status"] == k) for k in order}}
