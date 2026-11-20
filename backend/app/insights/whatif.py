"""What-if simulator: recompute posture score, controls and attack paths as if chosen findings were fixed.

Uses the same scoring function as the scan, so the "after" numbers are what a re-scan would report if the fixes
remove exactly those findings. Attack-path edges are evidence-backed: an edge disappears when every finding behind it
is fixed. Adding workflow `permissions:` (PT-PBAC-001) also removes that workflow's "holds default write token" edges.
"""
from __future__ import annotations

from types import SimpleNamespace

from ..models import Finding
from ..scanner.scoring import summarize


def _ns(f: Finding) -> SimpleNamespace:
    return SimpleNamespace(rule_id=f.rule_id, category=f.category, severity=f.severity, risk_score=f.risk_score)


def _removed_edges(graph: dict, fixed: set[str], fixed_pbac_workflows: set[str]) -> set[tuple[str, str]]:
    gone = set()
    for e in graph.get("edges", []):
        ids = set(e.get("finding_ids") or [])
        if ids and ids <= fixed:
            gone.add((e["source"], e["target"]))
        elif e["target"] == "cap:token-default" and any(e["source"].startswith(f"job:{w}#") for w in fixed_pbac_workflows):
            gone.add((e["source"], e["target"]))
    return gone


def _surviving_paths(graph: dict, gone: set[tuple[str, str]]) -> list[dict]:
    keep = []
    for p in graph.get("paths", []):
        n = p.get("nodes", [])
        if not any((n[i], n[i + 1]) in gone for i in range(len(n) - 1)):
            keep.append(p)
    return keep


def _state(controls: list[dict], findings: list[Finding], graph: dict, fixed: set[str]) -> dict:
    remaining = [f for f in findings if f.id not in fixed]
    left_by_rule: dict[str, int] = {}
    had_by_rule: dict[str, int] = {}
    for f in findings:
        had_by_rule[f.rule_id] = had_by_rule.get(f.rule_id, 0) + 1
    for f in remaining:
        left_by_rule[f.rule_id] = left_by_rule.get(f.rule_id, 0) + 1
    ctrls, flipped = [], []
    for c in controls:
        c2 = dict(c)
        if c["status"] == "FAIL" and had_by_rule.get(c["rule_id"]) and not left_by_rule.get(c["rule_id"]):
            c2["status"] = "PASS"
            flipped.append(c["rule_id"])
        ctrls.append(c2)
    summary = summarize(ctrls, [_ns(f) for f in remaining])
    pbac = {f.file_path for f in findings if f.id in fixed and f.rule_id == "PT-PBAC-001"}
    paths = _surviving_paths(graph, _removed_edges(graph, fixed, pbac))
    return {"posture_score": summary["posture_score"], "grade": summary["grade"], "severity_counts": summary["severity_counts"],
            "findings": len(remaining), "attack_paths": len(paths), "path_ids": [p["id"] for p in paths],
            "categories": {c["category"]: c["score"] for c in summary["categories"]}, "controls_fixed": flipped}


def simulate(scan, findings: list[Finding], fixed_ids: set[str]) -> dict:
    graph = scan.attack_graph or {}
    known = {f.id for f in findings}
    fixed = set(fixed_ids) & known
    before = _state(scan.controls or [], findings, graph, set())
    after = _state(scan.controls or [], findings, graph, fixed)
    removed = [pid for pid in before["path_ids"] if pid not in set(after["path_ids"])]
    delta = None if before["posture_score"] is None or after["posture_score"] is None else round(after["posture_score"] - before["posture_score"], 1)
    return {"fixed": sorted(fixed), "before": before, "after": after, "score_delta": delta, "removed_paths": removed,
            "category_deltas": {k: (None if v is None or before["categories"].get(k) is None else round(v - before["categories"][k], 1))
                                for k, v in after["categories"].items()}}


def recommendations(scan, findings: list[Finding], fixable_rules: set[str], limit: int = 12) -> dict:
    """Rank fixes by impact: whole rules ("fix every finding of PT-3P-001") and single findings."""
    graph = scan.attack_graph or {}
    controls = scan.controls or []
    base = _state(controls, findings, graph, set())
    by_rule: dict[str, list[Finding]] = {}
    for f in findings:
        if f.severity != "info":
            by_rule.setdefault(f.rule_id, []).append(f)

    def impact(ids: set[str]) -> dict:
        s = _state(controls, findings, graph, ids)
        gain = None if base["posture_score"] is None or s["posture_score"] is None else round(s["posture_score"] - base["posture_score"], 1)
        return {"score_gain": gain, "paths_removed": base["attack_paths"] - s["attack_paths"], "after_score": s["posture_score"],
                "controls_fixed": s["controls_fixed"]}

    rules = []
    for rid, fs in by_rule.items():
        imp = impact({f.id for f in fs})
        rules.append({"rule_id": rid, "title": fs[0].title, "category": fs[0].category, "findings": len(fs),
                      "finding_ids": [f.id for f in fs], "auto_fixable": rid in fixable_rules, **imp})
    rules.sort(key=lambda r: (-r["paths_removed"], -(r["score_gain"] or 0), -r["findings"]))

    singles = []
    path_fids = {fid for p in graph.get("paths", []) for fid in (p.get("finding_ids") or [])}
    candidates = [f for f in findings if f.id in path_fids or f.severity in ("critical", "high")]
    for f in candidates[:200]:
        imp = impact({f.id})
        if imp["paths_removed"] or (imp["score_gain"] or 0) > 0:
            singles.append({"finding_id": f.id, "rule_id": f.rule_id, "title": f.title, "severity": f.severity,
                            "location": f"{f.file_path}{':' + str(f.line) if f.line else ''}", "job": f.job,
                            "auto_fixable": f.rule_id in fixable_rules, **imp})
    singles.sort(key=lambda r: (-r["paths_removed"], -(r["score_gain"] or 0)))
    return {"baseline": {"posture_score": base["posture_score"], "grade": base["grade"], "attack_paths": base["attack_paths"],
                         "findings": base["findings"]},
            "by_rule": rules[:limit], "single_fixes": singles[:limit]}
