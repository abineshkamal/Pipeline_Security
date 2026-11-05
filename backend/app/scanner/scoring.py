"""Risk scoring.

finding.risk_score (0-10) = severity base x confidence factor x exposure factor.
category score (0-100)    = 100 - penalty, where each failing rule contributes its worst finding risk x 6
                            plus 1 point per additional finding (max +5 per rule). Capped to [0, 100].
posture score             = mean of category scores over categories with at least one assessed control.
Controls that are NOT_ASSESSED / NEEDS_MANUAL_VALIDATION never raise or lower the score - they lower coverage.
"""
from __future__ import annotations

from .model import CATEGORIES, FindingResult, SEVERITY_ORDER

SEVERITY_BASE = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}
CONFIDENCE_FACTOR = {"high": 1.0, "medium": 0.85, "low": 0.6}


def score_finding(f: FindingResult, public_repo: bool | None) -> float:
    base = SEVERITY_BASE.get(f.severity, 2.5)
    conf = CONFIDENCE_FACTOR.get(f.confidence, 0.85)
    exposure = 1.0
    triggers = set(f.extra.get("triggers") or [])
    if f.extra.get("code_execution") and (triggers or f.category == "CICD-SEC-4"):
        exposure += 0.1
    if public_repo:
        exposure += 0.1
    if f.extra.get("corroborated_by"):
        conf = min(1.0, conf + 0.1)
    return round(min(10.0, base * conf * exposure), 1)


def grade(score: float | None) -> str:
    if score is None:
        return "N/A"
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"


def summarize(controls: list[dict], findings: list[FindingResult]) -> dict:
    by_cat: dict[str, dict] = {c: {"category": c, "name": n, "controls": 0, "pass": 0, "fail": 0, "not_assessed": 0,
                                    "not_applicable": 0, "manual": 0, "findings": 0, "penalty": 0.0} for c, n in CATEGORIES.items()}
    for c in controls:
        cat = by_cat.get(c["category"])
        if not cat or c["rule_id"].startswith("PT-TOOL-"):  # cross-category tool controls count via their findings
            continue
        if not cat:
            continue
        cat["controls"] += 1
        key = {"PASS": "pass", "FAIL": "fail", "NOT_ASSESSED": "not_assessed", "NOT_APPLICABLE": "not_applicable",
               "NEEDS_MANUAL_VALIDATION": "manual"}[c["status"]]
        cat[key] += 1
    rule_findings: dict[tuple[str, str], list[FindingResult]] = {}
    for f in findings:
        if f.severity == "info":
            continue  # informational evidence never fails a category
        rule_findings.setdefault((f.category, f.rule_id), []).append(f)
        if f.category in by_cat:
            by_cat[f.category]["findings"] += 1
    for (cat, _rid), fs in rule_findings.items():
        if cat not in by_cat:
            continue
        worst = max(x.risk_score for x in fs)
        by_cat[cat]["penalty"] += worst * 6 + min(len(fs) - 1, 5)
    scores = []
    for cat in by_cat.values():
        assessed = cat["pass"] + cat["fail"] + (1 if cat["findings"] else 0)
        if assessed == 0:
            cat["score"] = None
        else:
            cat["score"] = round(max(0.0, 100 - cat["penalty"]), 1)
            scores.append(cat["score"])
        cat["grade"] = grade(cat["score"])
        cat["status"] = ("FAIL" if cat["fail"] or cat["findings"] else "PASS" if cat["pass"] else
                         "NEEDS_MANUAL_VALIDATION" if cat["manual"] else "NOT_ASSESSED" if cat["not_assessed"] else "NOT_APPLICABLE")
        del cat["penalty"]
    sev_counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    posture = round(sum(scores) / len(scores), 1) if scores else None
    total = len(controls)
    decided = sum(1 for c in controls if c["status"] in ("PASS", "FAIL"))
    return {
        "posture_score": posture, "grade": grade(posture), "severity_counts": sev_counts, "total_findings": len(findings),
        "categories": list(by_cat.values()),
        "coverage": {"controls": total, "automated_decisions": decided,
                     "not_assessed": sum(1 for c in controls if c["status"] == "NOT_ASSESSED"),
                     "manual": sum(1 for c in controls if c["status"] == "NEEDS_MANUAL_VALIDATION"),
                     "not_applicable": sum(1 for c in controls if c["status"] == "NOT_APPLICABLE"),
                     "percent": round(100 * decided / max(1, total - sum(1 for c in controls if c["status"] == "NOT_APPLICABLE")), 1)},
    }
