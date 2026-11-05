"""Report rendering: self-contained HTML, JSON export, and SARIF 2.1.0 (GitHub code scanning compatible)."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..scanner.model import CATEGORIES, CATEGORY_OBJECTIVES, CATEGORY_REF

_env = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"), autoescape=select_autoescape(["html"]),
                   trim_blocks=True, lstrip_blocks=True)
VERSION = "1.0.0"
SEV_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SEV_SCORE = {"critical": "9.5", "high": "7.5", "medium": "5.0", "low": "2.5", "info": "0.0"}


def render_html(data: dict) -> str:
    scan = data["scan"]
    by_cat: dict[str, list] = {c: [] for c in CATEGORIES}
    for f in data["findings"]:
        by_cat.setdefault(f["category"], []).append(f)
    controls_by_cat: dict[str, list] = {c: [] for c in CATEGORIES}
    for c in scan.get("controls") or []:
        controls_by_cat.setdefault(c["category"], []).append(c)
    fid_index = {f["id"]: i + 1 for i, f in enumerate(data["findings"])}
    return _env.get_template("report.html").render(
        d=data, scan=scan, summary=scan.get("summary") or {}, ai=scan.get("ai_analysis") or {}, categories=CATEGORIES,
        objectives=CATEGORY_OBJECTIVES, cat_refs=CATEGORY_REF, by_cat=by_cat, controls_by_cat=controls_by_cat,
        paths=(scan.get("attack_graph") or {}).get("paths", []), fid_index=fid_index,
        generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), version=VERSION)


def render_json(data: dict) -> dict:
    scan = data["scan"]
    return {
        "tool": {"name": "PipelineTrust", "version": VERSION}, "generated_at": datetime.now(timezone.utc).isoformat(),
        "framework": "OWASP Top 10 CI/CD Security Risks", "project": data["project"],
        "scan": {k: scan.get(k) for k in ("id", "status", "commit_sha", "created_at", "finished_at", "posture_score", "grade", "options")},
        "summary": scan.get("summary"), "controls": scan.get("controls"), "findings": data["findings"],
        "attack_paths": (scan.get("attack_graph") or {}).get("paths", []), "inventory": scan.get("inventory"),
        "tool_runs": scan.get("tool_runs"),
        "ai_analysis": {k: (scan.get("ai_analysis") or {}).get(k) for k in ("provider", "model", "mode", "report", "narratives", "guardrail", "disclaimer")},
    }


def render_sarif(data: dict) -> dict:
    rules_seen: dict[str, dict] = {}
    results = []
    for f in data["findings"]:
        rid = f["rule_id"] if f["rule_id"] != "PT-TOOL-ZIZMOR" else f"ZIZMOR-{(f.get('extra') or {}).get('zizmor_rule', 'finding')}"
        meta = data["rules"].get(f["rule_id"], {})
        if rid not in rules_seen:
            rules_seen[rid] = {
                "id": rid, "name": rid.replace("-", ""), "shortDescription": {"text": f["title"][:200]},
                "fullDescription": {"text": (meta.get("description") or f["title"])[:1000]},
                "help": {"text": meta.get("remediation") or "", "markdown": f"**Remediation:** {meta.get('remediation', '')}"},
                "helpUri": (meta.get("references") or [CATEGORY_REF.get(f["category"], "")])[0],
                "properties": {"tags": ["security", "ci-cd", f["category"], *(meta.get("cwe") or [])],
                               "security-severity": SEV_SCORE.get(f["severity"], "5.0"), "category": f["category"]},
            }
        loc_path = f["file_path"] if f["file_path"] and not f["file_path"].startswith("(") else ".github"
        region = {"startLine": f["line"]} if f.get("line") else {"startLine": 1}
        results.append({
            "ruleId": rid, "level": SEV_LEVEL.get(f["severity"], "warning"),
            "message": {"text": f["message"][:2000]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": loc_path}, "region": region}}],
            "partialFingerprints": {"pipelinetrustFingerprint/v1": f["fingerprint"]},
            "properties": {"severity": f["severity"], "confidence": f["confidence"], "evidence_type": f["evidence_type"],
                           "risk_score": f["risk_score"], "owasp_category": f["category"], "triage_status": f["triage_status"]},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "PipelineTrust", "version": VERSION, "informationUri": "https://owasp.org/www-project-top-10-ci-cd-security-risks/",
                                      "rules": list(rules_seen.values())}},
                  "results": results,
                  "properties": {"posture_score": data["scan"].get("posture_score")}}],
    }
