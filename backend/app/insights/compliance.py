"""Compliance evidence packs: map PipelineTrust controls to external frameworks.

Mappings are indicative - they show which automated CI/CD checks provide evidence for a framework requirement. A
requirement is only as satisfied as its mapped controls; manual or unassessed controls keep it open. This supports an
audit; it does not replace one.
"""
from __future__ import annotations

import csv
import html
import io

from ..models import Finding

DISCLAIMER = ("Indicative mapping from automated checks of CI/CD configuration. It provides evidence for, but does not "
              "replace, an assessment by a qualified auditor. Requirements outside the CI/CD pipeline are not covered.")

FRAMEWORKS: dict[str, dict] = {
    "ssdf": {
        "name": "NIST SSDF (SP 800-218 v1.1)",
        "controls": [
            ("PO.3.2", "Securely deploy, operate and maintain tools and toolchains",
             ["PT-SYS-001", "PT-SYS-002", "PT-SYS-003", "PT-SYS-005", "PT-3P-001", "PT-3P-002", "PT-3P-003", "PT-3P-004"]),
            ("PO.3.3", "Configure tools to generate evidence of secure development practices",
             ["PT-LOG-001", "PT-LOG-002", "PT-LOG-003", "PT-LOG-004", "PT-ART-001"]),
            ("PO.5.1", "Separate and protect each environment involved in software development",
             ["PT-FC-003", "PT-PBAC-003", "PT-SYS-001", "PT-PPE-001", "PT-PPE-002", "PT-PPE-005"]),
            ("PO.5.2", "Secure and harden development endpoints (build runners)", ["PT-SYS-001", "PT-SYS-002"]),
            ("PS.1.1", "Store all forms of code based on the principle of least privilege",
             ["PT-FC-001", "PT-FC-002", "PT-FC-004", "PT-IAM-001", "PT-IAM-002", "PT-IAM-003", "PT-PBAC-001", "PT-PBAC-002",
              "PT-PBAC-005", "PT-CRED-001", "PT-CRED-005", "PT-CRED-006"]),
            ("PS.2.1", "Make software integrity verification information available", ["PT-ART-002", "PT-ART-003"]),
            ("PS.3.2", "Collect, safeguard and share provenance data (e.g. SBOM)", ["PT-ART-001", "PT-ART-003", "PT-LOG-002"]),
            ("PW.4.1", "Acquire and maintain well-secured third-party components",
             ["PT-DEP-001", "PT-DEP-002", "PT-DEP-003", "PT-DEP-004", "PT-3P-001", "PT-3P-004", "PT-3P-005"]),
            ("PW.4.4", "Verify that acquired components are trustworthy and not tampered with", ["PT-ART-004", "PT-3P-001", "PT-DEP-002"]),
            ("RV.1.1", "Gather information about potential vulnerabilities in the software", ["PT-DEP-004", "PT-LOG-004"]),
        ],
    },
    "slsa": {
        "name": "SLSA v1.0 Build track (indicators)",
        "controls": [
            ("BUILD-L1", "Provenance exists and describes how the artifact was built", ["PT-ART-003"]),
            ("BUILD-L2", "Hosted build platform generates signed provenance", ["PT-ART-003", "PT-ART-002", "PT-SYS-001"]),
            ("BUILD-L3", "Hardened builds: runs are isolated and secrets are not reachable by untrusted steps",
             ["PT-PPE-001", "PT-PPE-002", "PT-PPE-003", "PT-PPE-004", "PT-PPE-005", "PT-ART-005", "PT-CRED-002", "PT-CRED-003", "PT-SYS-002"]),
            ("SOURCE", "Source integrity: changes are protected and reviewed (source track, draft)", ["PT-FC-001", "PT-FC-002", "PT-FC-004"]),
        ],
    },
    "cis-ssc": {
        "name": "CIS Software Supply Chain Security Guide (areas)",
        "controls": [
            ("SOURCE-CHANGES", "Source code: code changes are protected, reviewed and owned", ["PT-FC-001", "PT-FC-002", "PT-FC-004", "PT-IAM-001"]),
            ("SOURCE-ACCESS", "Source code: repository access and third-party permissions", ["PT-IAM-002", "PT-IAM-003", "PT-3P-003"]),
            ("BUILD-PIPELINE", "Build pipelines: integrity, least privilege and secret handling",
             ["PT-PBAC-001", "PT-PBAC-002", "PT-PBAC-004", "PT-PBAC-005", "PT-CRED-001", "PT-CRED-002", "PT-CRED-003", "PT-CRED-005",
              "PT-PPE-001", "PT-PPE-002", "PT-PPE-003", "PT-PPE-004", "PT-PPE-005", "PT-SYS-004"]),
            ("BUILD-WORKERS", "Build environment: runner isolation and hardening", ["PT-SYS-001", "PT-SYS-002", "PT-SYS-005"]),
            ("DEPENDENCIES", "Dependencies: third-party packages and actions are trusted and pinned",
             ["PT-DEP-001", "PT-DEP-002", "PT-DEP-003", "PT-DEP-004", "PT-3P-001", "PT-3P-002", "PT-3P-004", "PT-3P-005"]),
            ("ARTIFACTS", "Artifacts: signing, SBOM, provenance and verification",
             ["PT-ART-001", "PT-ART-002", "PT-ART-003", "PT-ART-004", "PT-ART-005"]),
            ("DEPLOYMENT", "Deployment: protected environments and short-lived credentials", ["PT-FC-003", "PT-PBAC-003", "PT-CRED-004"]),
        ],
    },
    "soc2": {
        "name": "SOC 2 Trust Services Criteria (CI/CD evidence)",
        "controls": [
            ("CC6.1", "Logical access security over protected information assets",
             ["PT-IAM-002", "PT-IAM-003", "PT-PBAC-001", "PT-PBAC-002", "PT-PBAC-005", "PT-CRED-001", "PT-CRED-004", "PT-CRED-006"]),
            ("CC6.3", "Role-based access and segregation of duties", ["PT-IAM-002", "PT-FC-004", "PT-PBAC-003"]),
            ("CC6.8", "Prevent or detect unauthorized or malicious software",
             ["PT-3P-001", "PT-3P-003", "PT-3P-004", "PT-DEP-001", "PT-PPE-001", "PT-PPE-003", "PT-ART-004"]),
            ("CC7.1", "Detect configuration changes and newly discovered vulnerabilities", ["PT-DEP-004", "PT-LOG-004", "PT-SYS-003"]),
            ("CC7.2", "Monitor system components for anomalies", ["PT-LOG-001", "PT-LOG-002", "PT-LOG-003"]),
            ("CC8.1", "Authorize, test, approve and implement changes", ["PT-FC-001", "PT-FC-002", "PT-FC-003", "PT-IAM-001"]),
        ],
    },
    "iso27001": {
        "name": "ISO/IEC 27001:2022 Annex A (CI/CD evidence)",
        "controls": [
            ("A.5.15", "Access control", ["PT-IAM-002", "PT-PBAC-001", "PT-PBAC-002", "PT-PBAC-004"]),
            ("A.5.17", "Authentication information", ["PT-CRED-001", "PT-CRED-003", "PT-CRED-005", "PT-CRED-006"]),
            ("A.5.21", "Managing information security in the ICT supply chain",
             ["PT-3P-001", "PT-3P-002", "PT-3P-004", "PT-3P-005", "PT-DEP-001", "PT-DEP-003", "PT-ART-001"]),
            ("A.8.2", "Privileged access rights", ["PT-IAM-002", "PT-PBAC-002", "PT-PBAC-005", "PT-FC-004"]),
            ("A.8.4", "Access to source code", ["PT-FC-001", "PT-FC-002", "PT-IAM-001"]),
            ("A.8.5", "Secure authentication", ["PT-IAM-003", "PT-CRED-004"]),
            ("A.8.8", "Management of technical vulnerabilities", ["PT-DEP-004", "PT-3P-004", "PT-LOG-004"]),
            ("A.8.9", "Configuration management", ["PT-SYS-002", "PT-SYS-003", "PT-SYS-005", "PT-PBAC-001"]),
            ("A.8.15", "Logging", ["PT-LOG-001", "PT-LOG-002", "PT-LOG-003"]),
            ("A.8.25", "Secure development life cycle", ["PT-PPE-001", "PT-PPE-002", "PT-PPE-003", "PT-PPE-005", "PT-LOG-004"]),
            ("A.8.32", "Change management", ["PT-FC-001", "PT-FC-002", "PT-FC-003"]),
        ],
    },
}


def _status(statuses: list[str]) -> str:
    if not statuses:
        return "NOT_ASSESSED"
    if "FAIL" in statuses:
        return "FAIL"
    decided = [s for s in statuses if s != "NOT_APPLICABLE"]
    if not decided:
        return "NOT_APPLICABLE"
    if all(s == "PASS" for s in decided):
        return "PASS"
    if "PASS" in decided:
        return "PARTIAL"
    return "NEEDS_MANUAL_VALIDATION" if "NEEDS_MANUAL_VALIDATION" in decided else "NOT_ASSESSED"


def assess(scan, findings: list[Finding], framework: str) -> dict:
    fw = FRAMEWORKS[framework]
    ctrl = {c["rule_id"]: c for c in scan.controls or []}
    by_rule: dict[str, list[Finding]] = {}
    for f in findings:
        if f.triage_status != "false_positive":
            by_rule.setdefault(f.rule_id, []).append(f)
    reqs = []
    for rid, title, rules in fw["controls"]:
        evid = []
        for r in rules:
            c = ctrl.get(r)
            if not c:
                continue
            fs = by_rule.get(r, [])
            evid.append({"rule_id": r, "title": c["title"], "status": c["status"], "note": c.get("note", ""),
                         "evidence": (c.get("evidence") or [])[:5], "open_findings": sum(1 for f in fs if f.triage_status in ("open", "confirmed")),
                         "accepted_risk": sum(1 for f in fs if f.triage_status == "accepted_risk"),
                         "findings": [{"id": f.id, "title": f.title, "severity": f.severity,
                                       "location": f"{f.file_path}{':' + str(f.line) if f.line else ''}", "triage": f.triage_status} for f in fs[:5]]})
        reqs.append({"id": rid, "title": title, "status": _status([e["status"] for e in evid]), "evidence": evid,
                     "open_findings": sum(e["open_findings"] for e in evid)})
    counts = {}
    for r in reqs:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    decided = sum(1 for r in reqs if r["status"] in ("PASS", "FAIL", "PARTIAL"))
    return {"framework": framework, "name": fw["name"], "disclaimer": DISCLAIMER, "requirements": reqs, "counts": counts,
            "satisfied_percent": round(100 * counts.get("PASS", 0) / max(1, decided), 1),
            "frameworks": [{"id": k, "name": v["name"]} for k, v in FRAMEWORKS.items()]}


def to_csv(pack: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["framework", "requirement", "title", "status", "open_findings", "mapped_controls"])
    for r in pack["requirements"]:
        w.writerow([pack["name"], r["id"], r["title"], r["status"], r["open_findings"],
                    "; ".join(f"{e['rule_id']}={e['status']}" for e in r["evidence"])])
    return buf.getvalue()


def to_html(pack: dict, project: str, repo: str, scanned: str, commit: str) -> str:
    e = html.escape
    rows = []
    for r in pack["requirements"]:
        ev = "".join(
            f"<li><code>{e(x['rule_id'])}</code> {e(x['title'])} - <b>{e(x['status'])}</b>"
            + (f" · {x['open_findings']} open finding(s)" if x["open_findings"] else "")
            + (f"<div class='n'>{e(x['note'])}</div>" if x["note"] else "")
            + "".join(f"<div class='n'>{e(s)}</div>" for s in x["evidence"])
            + "".join(f"<div class='n'>[{e(f['severity'])}] {e(f['title'])} - {e(f['location'])} ({e(f['triage'])})</div>" for f in x["findings"])
            + "</li>" for x in r["evidence"])
        rows.append(f"<tr><td><b>{e(r['id'])}</b></td><td>{e(r['title'])}</td><td class='s {e(r['status'])}'>{e(r['status'])}</td>"
                    f"<td><ul>{ev or '<li>No mapped automated control.</li>'}</ul></td></tr>")
    counts = " · ".join(f"{e(k)}: {v}" for k, v in sorted(pack["counts"].items()))
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{e(pack['name'])} evidence - {e(project)}</title>
<style>body{{font:14px/1.45 system-ui,Segoe UI,Arial,sans-serif;margin:32px;color:#151a30}}h1{{font-size:22px}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #d5dae6;padding:8px;vertical-align:top;text-align:left}}th{{background:#eef1f8}}ul{{margin:0;padding-left:18px}}
.n{{color:#5b6478;font-size:12px}}.s{{font-weight:700}}.FAIL{{color:#b3261e}}.PASS{{color:#2e7d4f}}.PARTIAL{{color:#a15c00}}
.d{{background:#fff4e2;padding:10px 12px;border-radius:6px}}</style></head><body>
<h1>{e(pack['name'])} - CI/CD evidence pack</h1>
<p><b>Project:</b> {e(project)} · <b>Repository:</b> {e(repo or 'uploaded archive')} · <b>Scanned:</b> {e(scanned)} · <b>Commit:</b> <code>{e(commit or '-')}</code></p>
<p><b>Result:</b> {counts} · {pack['satisfied_percent']}% of decided requirements satisfied</p>
<p class="d">{e(pack['disclaimer'])}</p>
<table><thead><tr><th>Requirement</th><th>Title</th><th>Status</th><th>Evidence (automated controls)</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
<p class="n">Generated by PipelineTrust.</p></body></html>"""
