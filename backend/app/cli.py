"""PipelineTrust CLI - run an assessment locally or in CI without the web app.

    python -m app.cli scan PATH [--github owner/repo] [--format table|json|sarif|html] [--out FILE]
                       [--tools gitleaks,actionlint,...|none] [--fail-on high] [--ai]

Exit code 1 when any open finding is at or above --fail-on severity (for use as a CI gate).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from .scanner.engine import run_assessment
from .scanner.model import SEVERITY_ORDER, RepoMetadata
from .scanner.rules import load_rules
from .scanner.tools import DEFAULT_TOOLS


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pipelinetrust")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan", help="assess a local repository directory")
    sc.add_argument("path", nargs="?", default=".")
    sc.add_argument("--github", help="owner/repo: download and collect settings via GitHub API (token from GITHUB_TOKEN)")
    sc.add_argument("--format", choices=["table", "json", "sarif", "html"], default="table")
    sc.add_argument("--out")
    sc.add_argument("--tools", default=",".join(DEFAULT_TOOLS), help="comma list or 'none'")
    sc.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"], default="none")
    sc.add_argument("--ai", action="store_true", help="run AI agents (PT_LLM_PROVIDER / API key required, else deterministic)")
    sub.add_parser("rules", help="list detection rules")
    a = ap.parse_args(argv)

    if a.cmd == "rules":
        for rid, c in load_rules().items():
            print(f"{rid:16} {c.category:11} {c.severity:8} {c.title}")
        return 0

    opts = {"tools": [] if a.tools == "none" else [t for t in a.tools.split(",") if t]}
    opts["run_tools"] = bool(opts["tools"])
    tmp = None
    resolver = None
    if a.github:
        from .connectors.base import ConnectorError
        from .connectors.github import GitHubConnector

        tmp = tempfile.TemporaryDirectory()
        proj = type("P", (), {"repo_full_name": a.github, "ref": "", "name": a.github})()
        try:
            ws = GitHubConnector().acquire(project=proj, secret=os.environ.get("GITHUB_TOKEN"), workdir=Path(tmp.name), upload_path=None,
                                           progress=lambda m: print(f"[*] {m}", file=sys.stderr))
        except ConnectorError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        root, md, resolver = ws.root, ws.metadata, ws.sha_resolver
    else:
        root = Path(a.path).resolve()
        if not root.is_dir():
            print(f"error: {root} is not a directory", file=sys.stderr)
            return 2
        md = RepoMetadata(source="upload", full_name=root.name)
    art = Path(tempfile.mkdtemp(prefix="pt-art-"))
    res = run_assessment(root, md, opts, art, lambda m: print(f"[*] {m}", file=sys.stderr), resolver)

    findings = [f.__dict__ | {"fingerprint": f.fingerprint, "id": f"F{i + 1}", "triage_status": "open", "validation_status": "", "triage_note": "", "ai_notes": {}}
                for i, f in enumerate(res.findings)]
    scan = {"id": "cli", "status": "completed", "summary": res.summary, "controls": res.controls, "inventory": res.inventory,
            "tool_runs": res.tool_runs, "attack_graph": res.attack_graph, "posture_score": res.summary["posture_score"],
            "grade": res.summary["grade"], "commit_sha": "", "created_at": "", "finished_at": "", "options": opts, "ai_analysis": {}}
    fp_to_id = {f["fingerprint"]: f["id"] for f in findings}
    for p in res.attack_graph.get("paths", []):
        p["finding_ids"] = [fp_to_id[x] for x in p["findings"] if x in fp_to_id]
    rules = {rid: c.describe() for rid, c in load_rules().items()}
    if a.ai:
        from .agents.pipeline import run_ai_analysis
        scan["ai_analysis"] = run_ai_analysis(findings, res.controls, res.inventory, res.attack_graph.get("paths", []), res.summary, rules)
    data = {"scan": scan, "project": {"name": md.full_name, "repo": md.full_name if a.github else "", "source": md.source},
            "findings": findings, "rules": rules}

    if a.format == "table":
        out = _table(res)
    else:
        from .reports.render import render_html, render_json, render_sarif
        out = {"json": lambda: json.dumps(render_json(data), indent=2, default=str),
               "sarif": lambda: json.dumps(render_sarif(data), indent=2), "html": lambda: render_html(data)}[a.format]()
    if a.out:
        Path(a.out).write_text(out, encoding="utf-8")
        print(f"[*] wrote {a.out}", file=sys.stderr)
    else:
        sys.stdout.write(out + "\n")
    if tmp:
        tmp.cleanup()
    if a.fail_on != "none":
        th = SEVERITY_ORDER[a.fail_on]
        if any(SEVERITY_ORDER.get(f.severity, 0) >= th for f in res.findings):
            return 1
    return 0


def _table(res) -> str:
    s = res.summary
    lines = [f"PipelineTrust - posture {s['posture_score']} ({s['grade']})  findings {s['total_findings']}  "
             f"coverage {s['coverage']['percent']}%", ""]
    for c in s["categories"]:
        lines.append(f"  {c['category']:11} {c['status']:24} score {str(c['score']):6} findings {c['findings']:>3}  {c['name']}")
    lines.append("")
    for f in res.findings:
        if f.severity == "info":
            continue
        lines.append(f"  [{f.severity.upper():8}] {f.rule_id:15} {f.file_path}:{f.line or '-'}  {f.message[:140]}")
    for p in res.attack_graph.get("paths", [])[:5]:
        lines.append(f"  PATH {p['id']} risk {p['risk']}: " + " -> ".join(p["labels"]))
    for n in res.coverage_notes:
        lines.append(f"  NOTE {n}")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
