"""PipelineTrust CLI - run an assessment locally or in CI without the web app.

    python -m app.cli scan PATH [--github owner/repo] [--format table|json|sarif|html] [--out FILE]
                       [--tools gitleaks,actionlint,...|none] [--fail-on high] [--ai]
                       [--policies FILE_OR_DIR] [--fail-on-policy] [--max-attack-paths N] [--summary FILE]

Exit code 1 when the gate fails: any finding at or above --fail-on, any custom-policy violation with --fail-on-policy,
or more attack paths than --max-attack-paths. --summary writes a Markdown summary (e.g. to $GITHUB_STEP_SUMMARY).
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
    sc.add_argument("--policies", help="custom policy file (.yml/.yaml/.json, several documents allowed) or directory of them")
    sc.add_argument("--fail-on-policy", action="store_true", help="fail when any custom policy is violated")
    sc.add_argument("--max-attack-paths", type=int, default=None, help="fail when more attack paths than this are found")
    sc.add_argument("--summary", help="write a Markdown gate summary to this file (appends)")
    sub.add_parser("rules", help="list detection rules")
    a = ap.parse_args(argv)

    if a.cmd == "rules":
        for rid, c in load_rules().items():
            print(f"{rid:16} {c.category:11} {c.severity:8} {c.title}")
        return 0

    opts = {"tools": [] if a.tools == "none" else [t for t in a.tools.split(",") if t]}
    opts["run_tools"] = bool(opts["tools"])
    if a.policies:
        try:
            opts["custom_policies"] = load_policy_files(Path(a.policies))
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"[*] {len(opts['custom_policies'])} custom policy(ies) loaded", file=sys.stderr)
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
    reasons = gate_reasons(res, a.fail_on, a.fail_on_policy, a.max_attack_paths)
    if a.summary:
        with open(a.summary, "a", encoding="utf-8") as fh:
            fh.write(gate_summary(res, reasons))
    for r in reasons:
        print(f"[!] gate failed: {r}", file=sys.stderr)
    return 1 if reasons else 0


def load_policy_files(path: Path) -> list[dict]:
    import yaml

    from .scanner.policies import PolicyError, parse_policy

    files = sorted(x for x in path.rglob("*") if x.suffix in (".yml", ".yaml", ".json")) if path.is_dir() else [path]
    out = []
    for f in files:
        text = f.read_text("utf-8")
        docs = [d for d in yaml.safe_load_all(text) if d]
        for d in docs:
            try:
                out.append(parse_policy(yaml.safe_dump(d)))
            except PolicyError as exc:
                raise ValueError(f"{f}: {exc}") from exc
    return out


def gate_reasons(res, fail_on: str, fail_on_policy: bool, max_paths: int | None) -> list[str]:
    reasons = []
    if fail_on != "none":
        th = SEVERITY_ORDER[fail_on]
        hits = [f for f in res.findings if SEVERITY_ORDER.get(f.severity, 0) >= th]
        if hits:
            reasons.append(f"{len(hits)} finding(s) at or above {fail_on}")
    if fail_on_policy:
        pol = [f for f in res.findings if not f.rule_id.startswith("PT-")]
        if pol:
            reasons.append(f"{len(pol)} custom policy violation(s): " + ", ".join(sorted({f.rule_id for f in pol})))
    n = len(res.attack_graph.get("paths", []))
    if max_paths is not None and n > max_paths:
        reasons.append(f"{n} attack path(s), limit is {max_paths}")
    return reasons


def gate_summary(res, reasons: list[str]) -> str:
    sc = res.summary.get("severity_counts", {})
    lines = [f"## PipelineTrust: {'❌ gate failed' if reasons else '✅ gate passed'}", "",
             f"Posture **{res.summary.get('posture_score')}** (grade {res.summary.get('grade')}) · "
             + " · ".join(f"{k} {sc.get(k, 0)}" for k in ("critical", "high", "medium", "low"))
             + f" · attack paths {len(res.attack_graph.get('paths', []))}", ""]
    lines += [f"- {r}" for r in reasons]
    top = sorted(res.findings, key=lambda f: -SEVERITY_ORDER.get(f.severity, 0))[:15]
    if top:
        lines += ["", "| Severity | Rule | Finding | Location |", "|---|---|---|---|"]
        lines += [f"| {f.severity} | {f.rule_id} | {f.title.replace('|', '/')} | `{f.file_path}{':' + str(f.line) if f.line else ''}` |" for f in top]
    return "\n".join(lines) + "\n\n"


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
