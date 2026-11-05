"""Developer smoke test: run the full engine (with tools) on the sample repositories and print a digest."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.scanner.engine import run_assessment  # noqa: E402
from app.scanner.model import RepoMetadata  # noqa: E402

SAMPLES = Path(__file__).resolve().parents[2] / "samples"
tools = sys.argv[1].split(",") if len(sys.argv) > 1 and sys.argv[1] else []

for repo in ("vulnerable-repo", "hardened-repo"):
    opts = {"tools": tools} if tools else {"run_tools": False}
    r = run_assessment(SAMPLES / repo, RepoMetadata(source="upload"), opts, artifacts_dir=Path("data/_smoke") / repo)
    print("=" * 30, repo, "score", r.summary["posture_score"], r.summary["severity_counts"])
    for t in r.tool_runs:
        print("TOOL", t["tool"], t["status"], t["count"], t["seconds"], str(t["detail"])[:200])
    for c in r.controls:
        print(f"  C {c['rule_id']:16} {c['status']:24} {c['finding_count']:>3} {c['note'][:80]}")
    for f in r.findings:
        corr = " [corroborated]" if f.extra.get("corroborated_by") else ""
        print(f"  F {f.risk_score:>4} {f.severity:8} {f.rule_id:15} {f.category:11} {f.file_path}:{f.line} | {f.message[:130]}{corr}")
    for p in r.attack_graph["paths"][:8]:
        print("  P", p["id"], p["risk"], " -> ".join(p["labels"]))
    print("  coverage", r.summary["coverage"])
    for n in r.coverage_notes:
        print("  N", n)
