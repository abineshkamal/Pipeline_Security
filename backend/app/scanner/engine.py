"""Assessment engine: workspace -> inventory -> rules + tools -> correlation -> scoring -> attack graph."""
from __future__ import annotations

import logging
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..graph.attack_paths import build_attack_graph
from .gha import (
    effective_job_permissions, external_triggers, is_self_hosted, job_deploy_indicators, job_secret_names, parse_uses,
    privileged_external_triggers, write_scopes,
)
from .model import CATEGORIES, FindingResult, RepoMetadata, RuleOutcome, ScanContext, Status, parse_workflow
from .rules import load_rules
from .scoring import score_finding, summarize
from .tools import DEFAULT_TOOLS, run_tools
from .workspace import detect_other_ci, list_files, workflow_paths

log = logging.getLogger("pipelinetrust.engine")

ShaResolver = Callable[[str, str, str], "str | None"]


@dataclass
class AssessmentResult:
    inventory: dict
    controls: list[dict]
    findings: list[FindingResult]
    tool_runs: list[dict]
    summary: dict
    attack_graph: dict
    coverage_notes: list[str] = field(default_factory=list)
    sbom_path: str | None = None
    workflow_sources: dict[str, str] = field(default_factory=dict)  # path -> text, kept so fixes can be generated later


def load_context(root: Path, metadata: RepoMetadata, options: dict | None = None) -> ScanContext:
    files = list_files(root)
    workflows = []
    for rel in workflow_paths(files):
        try:
            text = (root / rel).read_text("utf-8", errors="replace")
        except OSError as exc:
            text = ""
            wf = parse_workflow(rel, text)
            wf.error = f"unreadable: {exc}"
            workflows.append(wf)
            continue
        workflows.append(parse_workflow(rel, text))
    return ScanContext(root=root, files=files, workflows=workflows, metadata=metadata, options=options or {})


def build_inventory(ctx: ScanContext) -> dict:
    wfs, actions, secrets, runners, envs, triggers = [], {}, {}, {}, {}, {}
    for wf in ctx.workflows:
        entry = {"path": wf.path, "name": wf.name, "error": wf.error, "triggers": sorted(wf.triggers), "jobs": [],
                 "permissions": wf.permissions if isinstance(wf.permissions, (str, dict)) else None,
                 "external_triggers": sorted(external_triggers(wf)) if wf.data else [],
                 "privileged_triggers": sorted(privileged_external_triggers(wf)) if wf.data else []}
        for t in wf.triggers:
            triggers.setdefault(t, []).append(wf.path)
        for job in wf.jobs:
            perms, src = effective_job_permissions(wf, job)
            sec = sorted(job_secret_names(job))
            for s in sec:
                secrets.setdefault(s, set()).add(f"{wf.path}#{job.id}")
            if is_self_hosted(job):
                runners.setdefault(", ".join(job.runs_on), set()).add(f"{wf.path}#{job.id}")
            if job.environment:
                envs.setdefault(job.environment, set()).add(f"{wf.path}#{job.id}")
            entry["jobs"].append({
                "id": job.id, "name": job.name, "line": job.line, "runs_on": job.runs_on, "self_hosted": is_self_hosted(job),
                "environment": job.environment, "permissions_source": src,
                "write_scopes": sorted(write_scopes(perms)) if perms is not None else None,
                "secrets": sec, "steps": len(job.steps), "reusable": job.uses,
                "deploy_indicators": job_deploy_indicators(job)[:5],
            })
            uses_list = [(s.uses, s.key_line("uses")) for s in job.steps if s.uses] + ([(job.uses, job.key_line("uses"))] if job.uses else [])
            for uses, uline in uses_list:
                ref = parse_uses(uses)
                if not ref or ref.kind == "local":
                    continue
                key = uses
                a = actions.setdefault(key, {"uses": uses, "kind": ref.kind, "owner": ref.owner, "action": ref.slug if ref.kind != "docker" else ref.path,
                                             "ref": ref.ref, "sha_pinned": ref.is_sha_pinned, "first_party": ref.is_first_party,
                                             "workflows": set(), "count": 0, "occurrences": []})
                a["workflows"].add(wf.path)
                a["count"] += 1
                a["occurrences"].append({"workflow": wf.path, "job": job.id, "line": uline})
        wfs.append(entry)
    manifests = [f for f in ctx.files if f.rsplit("/", 1)[-1] in ("package.json", "requirements.txt", "pyproject.toml", "go.mod", "Cargo.toml", "Gemfile", "pom.xml", "build.gradle", "composer.json", "Dockerfile")]
    md = ctx.metadata
    return {
        "source": md.source, "repository": md.full_name, "default_branch": md.default_branch, "visibility": md.visibility,
        "file_count": len(ctx.files), "workflows": wfs,
        "actions": sorted(({**a, "workflows": sorted(a["workflows"])} for a in actions.values()), key=lambda x: (x["first_party"], x["uses"])),
        "secrets": {k: sorted(v) for k, v in sorted(secrets.items())},
        "self_hosted_runners": {k: sorted(v) for k, v in runners.items()},
        "environments": {k: sorted(v) for k, v in envs.items()},
        "triggers": {k: sorted(v) for k, v in sorted(triggers.items())},
        "other_ci_systems": detect_other_ci(ctx.files),
        "manifests": manifests[:200],
        "api_collection": {k: {"status": v.status, "detail": v.detail} for k, v in md.collected.items()},
        "secret_metadata": _secret_metadata(md),
    }


def _secret_metadata(md: RepoMetadata) -> dict:
    r = md.collected.get("secret_metadata")
    if r is None:
        return {"status": "skipped", "detail": "offline (ZIP) assessment", "secrets": []}
    return {"status": r.status, "detail": r.detail, "secrets": r.data if r.status == "ok" else []}


def _corroborate(findings: list[FindingResult]) -> list[FindingResult]:
    """Merge tool findings that duplicate a built-in configuration finding into corroborating evidence."""
    primary = [f for f in findings if f.evidence_type != "tool"]
    merged: list[FindingResult] = list(primary)
    for t in (f for f in findings if f.evidence_type == "tool"):
        if t.rule_id not in ("PT-TOOL-ZIZMOR", "PT-SYS-003") or not t.line:
            merged.append(t)
            continue
        match = None
        for p in primary:
            if p.file_path == t.file_path and p.line and abs(p.line - t.line) <= 3 and (
                    p.category == t.category or (t.rule_id == "PT-SYS-003" and p.category == "CICD-SEC-4" and "untrusted" in t.message)):
                match = p
                break
        if match:
            match.extra.setdefault("corroborated_by", []).append(f"{t.message[:140]}")
        else:
            merged.append(t)
    return merged


def run_assessment(root: Path, metadata: RepoMetadata, options: dict | None = None, artifacts_dir: Path | None = None,
                   progress: Callable[[str], None] | None = None, sha_resolver: ShaResolver | None = None) -> AssessmentResult:
    options = options or {}
    progress = progress or (lambda _m: None)
    progress("Parsing workflows")
    ctx = load_context(root, metadata, options)

    tools = options.get("tools", DEFAULT_TOOLS) if options.get("run_tools", True) else []
    tool_log: list[dict] = []
    if tools:
        ctx.tool_results, tool_log = run_tools(root, tools, [w.path for w in ctx.workflows], artifacts_dir or (root.parent / "_artifacts"), progress)
    else:
        from .tools import ALL_TOOLS
        tool_log = [{"tool": t, "status": "skipped", "detail": "external tools disabled", "seconds": 0, "count": 0} for t in ALL_TOOLS]

    progress("Evaluating OWASP CI/CD rules")
    controls: list[dict] = []
    findings: list[FindingResult] = []
    for rid, cls in load_rules().items():
        rule = cls()
        try:
            outcome: RuleOutcome = rule.evaluate(ctx)
        except Exception as exc:  # noqa: BLE001 - one broken rule must not sink the assessment
            log.exception("rule %s failed", rid)
            outcome = RuleOutcome(Status.NOT_ASSESSED, note=f"Rule error: {type(exc).__name__}: {exc}")
            traceback.print_exc()
        findings.extend(outcome.findings)
        controls.append({
            "rule_id": rid, "category": cls.category, "category_name": CATEGORIES.get(cls.category, ""), "title": cls.title,
            "severity": cls.severity, "status": outcome.status.value, "note": outcome.note, "evidence": outcome.evidence[:20],
            "finding_count": len(outcome.findings), "data_sources": cls.data_sources,
        })

    # Organization-defined policies (policy-as-code) run against the same inventory the UI shows.
    inventory = build_inventory(ctx)
    custom = options.get("custom_policies") or []
    if custom:
        from .policies import evaluate_policies
        progress("Evaluating organization policies")
        p_controls, p_findings = evaluate_policies(custom, inventory)
        controls.extend(p_controls)
        findings.extend(p_findings)

    findings = _corroborate(findings)
    # Drop info-level noise from scoring but keep it as evidence.
    for f in findings:
        f.risk_score = score_finding(f, metadata.is_public)

    if sha_resolver:
        progress("Resolving action pins")
        cache: dict[tuple, str | None] = {}
        for f in findings:
            if f.rule_id == "PT-3P-001" and f.extra.get("action") and f.extra.get("ref"):
                owner_repo = "/".join(f.extra["action"].split("/")[:2])
                k = (owner_repo, f.extra["ref"])
                if k not in cache and len(cache) < 40:
                    try:
                        cache[k] = sha_resolver(*owner_repo.split("/", 1), f.extra["ref"])
                    except Exception:  # noqa: BLE001
                        cache[k] = None
                if cache.get(k):
                    f.extra["suggested_pin"] = f"{f.extra['action']}@{cache[k]} # {f.extra['ref']}"

    coverage_notes = []
    for o in build_inventory_notes(ctx):
        coverage_notes.append(o)

    summary = summarize(controls, findings)
    summary["coverage_notes"] = coverage_notes
    if custom:
        summary["policies_applied"] = [p.get("id") for p in custom]
    progress("Building attack graph")
    graph = build_attack_graph(ctx, findings)
    findings.sort(key=lambda f: (-f.risk_score, f.category, f.file_path, f.line or 0))
    sbom = (ctx.tool_results.get("syft") or {}).get("sbom_path")
    return AssessmentResult(inventory=inventory, controls=controls, findings=findings, tool_runs=tool_log, summary=summary,
                            attack_graph=graph, coverage_notes=coverage_notes, sbom_path=sbom,
                            workflow_sources={w.path: w.text for w in ctx.workflows if w.text})


def build_inventory_notes(ctx: ScanContext) -> list[str]:
    notes = []
    if not ctx.workflows:
        notes.append("No GitHub Actions workflows (.github/workflows/*.yml) were found - workflow controls are NOT APPLICABLE.")
    bad = [w.path for w in ctx.workflows if w.error]
    if bad:
        notes.append(f"{len(bad)} workflow file(s) could not be parsed and were excluded from detection: {', '.join(bad[:5])}.")
    for ci in detect_other_ci(ctx.files):
        notes.append(f"{ci['system']} configuration detected ({ci['file']}) - not supported by this connector; NOT ASSESSED.")
    comp = [f for f in ctx.files if f.endswith(("action.yml", "action.yaml")) and not f.startswith(".github/workflows/")]
    if comp:
        notes.append(f"{len(comp)} local action definition(s) found ({', '.join(comp[:3])}); their internals are analysed by zizmor only.")
    if ctx.metadata.source != "github":
        notes.append("Offline (ZIP) assessment: repository settings (branch protection, environments, token defaults, collaborators) are NOT ASSESSED.")
    else:
        for k, v in ctx.metadata.collected.items():
            if v.status in ("forbidden", "error") and k != "secret_metadata":  # rotation dates are optional
                notes.append(f"GitHub API `{k}`: {v.status} ({v.detail}) - dependent controls are NOT ASSESSED or need manual validation.")
    return notes
