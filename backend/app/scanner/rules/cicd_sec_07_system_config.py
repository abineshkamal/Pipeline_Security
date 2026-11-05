"""CICD-SEC-7: Insecure System Configuration."""
from __future__ import annotations

import re

from ..gha import EXTERNAL_TRIGGERS, is_self_hosted
from ..model import GH_HARDENING, Rule, RuleOutcome, Status, Workflow, WorkflowRule
from ._util import tool_outcome, tools_outcome

SH_RUNNERS = "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#hardening-for-self-hosted-runners"


class SelfHostedRunnerExposure(WorkflowRule):
    id = "PT-SYS-001"
    category = "CICD-SEC-7"
    title = "Self-hosted runner exposed to untrusted workflows"
    description = ("Jobs triggered by pull requests or other external events run on self-hosted runners. Fork code then "
                   "executes on your infrastructure, which is usually non-ephemeral and network-trusted: an attacker can "
                   "persist on the runner, steal other jobs' secrets, or pivot into the internal network.")
    severity = "high"
    cwe = ["CWE-250", "CWE-653"]
    references = [SH_RUNNERS]
    remediation = ("Use GitHub-hosted or ephemeral, isolated (just-in-time) self-hosted runners for untrusted triggers; "
                   "restrict runner groups to specific repositories/workflows; require approval for fork PR workflows.")
    evidence_requirements = "`runs-on` includes self-hosted (or a runner group) in a workflow with external triggers."
    false_positives = "Private repositories with no outside collaborators and fork workflows disabled have much lower exposure."

    def check(self, ctx, wf: Workflow):
        ext = set(wf.triggers) & EXTERNAL_TRIGGERS
        out = []
        for job in wf.jobs:
            if not is_self_hosted(job):
                continue
            public = ctx.metadata.is_public
            if ext:
                sev = "critical" if public and ext & {"pull_request", "pull_request_target"} else "high" if public is not False else "medium"
                out.append(self.finding(
                    f"Job `{job.id}` runs on `{', '.join(job.runs_on)}` and is triggered by {', '.join(sorted(ext))}"
                    + (" in a public repository" if public else "") + ".",
                    wf=wf, job=job, line=job.key_line("runs-on"), severity=sev, key=job.id, runner=job.runs_on))
            else:
                out.append(self.finding(
                    f"Job `{job.id}` uses self-hosted runner `{', '.join(job.runs_on)}` (trusted triggers only) - verify runner is ephemeral and isolated.",
                    wf=wf, job=job, line=job.key_line("runs-on"), severity="info", evidence_type="inferred",
                    confidence="low", key=job.id, runner=job.runs_on))
        return out

    def evaluate(self, ctx):
        res = super().evaluate(ctx)
        if res.status == Status.FAIL and all(f.severity == "info" for f in res.findings):
            res.status = Status.NEEDS_MANUAL_VALIDATION
        return res


DANGEROUS = [
    (re.compile(r"ACTIONS_ALLOW_UNSECURE_COMMANDS\s*:\s*['\"]?true", re.I), "`ACTIONS_ALLOW_UNSECURE_COMMANDS` re-enables deprecated set-env/add-path commands (environment injection)", "high"),
    (re.compile(r"--privileged\b"), "container started with `--privileged`", "high"),
    (re.compile(r"/var/run/docker\.sock"), "Docker socket mounted into a job container (host takeover)", "high"),
    (re.compile(r"--(network|net)[ =]host\b|--pid[ =]host\b"), "container shares host network/PID namespace", "medium"),
    (re.compile(r"--cap-add[ =](ALL|SYS_ADMIN)\b", re.I), "container granted broad Linux capabilities", "medium"),
    (re.compile(r"chmod\s+(-R\s+)?777\s+/(?!tmp)"), "world-writable permissions on system paths", "low"),
    (re.compile(r"(setenforce\s+0|ufw\s+disable|iptables\s+-F)"), "host security controls disabled", "medium"),
]


class DangerousRunnerConfig(WorkflowRule):
    id = "PT-SYS-002"
    category = "CICD-SEC-7"
    title = "Insecure runner or job container configuration"
    description = "The workflow enables settings that weaken runner isolation or GitHub's command-injection protections."
    severity = "high"
    cwe = ["CWE-250", "CWE-16"]
    references = [GH_HARDENING, "https://github.blog/changelog/2020-10-01-github-actions-deprecating-set-env-and-add-path-commands/"]
    remediation = "Remove privileged container options and docker.sock mounts; use rootless builders (buildkit, kaniko); never set ACTIONS_ALLOW_UNSECURE_COMMANDS."
    evidence_requirements = "Exact line containing the dangerous option."
    false_positives = "Docker-in-docker build jobs sometimes require privilege - isolate them on dedicated ephemeral runners."

    def check(self, ctx, wf: Workflow):
        out = []
        for i, line in enumerate(wf.lines, 1):
            if line.lstrip().startswith("#"):
                continue
            for rx, desc, sev in DANGEROUS:
                if rx.search(line):
                    out.append(self.finding(desc[0].upper() + desc[1:] + ".", wf=wf, line=i, severity=sev, key=f"{i}:{desc[:20]}"))
        return out


class WorkflowLint(Rule):
    id = "PT-SYS-003"
    category = "CICD-SEC-7"
    title = "Workflow static analysis issues (actionlint)"
    description = "actionlint found errors such as invalid expressions, unknown inputs, shell issues or type mismatches that can make security controls silently ineffective."
    severity = "low"
    cwe = ["CWE-1164"]
    references = ["https://github.com/rhysd/actionlint"]
    remediation = "Fix the reported issues; run actionlint in CI on changes to .github/workflows."
    evidence_requirements = "actionlint diagnostic with file and line."
    false_positives = "Style-level diagnostics are reported as low/info."
    data_sources = ["tool:actionlint"]

    def evaluate(self, ctx):
        if not ctx.workflows:
            return RuleOutcome(Status.NOT_APPLICABLE, note="No workflows.")
        r, bad = tool_outcome(ctx, "actionlint")
        if bad:
            return bad
        out = []
        sec_kinds = {"expression", "credentials", "permissions", "deprecated-commands", "shell-name", "events", "runner-label"}
        for f in r.get("findings", [])[:200]:
            kind = f.get("rule", "")
            sev = "medium" if kind in {"credentials", "deprecated-commands", "permissions", "expression"} and ("untrusted" in f.get("message", "") or kind != "expression") else "low"
            if "potentially untrusted" in f.get("message", ""):
                sev = "high"
            out.append(self.finding(f"actionlint [{kind}]: {f.get('message')}", file_path=f.get("file", ""), line=f.get("line"),
                                    severity=sev if kind in sec_kinds or sev != "low" else "info", evidence_type="tool",
                                    snippet=f.get("snippet", ""), key=f"{f.get('file')}:{f.get('line')}:{kind}:{f.get('message', '')[:40]}"))
        res = self.outcome_from(out, pass_evidence="actionlint reported no issues.")
        if res.status == Status.FAIL and all(f.severity == "info" for f in out):
            res.status = Status.PASS
            res.evidence = [f"actionlint: {len(out)} informational diagnostics only."]
        return res


class UnparseableWorkflows(Rule):
    id = "PT-SYS-004"
    category = "CICD-SEC-7"
    title = "Workflow files could not be parsed"
    description = "Malformed workflow YAML cannot be assessed; GitHub will also refuse to run it or may run an older version."
    severity = "low"
    cwe = ["CWE-1164"]
    references = ["https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions"]
    remediation = "Fix the YAML syntax error and re-run the assessment."
    evidence_requirements = "Parser error with line number."
    false_positives = "None - but other rules have NOT assessed these files."
    data_sources = ["workflows"]

    def evaluate(self, ctx):
        if not ctx.workflows:
            return RuleOutcome(Status.NOT_APPLICABLE, note="No workflows.")
        bad = [w for w in ctx.workflows if w.error]
        if not bad:
            return RuleOutcome(Status.PASS, evidence=[f"All {len(ctx.workflows)} workflow file(s) parsed."])
        out = [self.finding(f"`{w.path}` is not a valid workflow: {w.error}. Other rules could not assess this file.",
                            wf=w, line=w.error_line or 1, key=w.path, evidence_type="configuration") for w in bad]
        return RuleOutcome(Status.NEEDS_MANUAL_VALIDATION, out, note="Coverage gap: these files were excluded from detection rules.")


class InfrastructureMisconfiguration(Rule):
    id = "PT-SYS-005"
    category = "CICD-SEC-7"
    title = "Pipeline infrastructure-as-code misconfiguration"
    description = "IaC scanners (Trivy config / Checkov / KICS) found misconfigurations in Dockerfiles, Kubernetes, Terraform or other build infrastructure."
    severity = "medium"
    cwe = ["CWE-16"]
    references = ["https://trivy.dev/latest/docs/scanner/misconfiguration/", "https://www.checkov.io/", "https://kics.io/"]
    remediation = "Apply the remediation suggested by the scanner for each check ID."
    evidence_requirements = "Scanner check ID, file and line."
    false_positives = "Development-only Dockerfiles and examples often trigger low-impact checks."
    data_sources = ["tool:trivy", "tool:checkov", "tool:kics"]

    def evaluate(self, ctx):
        ok, bad = tools_outcome(ctx, ["trivy", "checkov", "kics"])
        if bad:
            return bad
        out, seen = [], set()
        for tool, r in ok:
            for m in r.get("misconfigurations", [])[:300]:
                k = (m.get("file"), m.get("line"), m.get("id"))
                if k in seen:
                    continue
                seen.add(k)
                out.append(self.finding(f"{tool} {m.get('id')}: {m.get('title')}", file_path=m.get("file", ""), line=m.get("line"),
                                        severity=m.get("severity", "low"), evidence_type="tool", snippet=m.get("message", "")[:500],
                                        key="|".join(str(x) for x in k), tool=tool, check_id=m.get("id")))
        return self.outcome_from(out, pass_evidence=f"{', '.join(t for t, _ in ok)}: no misconfigurations.")
