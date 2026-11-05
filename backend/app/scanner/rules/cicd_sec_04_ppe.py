"""CICD-SEC-4: Poisoned Pipeline Execution."""
from __future__ import annotations

from ..gha import (
    HIGH_IMPACT_WRITE, PRIVILEGED_EXTERNAL_TRIGGERS, effective_job_permissions, external_triggers, job_is_gated, job_secret_names,
    privileged_external_triggers, step_executes_code, untrusted_checkout, untrusted_expressions, write_scopes,
)
from ..model import GH_HARDENING, RuleOutcome, Status, Workflow, WorkflowRule

GHSL_PWN = "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"
GHSL_INJ = "https://securitylab.github.com/resources/github-actions-untrusted-input/"


class PrivilegedTriggerUntrustedCheckout(WorkflowRule):
    id = "PT-PPE-001"
    category = "CICD-SEC-4"
    title = "Privileged trigger checks out and runs untrusted pull request code"
    description = ("Workflows triggered by pull_request_target, workflow_run or issue_comment run in the base repository "
                   "context with access to secrets and a write-capable GITHUB_TOKEN. Checking out the PR head and then "
                   "building or running it lets any fork author execute code with those privileges ('pwn request').")
    severity = "critical"
    cwe = ["CWE-829", "CWE-94"]
    references = [GHSL_PWN, GH_HARDENING]
    remediation = ("Use the `pull_request` trigger for building untrusted code. If pull_request_target is required, never "
                   "check out `github.event.pull_request.head.*`; split into an unprivileged `pull_request` build and a "
                   "privileged `workflow_run` consumer that treats artifacts as data. Gate with a protected environment.")
    evidence_requirements = "Trigger declaration + checkout step whose ref resolves to PR-controlled code + subsequent code execution."
    false_positives = "Jobs gated by a maintainer-applied label or protected environment still need manual review of the gate."

    def check(self, ctx, wf: Workflow):
        trig = privileged_external_triggers(wf) - {"issues", "discussion", "discussion_comment"}
        if not trig:
            return []
        out = []
        for job in wf.jobs:
            hit = untrusted_checkout(job)
            if not hit:
                continue
            step, reason = hit
            later_exec = [s for s in job.steps[step.index + 1:] if step_executes_code(s)]
            gate = job_is_gated(job, wf)
            sev = "critical" if later_exec and not gate else "high" if later_exec else "medium"
            secrets = sorted(job_secret_names(job))
            perms, _src = effective_job_permissions(wf, job)
            out.append(self.finding(
                f"Job `{job.id}` runs on `{', '.join(sorted(trig))}` and checks out untrusted code ({reason})"
                + (f", then executes {len(later_exec)} step(s)" if later_exec else "")
                + (f". Mitigating gate: {gate}" if gate else "") + ".",
                wf=wf, job=job, line=step.line, severity=sev, confidence="high" if later_exec else "medium",
                evidence_type="configuration", key=f"{job.id}:{step.index}",
                triggers=sorted(trig), secrets=secrets, write_scopes=sorted(write_scopes(perms)) if perms is not None else ["(default)"],
                gate=gate, code_execution=bool(later_exec),
            ))
        return out


class PrivilegedTriggerUsage(WorkflowRule):
    id = "PT-PPE-002"
    category = "CICD-SEC-4"
    title = "Unsafe pull_request_target / privileged trigger usage"
    description = ("pull_request_target and workflow_run expose secrets and write tokens to events created by outside "
                   "contributors. Even without an explicit head checkout, use of PR data, caches or artifacts in these "
                   "workflows frequently leads to PPE.")
    severity = "medium"
    cwe = ["CWE-863"]
    references = [GHSL_PWN]
    remediation = ("Prefer `pull_request`. Where pull_request_target is unavoidable keep the job minimal (labelling, "
                   "commenting), set `permissions:` to the minimum, avoid secrets, and never execute PR content.")
    evidence_requirements = "Trigger declaration in the workflow `on:` block."
    false_positives = "Common, legitimate uses (auto-labelers) are low risk when the job never touches PR content."

    def evaluate(self, ctx):
        wfs = ctx.parsed_workflows
        if not wfs:
            return RuleOutcome(Status.NOT_APPLICABLE, note="No workflows.")
        findings = []
        for wf in wfs:
            trig = set(wf.triggers) & {"pull_request_target", "workflow_run"}
            if not trig:
                continue
            uses_head = any(untrusted_checkout(j) for j in wf.jobs)
            if uses_head:
                continue  # covered by PT-PPE-001
            secrets = sorted({s for j in wf.jobs for s in job_secret_names(j)})
            writes = sorted({s for j in wf.jobs for s in write_scopes(effective_job_permissions(wf, j)[0])})
            default_perms = any(effective_job_permissions(wf, j)[0] is None for j in wf.jobs)
            sev = "medium" if (secrets or writes or default_perms) else "low"
            line = wf.key_line("on") or 1
            findings.append(self.finding(
                f"Workflow uses privileged trigger(s) {', '.join(sorted(trig))}"
                + (f"; secrets in scope: {', '.join(secrets)}" if secrets else "")
                + (f"; write scopes: {', '.join(writes)}" if writes else "")
                + ("; some jobs inherit default token permissions" if default_perms else "") + ".",
                wf=wf, line=wf.find_line(next(iter(trig)), start=line) or line, severity=sev, confidence="medium",
                evidence_type="inferred", key=",".join(sorted(trig)), triggers=sorted(trig), secrets=secrets,
            ))
        if not findings:
            return RuleOutcome(Status.PASS, evidence=["No pull_request_target/workflow_run workflows without head checkout."])
        return RuleOutcome(Status.NEEDS_MANUAL_VALIDATION if all(f.severity == "low" for f in findings) else Status.FAIL, findings)


class ScriptInjection(WorkflowRule):
    id = "PT-PPE-003"
    category = "CICD-SEC-4"
    title = "Script injection from untrusted event data"
    description = ("Attacker-controlled values such as issue titles, PR bodies, branch names or commit messages are "
                   "interpolated with ${{ }} directly into `run:` scripts or github-script code. The expression is "
                   "expanded before the shell runs, so crafted input executes arbitrary commands in the runner.")
    severity = "high"
    cwe = ["CWE-78", "CWE-94"]
    references = [GHSL_INJ]
    remediation = ("Pass untrusted values through an environment variable (`env: TITLE: ${{ github.event.issue.title }}`) "
                   "and reference it as \"$TITLE\" in the script; never interpolate them into code.")
    evidence_requirements = "Exact `run:`/`script:` line containing the untrusted expression."
    false_positives = "Values that are validated earlier in the job are still unsafe because expansion happens before validation."

    def check(self, ctx, wf: Workflow):
        out = []
        ext = external_triggers(wf) | ({"push"} & set(wf.triggers))  # head_commit/commits are attacker-influenced on push from forks merged
        for job in wf.jobs:
            for step in job.steps:
                code = step.run
                key = "run"
                if code is None and (step.uses or "").lower().startswith("actions/github-script"):
                    code = str(step.with_.get("script", ""))
                    key = "script"
                if not code:
                    continue
                exprs = untrusted_expressions(code)
                if not exprs:
                    continue
                start = step.key_line(key) if key == "run" else step.with_line("script")
                for expr in dict.fromkeys(exprs):
                    line = wf.find_line(expr, start=start) or start
                    privileged = bool(set(wf.triggers) & PRIVILEGED_EXTERNAL_TRIGGERS)
                    sev = "critical" if privileged else "high" if ext else "medium"
                    out.append(self.finding(
                        f"`{expr}` is interpolated into a {'shell script' if key == 'run' else 'github-script'} in job `{job.id}`"
                        f" (triggers: {', '.join(sorted(wf.triggers)) or 'none'}).",
                        wf=wf, job=job, line=line, severity=sev, key=f"{job.id}:{step.index}:{expr}",
                        expression=expr, secrets=sorted(job_secret_names(job)), code_execution=True,
                    ))
        return out


class ArtifactPoisoning(WorkflowRule):
    id = "PT-PPE-004"
    category = "CICD-SEC-4"
    title = "workflow_run consumes artifacts from an untrusted run"
    description = ("A workflow_run workflow downloads artifacts produced by a pull_request run (attacker-controlled) and "
                   "then executes or extracts them in a privileged context.")
    severity = "high"
    cwe = ["CWE-345", "CWE-494"]
    references = [GHSL_PWN]
    remediation = ("Treat downloaded artifacts as untrusted data: extract to a temp dir outside the workspace, validate "
                   "content strictly, never execute it, and keep the consuming job's permissions minimal.")
    evidence_requirements = "workflow_run trigger + artifact download step + later code execution."
    false_positives = "Safe when the artifact is parsed as data only (e.g. a PR number validated as an integer)."

    def check(self, ctx, wf: Workflow):
        if "workflow_run" not in wf.triggers:
            return []
        out = []
        for job in wf.jobs:
            for step in job.steps:
                text = (step.uses or "") + "\n" + (step.run or "") + "\n" + str(step.with_.get("script", ""))
                if any(k in text for k in ("download-artifact", "dawidd6/action-download-artifact", "listWorkflowRunArtifacts", "gh run download")):
                    later = [s for s in job.steps[step.index + 1:] if step_executes_code(s)]
                    if later:
                        out.append(self.finding(
                            f"Job `{job.id}` downloads artifacts from the triggering run and executes {len(later)} step(s) afterwards.",
                            wf=wf, job=job, line=step.line, confidence="medium", evidence_type="inferred",
                            key=f"{job.id}:{step.index}", secrets=sorted(job_secret_names(job)), code_execution=True,
                        ))
                        break
        return out


class UnsafePullRequestExecution(WorkflowRule):
    id = "PT-PPE-005"
    category = "CICD-SEC-4"
    title = "Pull request code executed with secrets or write permissions"
    description = ("Jobs triggered by `pull_request` build and run code from the PR branch. Branches pushed inside the "
                   "repository (not forks) receive secrets and the configured token permissions, so anyone able to push "
                   "a branch can run arbitrary code with them without review (direct PPE).")
    severity = "medium"
    cwe = ["CWE-284"]
    references = [GH_HARDENING]
    remediation = ("Do not reference deployment secrets in pull_request jobs; set `permissions: contents: read`; move "
                   "privileged steps to post-merge (push to protected branch) workflows or environment-gated jobs.")
    evidence_requirements = "pull_request trigger + job executing code + secrets or write scopes in scope."
    false_positives = "Fork PRs do not receive secrets; the risk is from internal branches or compromised contributor accounts."

    def check(self, ctx, wf: Workflow):
        if "pull_request" not in wf.triggers:
            return []
        out = []
        for job in wf.jobs:
            if not any(step_executes_code(s) for s in job.steps):
                continue
            secrets = sorted(job_secret_names(job))
            perms, src = effective_job_permissions(wf, job)
            writes = sorted(write_scopes(perms) & HIGH_IMPACT_WRITE)
            if not secrets and not writes:
                continue
            if job.environment:
                continue  # environment gate handled under flow control
            out.append(self.finding(
                f"Job `{job.id}` executes pull request code with "
                + ", ".join(x for x in [f"secrets {', '.join(secrets)}" if secrets else "", f"write scopes {', '.join(writes)} ({src})" if writes else ""] if x) + ".",
                wf=wf, job=job, line=job.line, confidence="medium", evidence_type="inferred",
                severity="high" if ("id-token" in writes or "contents" in writes) and secrets else "medium",
                key=job.id, secrets=secrets, write_scopes=writes, code_execution=True,
            ))
        return out
