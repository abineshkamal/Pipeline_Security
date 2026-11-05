"""CICD-SEC-10: Insufficient Logging and Visibility."""
from __future__ import annotations

import re

from ..model import Rule, RuleOutcome, Status, Workflow, WorkflowRule

AUDIT = "https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization"
STREAM = "https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise"

SCAN_RE = re.compile(r"github/codeql-action|actions/dependency-review-action|aquasecurity/trivy-action|\btrivy\s|snyk|semgrep|gitleaks|trufflehog|"
                     r"zizmor|checkov|kics|ossf/scorecard-action|anchore/scan-action|grype|bandit|sonarsource|sonarqube|bearer|osv-scanner|step-security/harden-runner", re.I)
SECURITY_STEP_RE = re.compile(r"codeql|trivy|snyk|semgrep|gitleaks|trufflehog|zizmor|checkov|kics|scorecard|grype|bandit|sonar|audit|dependency-review|osv-scanner|scan", re.I)


class AuditLogVisibility(Rule):
    id = "PT-LOG-001"
    category = "CICD-SEC-10"
    title = "CI/CD audit logs are centrally collected and retained"
    description = ("GitHub audit logs (workflow changes, secret access, runner registration, permission changes) must be "
                   "streamed to a SIEM and retained beyond the platform default. This is an organization/enterprise setting "
                   "that a repository-scoped token cannot read.")
    severity = "medium"
    cwe = ["CWE-778"]
    references = [AUDIT, STREAM]
    remediation = "Enable audit-log streaming to your SIEM, alert on workflow file changes, new self-hosted runners, secret changes and protection bypasses."
    evidence_requirements = "Organization/enterprise audit-log streaming configuration (manual)."
    false_positives = "Not assessable automatically - always requires manual validation."
    data_sources = ["manual"]

    def evaluate(self, ctx):
        return RuleOutcome(Status.NEEDS_MANUAL_VALIDATION, note=(
            "Requires organization owner/enterprise access. Verify: audit-log streaming enabled, retention >= 1 year, "
            "alerts on .github/workflows changes, runner registration and branch-protection bypass."))


class ShortRetention(WorkflowRule):
    id = "PT-LOG-002"
    category = "CICD-SEC-10"
    title = "Very short artifact / log retention"
    description = "Artifacts or logs are retained for only a few days, destroying the evidence needed to investigate a pipeline compromise."
    severity = "low"
    cwe = ["CWE-778"]
    references = ["https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/storing-and-sharing-data-from-a-workflow#configuring-a-custom-artifact-retention-period"]
    remediation = "Keep build artifacts and logs for at least 30-90 days (or export them to long-term storage)."
    evidence_requirements = "`retention-days` value below 7."
    false_positives = "Large ephemeral intermediates may intentionally use short retention; release artifacts should not."

    def check(self, ctx, wf: Workflow):
        out = []
        for job in wf.jobs:
            for s in job.steps:
                rd = s.with_.get("retention-days")
                try:
                    days = int(str(rd)) if rd is not None else None
                except ValueError:
                    days = None
                if days is not None and days < 7:
                    out.append(self.finding(f"`retention-days: {days}` on `{s.uses}` in job `{job.id}`.", wf=wf, job=job,
                                            line=s.with_line("retention-days"), key=f"{job.id}:{s.index}"))
        return out


class SilencedSecurityChecks(WorkflowRule):
    id = "PT-LOG-003"
    category = "CICD-SEC-10"
    title = "Security checks or workflow logging silenced"
    description = ("Security scanning steps are allowed to fail silently (`continue-on-error`, `|| true`), or workflow "
                   "command processing is stopped (`::stop-commands::`), hiding results and attacker activity from defenders.")
    severity = "medium"
    cwe = ["CWE-778", "CWE-223"]
    references = ["https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions#stopping-and-starting-workflow-commands"]
    remediation = "Make security checks blocking (or at least report results to code scanning); avoid stop-commands except around echoed untrusted content."
    evidence_requirements = "Security step with continue-on-error / `|| true`, or ::stop-commands:: line."
    false_positives = "Non-blocking scans that upload SARIF to code scanning still provide visibility - check for an upload step."

    def check(self, ctx, wf: Workflow):
        out = []
        sarif_upload = "upload-sarif" in wf.text
        for job in wf.jobs:
            for s in job.steps:
                label = f"{s.name} {s.uses or ''} {(s.run or '')[:200]}"
                if not SECURITY_STEP_RE.search(label):
                    continue
                coe = str(s.data.get("continue-on-error", "")).lower() == "true" or str(job.data.get("continue-on-error", "")).lower() == "true"
                ortrue = bool(s.run and re.search(r"\|\|\s*(true|exit\s+0|:)\s*$", s.run, re.M))
                if (coe or ortrue) and not sarif_upload:
                    out.append(self.finding(f"Security step `{s.name}` in job `{job.id}` cannot fail the build ({'continue-on-error' if coe else '|| true'}) and results are not uploaded.",
                                            wf=wf, job=job, line=s.key_line("continue-on-error") if coe else s.key_line("run"), key=f"{job.id}:{s.index}"))
        for i, line in enumerate(wf.lines, 1):
            if "::stop-commands::" in line:
                out.append(self.finding("`::stop-commands::` disables workflow command processing.", wf=wf, line=i, severity="low", key=f"stop:{i}"))
        return out


class NoSecurityScanning(Rule):
    id = "PT-LOG-004"
    category = "CICD-SEC-10"
    title = "No security scanning visibility in the pipeline"
    description = "None of the workflows run SAST, dependency, secret, or workflow security scanning, so vulnerabilities and malicious changes are not surfaced to defenders."
    severity = "low"
    cwe = ["CWE-778", "CWE-1068"]
    references = ["https://docs.github.com/en/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning", "https://github.com/ossf/scorecard"]
    remediation = "Add CodeQL (or Semgrep), dependency-review, secret scanning and a workflow linter (zizmor/actionlint) on pull requests."
    evidence_requirements = "Absence of known scanner actions/commands across all workflows."
    false_positives = "Scanning may run in an external CI system or via GitHub's default setup for code scanning (not visible in workflow files)."

    def evaluate(self, ctx):
        wfs = ctx.parsed_workflows
        if not wfs:
            return RuleOutcome(Status.NOT_APPLICABLE, note="No workflows.")
        for wf in wfs:
            m = SCAN_RE.search(wf.text)
            if m:
                return RuleOutcome(Status.PASS, evidence=[f"{wf.path}:{wf.find_line(m.group(0)) or 1} `{m.group(0).strip()}`"])
        return RuleOutcome(Status.FAIL, [self.finding("No security scanning step found in any workflow.", file_path=".github/workflows/",
                                                      evidence_type="inferred", confidence="medium", key="none",
                                                      snippet=f"{len(wfs)} workflow(s) inspected")])
