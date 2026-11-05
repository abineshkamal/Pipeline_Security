"""CICD-SEC-6: Insufficient Credential Hygiene."""
from __future__ import annotations

import re

from ..gha import (
    PRIVILEGED_EXTERNAL_TRIGGERS, job_secret_names, untrusted_checkout,
)
from ..model import GH_HARDENING, EXPR_RE, Rule, RuleOutcome, Status, Workflow, WorkflowRule
from ._util import tools_outcome

SECRETS_DOCS = "https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions"
OIDC_DOCS = "https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect"

# High-signal credential patterns (subset of gitleaks defaults) - used even when gitleaks is unavailable.
SECRET_PATTERNS = [
    ("AWS access key id", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")),
    ("GitHub token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b")),
    ("GitHub fine-grained PAT", re.compile(r"\b(github_pat_[A-Za-z0-9_]{60,})\b")),
    ("Slack token", re.compile(r"\b(xox[abposr]-[A-Za-z0-9-]{10,})\b")),
    ("Slack webhook", re.compile(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)")),
    ("Google API key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b")),
    ("Private key", re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----)")),
    ("Stripe secret key", re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,})\b")),
    ("npm token", re.compile(r"\b(npm_[A-Za-z0-9]{36})\b")),
    ("PyPI token", re.compile(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})\b")),
    ("Generic credential assignment", re.compile(
        r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b\s*[:=]\s*['\"]?(?!\$\{\{|\$[A-Za-z_{(]|<|\*{3})([A-Za-z0-9/+_\-.!@#%^&]{12,})")),
]
PLACEHOLDER_RE = re.compile(r"(?i)(example|dummy|changeme|placeholder|xxxx|test|sample|your[_-]|redacted|\*\*\*)")


def redact(v: str) -> str:
    return v[:4] + "*" * max(4, len(v) - 8) + v[-4:] if len(v) > 10 else "****"


class HardcodedSecretsInPipelines(WorkflowRule):
    id = "PT-CRED-001"
    category = "CICD-SEC-6"
    title = "Hard-coded credential in pipeline definition"
    description = "A credential is embedded in a workflow file instead of being stored as an encrypted secret; anyone with read access can use it."
    severity = "critical"
    cwe = ["CWE-798"]
    references = [SECRETS_DOCS]
    remediation = "Revoke and rotate the credential immediately, remove it from history, and store it as an (environment-scoped) secret."
    evidence_requirements = "Matching pattern with exact line (value redacted in evidence)."
    false_positives = "Test fixtures and documented example values are filtered heuristically."

    def check(self, ctx, wf: Workflow):
        out = []
        for i, line in enumerate(wf.lines, 1):
            if line.lstrip().startswith("#"):
                continue
            for name, rx in SECRET_PATTERNS:
                m = rx.search(line)
                if not m:
                    continue
                val = m.group(1)
                if name == "Generic credential assignment" and (PLACEHOLDER_RE.search(val) or EXPR_RE.search(line)):
                    continue
                sev = "high" if name == "Generic credential assignment" else "critical"
                out.append(self.finding(f"{name} hard-coded in workflow.", wf=wf, line=i, severity=sev,
                                        snippet=f"{i:>4} | {line.replace(val, redact(val)).strip()}",
                                        confidence="medium" if name.startswith("Generic") else "high", key=f"{i}:{name}",
                                        secret_type=name))
                break
        return out


class SecretsInUntrustedContext(WorkflowRule):
    id = "PT-CRED-002"
    category = "CICD-SEC-6"
    title = "Secrets referenced in potentially untrusted contexts"
    description = ("Secrets are available to jobs triggered by events outside contributors control (pull_request_target, "
                   "issue_comment, workflow_run, ...) or to jobs that check out untrusted code. Any code execution "
                   "in that job can exfiltrate them.")
    severity = "high"
    cwe = ["CWE-200", "CWE-522"]
    references = [SECRETS_DOCS, GH_HARDENING]
    remediation = "Move secret-using steps to jobs triggered only by trusted events (push to protected branch, environment-gated deploy) and keep privileged-trigger jobs secret-free."
    evidence_requirements = "Secret reference inside a job of a privileged externally-triggered workflow."
    false_positives = "A secret used only by a pinned, first-party action with no untrusted input is lower risk."

    def check(self, ctx, wf: Workflow):
        priv = set(wf.triggers) & PRIVILEGED_EXTERNAL_TRIGGERS
        out = []
        for job in wf.jobs:
            names = job_secret_names(job)
            untrusted = untrusted_checkout(job)
            if not names or not (priv or untrusted):
                continue
            first = None
            for n in sorted(names):
                first = wf.find_line(f"secrets.{n}", start=job.line)
                if first:
                    break
            reason = f"privileged trigger(s) {', '.join(sorted(priv))}" if priv else "job checks out untrusted code"
            out.append(self.finding(
                f"Job `{job.id}` exposes secret(s) {', '.join(sorted(names))} under {reason}"
                + (" and checks out untrusted PR code" if untrusted and priv else "") + ".",
                wf=wf, job=job, line=first or job.line, severity="critical" if untrusted else "high",
                confidence="high" if untrusted else "medium", evidence_type="configuration" if untrusted else "inferred",
                key=job.id, secrets=sorted(names)))
        return out


class SecretExposurePatterns(WorkflowRule):
    id = "PT-CRED-003"
    category = "CICD-SEC-6"
    title = "Secrets exposed through bulk or inline usage"
    description = ("`toJSON(secrets)` hands every secret to a step; secrets interpolated directly into `run:` commands "
                   "appear in process arguments and can leak via logs, error output, or injected commands.")
    severity = "medium"
    cwe = ["CWE-532", "CWE-214"]
    references = [SECRETS_DOCS]
    remediation = "Pass only the specific secret needed, via `env:`, and reference it as an environment variable inside the script."
    evidence_requirements = "Exact line with toJSON(secrets) or ${{ secrets.X }} inside a run script."
    false_positives = "GitHub masks registered secrets in logs, but transformed values (base64, substrings) are not masked."

    def check(self, ctx, wf: Workflow):
        out = []
        for i, line in enumerate(wf.lines, 1):
            if re.search(r"toJSON\(\s*secrets\s*\)", line, re.I):
                out.append(self.finding("`toJSON(secrets)` exposes all repository secrets to one step.", wf=wf, line=i,
                                        severity="high", key=f"tojson:{i}"))
        for job in wf.jobs:
            for step in job.steps:
                if not step.run:
                    continue
                for m in EXPR_RE.finditer(step.run):
                    if re.search(r"secrets\.(?!GITHUB_TOKEN\b)", m.group(1)):
                        line = wf.find_line(m.group(0), start=step.key_line("run")) or step.key_line("run")
                        echo = bool(re.search(r"(echo|printf|cat|tee)\b[^\n]*" + re.escape(m.group(0)), step.run))
                        out.append(self.finding(
                            f"`{m.group(0)}` interpolated directly into a shell command in job `{job.id}`"
                            + (" and written to output" if echo else "") + ".",
                            wf=wf, job=job, line=line, severity="high" if echo else "low", key=f"{job.id}:{step.index}:{m.group(0)}"))
        return out


LONG_LIVED_INPUTS = {
    "aws-actions/configure-aws-credentials": ("aws-access-key-id", "aws-secret-access-key"),
    "azure/login": ("creds",),
    "google-github-actions/auth": ("credentials_json",),
    "docker/login-action": (),
}


class LongLivedCloudCredentials(WorkflowRule):
    id = "PT-CRED-004"
    category = "CICD-SEC-6"
    title = "Long-lived cloud credentials instead of OIDC federation"
    description = "Static cloud access keys stored as secrets never expire and work from anywhere if leaked; OIDC issues short-lived, scoped tokens per job."
    severity = "medium"
    cwe = ["CWE-324", "CWE-522"]
    references = [OIDC_DOCS]
    remediation = "Configure the cloud provider to trust GitHub's OIDC issuer (role-to-assume / workload identity federation) and remove the static keys."
    evidence_requirements = "Cloud auth action configured with static key inputs, or AWS key env vars sourced from secrets."
    false_positives = "Some providers do not support OIDC; then rotate keys frequently and scope them narrowly."

    def check(self, ctx, wf: Workflow):
        out = []
        for job in wf.jobs:
            for step in job.steps:
                u = (step.uses or "").lower().split("@")[0]
                for action, inputs in LONG_LIVED_INPUTS.items():
                    if u == action and any(k in step.with_ for k in inputs):
                        k = next(k for k in inputs if k in step.with_)
                        out.append(self.finding(f"`{step.uses}` authenticates with static credential input `{k}` in job `{job.id}`.",
                                                wf=wf, job=job, line=step.with_line(k), key=f"{job.id}:{step.index}"))
                env = wf.env_at(job, step)
                if "AWS_SECRET_ACCESS_KEY" in env and "secrets." in str(env["AWS_SECRET_ACCESS_KEY"]) and not any(f.job == job.id for f in out):
                    out.append(self.finding(f"Static `AWS_SECRET_ACCESS_KEY` from secrets used in job `{job.id}`.",
                                            wf=wf, job=job, line=wf.find_line("AWS_SECRET_ACCESS_KEY", start=job.line) or job.line,
                                            key=f"{job.id}:awsenv"))
        return out


class PersistedCheckoutCredentials(WorkflowRule):
    id = "PT-CRED-005"
    category = "CICD-SEC-6"
    title = "Checkout persists the GITHUB_TOKEN to disk"
    description = ("actions/checkout stores the token in .git/config unless `persist-credentials: false` is set. Later "
                   "steps (third-party actions, build scripts) can read it, and uploading the workspace as an artifact leaks it.")
    severity = "low"
    cwe = ["CWE-522", "CWE-538"]
    references = ["https://github.com/actions/checkout#usage", "https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/"]
    remediation = "Set `with: persist-credentials: false` on actions/checkout unless the job must push with git."
    evidence_requirements = "actions/checkout step without persist-credentials: false (and workspace artifact upload, which raises severity)."
    false_positives = "Jobs that push commits with git legitimately need persisted credentials."

    def check(self, ctx, wf: Workflow):
        out = []
        for job in wf.jobs:
            uploads_ws = any((s.uses or "").lower().startswith("actions/upload-artifact") and str(s.with_.get("path", "")).strip() in (".", "./", "${{ github.workspace }}", "**")
                             for s in job.steps)
            for s in job.steps:
                if (s.uses or "").lower().startswith("actions/checkout") and str(s.with_.get("persist-credentials", "true")).lower() != "false":
                    out.append(self.finding(
                        f"actions/checkout in job `{job.id}` persists credentials" + (" and the workspace is uploaded as an artifact" if uploads_ws else "") + ".",
                        wf=wf, job=job, line=s.line, severity="high" if uploads_ws else "low", key=f"{job.id}:{s.index}"))
        return out


class SecretsInRepository(Rule):
    id = "PT-CRED-006"
    category = "CICD-SEC-6"
    title = "Secrets committed to the repository"
    description = "Secret scanners (Gitleaks / TruffleHog) found credentials in repository files."
    severity = "high"
    cwe = ["CWE-798", "CWE-540"]
    references = ["https://github.com/gitleaks/gitleaks", "https://github.com/trufflesecurity/trufflehog"]
    remediation = "Rotate each exposed credential, purge it from git history, and enable push protection / pre-commit secret scanning."
    evidence_requirements = "Tool finding with file, line and redacted match."
    false_positives = "Test fixtures and example keys; TruffleHog runs without live verification by default (no network calls to providers)."
    data_sources = ["tool:gitleaks", "tool:trufflehog"]

    def evaluate(self, ctx):
        ok, bad = tools_outcome(ctx, ["gitleaks", "trufflehog"])
        if bad:
            return bad
        out, seen = [], set()
        for tool, r in ok:
            for f in r.get("findings", []):
                k = (f.get("file"), f.get("line"), f.get("rule"))
                if k in seen:
                    continue
                seen.add(k)
                test_path = bool(re.search(r"(?i)(test|spec|fixture|example|sample|mock)", f.get("file", "")))
                out.append(self.finding(
                    f"{tool}: {f.get('rule')} in `{f.get('file')}`" + (" (test/example path)" if test_path else "") + ".",
                    file_path=f.get("file", ""), line=f.get("line"), severity="medium" if test_path else ("critical" if f.get("verified") else "high"),
                    evidence_type="tool", confidence="medium" if test_path else "high", snippet=f.get("snippet", ""),
                    key=f"{f.get('file')}:{f.get('line')}:{f.get('rule')}", tool=tool))
        return self.outcome_from(out[:200], pass_evidence=f"{', '.join(t for t, _ in ok)}: no secrets detected.")
