"""CICD-SEC-5: Insufficient Pipeline-Based Access Controls."""
from __future__ import annotations

from ..gha import (
    HIGH_IMPACT_WRITE, effective_job_permissions, external_triggers, normalize_permissions, privileged_external_triggers,
    write_scopes,
)
from ..model import GH_HARDENING, RuleOutcome, Status, Workflow, WorkflowRule, Rule

GH_TOKEN_PERMS = "https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token"


def _repo_default_is_read(ctx) -> bool | None:
    r = ctx.metadata.get("workflow_permissions")
    if r.status != "ok" or not isinstance(r.data, dict):
        return None
    return r.data.get("default_workflow_permissions") == "read"


class MissingPermissions(WorkflowRule):
    id = "PT-PBAC-001"
    category = "CICD-SEC-5"
    title = "Workflow does not declare GITHUB_TOKEN permissions"
    description = ("Without a `permissions:` block the GITHUB_TOKEN gets the repository/organization default, which is "
                   "write-all on older repositories and organizations. Explicit least-privilege permissions keep the "
                   "token's blast radius small if a step is compromised.")
    severity = "medium"
    cwe = ["CWE-250", "CWE-272"]
    references = [GH_TOKEN_PERMS]
    remediation = "Add `permissions: contents: read` at workflow level and grant extra scopes only on the jobs that need them."
    evidence_requirements = "Absence of `permissions:` at workflow level and in every job."
    false_positives = "If the repository default is read-only (verified via API) the effective risk is low."
    data_sources = ["workflows", "github_api"]

    def check(self, ctx, wf: Workflow):
        if wf.has_permissions_key:
            return []
        missing = [j for j in wf.jobs if not j.has_permissions_key and not j.uses]
        if not missing:
            return []
        default_read = _repo_default_is_read(ctx)
        sev = "low" if default_read else "medium" if default_read is False or external_triggers(wf) else "medium"
        note = ("Repository default token permission is read-only (API)" if default_read else
                "Repository default token permission is WRITE (API)" if default_read is False else
                "Repository default token permission could not be verified")
        return [self.finding(
            f"No workflow-level `permissions:` and {len(missing)} job(s) without their own ({', '.join(j.id for j in missing[:6])}). {note}.",
            wf=wf, line=1, severity=sev, evidence_type="configuration" if default_read is not None else "inferred",
            confidence="high" if default_read is not None else "medium", key="workflow",
            jobs=[j.id for j in missing], repo_default_read=default_read,
        )]


class ExcessivePermissions(WorkflowRule):
    id = "PT-PBAC-002"
    category = "CICD-SEC-5"
    title = "Excessive GitHub Actions workflow permissions"
    description = ("The workflow grants `write-all` or broad write scopes. Any compromised step, dependency or injected "
                   "command can then push code, publish packages, or modify releases.")
    severity = "high"
    cwe = ["CWE-250"]
    references = [GH_TOKEN_PERMS, GH_HARDENING]
    remediation = "Replace write-all with the specific scopes each job needs, declared at job level."
    evidence_requirements = "`permissions:` block granting write-all or 3+ write scopes, or write scopes on externally-triggered workflows."
    false_positives = "Release workflows legitimately need contents/packages write - scope them to the release job only."

    def check(self, ctx, wf: Workflow):
        out = []
        ext = external_triggers(wf)
        blocks = []
        if wf.has_permissions_key:
            blocks.append(("workflow", None, wf.permissions, wf.key_line("permissions")))
        for j in wf.jobs:
            if j.has_permissions_key:
                blocks.append(("job", j, j.permissions, j.key_line("permissions")))
        for level, job, perms, line in blocks:
            writes = write_scopes(perms)
            is_all = isinstance(perms, str) and perms.strip().lower() == "write-all"
            if not writes:
                continue
            reason = None
            sev = "medium"
            impactful = writes & HIGH_IMPACT_WRITE - {"attestations"}
            if is_all:
                reason, sev = "`write-all`", "high"
            elif job is not None and job.environment and not ext:
                continue  # job-scoped, environment-gated deployment permissions are the recommended pattern
            elif len(impactful) >= 3:
                reason, sev = f"{len(writes)} write scopes ({', '.join(sorted(writes))})", "medium"
            elif ext and writes & HIGH_IMPACT_WRITE:
                reason = f"write scopes {', '.join(sorted(writes))} on externally triggered workflow ({', '.join(sorted(ext))})"
                sev = "high" if privileged_external_triggers(wf) else "medium"
            if reason:
                out.append(self.finding(
                    f"{level.capitalize()}-level permissions grant {reason}" + (f" for job `{job.id}`" if job else "") + ".",
                    wf=wf, job=job, line=line, severity=sev, key=f"{level}:{job.id if job else ''}",
                    write_scopes=sorted(writes),
                ))
        return out


class ExcessiveDeploymentPermissions(WorkflowRule):
    id = "PT-PBAC-003"
    category = "CICD-SEC-5"
    title = "Deployment privileges granted to the whole workflow"
    description = ("High-impact scopes such as `id-token: write` (cloud OIDC federation), `packages: write`, "
                   "`deployments: write` or `contents: write` are declared at workflow level, so every job - including "
                   "build/test jobs running third-party code - receives them.")
    severity = "medium"
    cwe = ["CWE-250", "CWE-266"]
    references = [GH_TOKEN_PERMS]
    remediation = "Declare `permissions: {}` or read-only at workflow level and grant deployment scopes only to the deploy job."
    evidence_requirements = "Workflow-level permissions with deployment scopes and more than one job."
    false_positives = "Single-job workflows are not affected."

    def check(self, ctx, wf: Workflow):
        if not wf.has_permissions_key:
            return []
        writes = write_scopes(wf.permissions) & {"id-token", "packages", "deployments", "contents", "pages", "attestations"}
        inheriting = [j for j in wf.jobs if not j.has_permissions_key]
        if not writes or len(inheriting) < 2:
            return []
        return [self.finding(
            f"Workflow-level permissions grant {', '.join(sorted(writes))} write to {len(inheriting)} jobs "
            f"({', '.join(j.id for j in inheriting[:6])}).",
            wf=wf, line=wf.key_line("permissions"), key="workflow", write_scopes=sorted(writes),
            severity="high" if "id-token" in writes else "medium",
        )]


class SecretsInherit(WorkflowRule):
    id = "PT-PBAC-004"
    category = "CICD-SEC-5"
    title = "Reusable workflow called with `secrets: inherit`"
    description = "All of the caller's secrets are passed to the called workflow regardless of what it needs."
    severity = "medium"
    cwe = ["CWE-200"]
    references = ["https://docs.github.com/en/actions/sharing-automations/reusing-workflows#passing-inputs-and-secrets-to-a-reusable-workflow"]
    remediation = "Pass only the named secrets the reusable workflow requires under `secrets:`."
    evidence_requirements = "Job with `uses:` reusable workflow and `secrets: inherit`."
    false_positives = "Lower risk when the reusable workflow is in the same repository and pinned."

    def check(self, ctx, wf: Workflow):
        out = []
        for j in wf.jobs:
            if j.uses and str(j.data.get("secrets", "")).strip().lower() == "inherit":
                ext = not j.uses.startswith("./")
                out.append(self.finding(
                    f"Job `{j.id}` passes all secrets to `{j.uses}`.", wf=wf, job=j, line=j.key_line("secrets"),
                    severity="high" if ext and "@" in j.uses and len(j.uses.rsplit('@', 1)[1]) != 40 else "medium", key=j.id,
                ))
        return out


class RepoDefaultTokenWrite(Rule):
    id = "PT-PBAC-005"
    category = "CICD-SEC-5"
    title = "Repository default GITHUB_TOKEN permission is read/write"
    description = "Repository settings grant every workflow without a permissions block a read/write token, and may let Actions approve pull requests."
    severity = "medium"
    cwe = ["CWE-276"]
    references = [GH_TOKEN_PERMS]
    remediation = "Settings > Actions > General > Workflow permissions: select 'Read repository contents' and disable 'Allow GitHub Actions to create and approve pull requests'."
    evidence_requirements = "GET /repos/{owner}/{repo}/actions/permissions/workflow"
    false_positives = "None - this is a direct configuration read."
    data_sources = ["github_api"]

    def evaluate(self, ctx):
        r = ctx.metadata.get("workflow_permissions")
        if r.status != "ok":
            return RuleOutcome(Status.NOT_ASSESSED, note=f"Repository workflow permission settings unavailable: {r.detail or r.status}.")
        d = r.data or {}
        if d.get("default_workflow_permissions") == "write":
            return RuleOutcome(Status.FAIL, [self.finding(
                "Repository default workflow permissions are `write`.", file_path="(repository settings)", key="default",
                snippet=f"default_workflow_permissions: {d.get('default_workflow_permissions')}\ncan_approve_pull_request_reviews: {d.get('can_approve_pull_request_reviews')}")])
        return RuleOutcome(Status.PASS, evidence=[f"default_workflow_permissions = {d.get('default_workflow_permissions')}"])
