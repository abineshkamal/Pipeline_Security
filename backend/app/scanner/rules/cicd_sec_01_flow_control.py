"""CICD-SEC-1: Insufficient Flow Control Mechanisms."""
from __future__ import annotations

import re

from ..gha import job_deploy_indicators
from ..model import Rule, RuleOutcome, Status, Workflow, WorkflowRule

BP_DOCS = "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches"
RULESETS = "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets"
ENV_DOCS = "https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-deployments/managing-environments-for-deployment"


def _ruleset_rules(ctx) -> list[dict] | None:
    r = ctx.metadata.get("branch_rules")
    if r.status != "ok":
        return None
    return r.data if isinstance(r.data, list) else []


class BranchProtection(Rule):
    id = "PT-FC-001"
    category = "CICD-SEC-1"
    title = "Default branch is not protected"
    description = ("Without branch protection or rulesets, anyone with write access can push directly to the default "
                   "branch - and thus into every pipeline that builds or deploys from it - without review or checks.")
    severity = "high"
    cwe = ["CWE-284"]
    references = [BP_DOCS, RULESETS]
    remediation = "Protect the default branch (classic protection or a ruleset): require pull requests, status checks, and block force-pushes and deletion."
    evidence_requirements = "GitHub API: branch `protected` flag, classic protection settings and active rulesets."
    false_positives = "Protection enforced at organization level via rulesets is included in the branch rules endpoint."
    data_sources = ["github_api"]

    def evaluate(self, ctx):
        md = ctx.metadata
        if md.source != "github":
            return RuleOutcome(Status.NOT_ASSESSED, note="Branch protection requires a GitHub connection (not available for ZIP uploads).")
        branch = md.get("branch")
        rules = _ruleset_rules(ctx)
        if branch.status != "ok" and rules is None:
            return RuleOutcome(Status.NOT_ASSESSED, note=f"Branch metadata unavailable: {branch.detail or branch.status}.")
        protected = bool((branch.data or {}).get("protected")) if branch.status == "ok" else False
        rule_types = sorted({r.get("type", "") for r in (rules or [])})
        if protected or rule_types:
            ev = []
            if protected:
                ev.append(f"Branch `{md.default_branch}` has classic protection enabled.")
            if rule_types:
                ev.append(f"Active ruleset rules: {', '.join(rule_types)}.")
            blocks_force = protected or "non_fast_forward" in rule_types
            if not blocks_force:
                return RuleOutcome(Status.FAIL, [self.finding(
                    f"Default branch `{md.default_branch}` has rulesets ({', '.join(rule_types)}) but force-pushes are not blocked.",
                    file_path="(repository settings)", severity="medium", key="force-push",
                    snippet="\n".join(ev))], evidence=ev)
            return RuleOutcome(Status.PASS, evidence=ev)
        return RuleOutcome(Status.FAIL, [self.finding(
            f"Default branch `{md.default_branch}` has no branch protection and no active rulesets.",
            file_path="(repository settings)", key="unprotected",
            snippet=f"GET /repos/{md.full_name}/branches/{md.default_branch} -> protected: false\nGET /repos/{md.full_name}/rules/branches/{md.default_branch} -> []")])


class RequiredReviews(Rule):
    id = "PT-FC-002"
    category = "CICD-SEC-1"
    title = "Required pull request reviews are not enforced"
    description = ("Code can reach the default branch - and the pipeline - with zero independent approvals, so a single "
                   "compromised or malicious account can ship changes.")
    severity = "high"
    cwe = ["CWE-284", "CWE-1220"]
    references = [BP_DOCS, RULESETS]
    remediation = ("Require at least one (ideally two for production repos) approving review, dismiss stale approvals, "
                   "require Code Owner review for `.github/workflows/**`, and do not allow administrators to bypass.")
    evidence_requirements = "Ruleset `pull_request` rule or classic protection `required_pull_request_reviews`."
    false_positives = "Classic protection details require admin access; with a read-only token this may be NEEDS MANUAL VALIDATION."
    data_sources = ["github_api"]

    def evaluate(self, ctx):
        md = ctx.metadata
        if md.source != "github":
            return RuleOutcome(Status.NOT_ASSESSED, note="Requires a GitHub connection.")
        rules = _ruleset_rules(ctx) or []
        pr_rules = [r for r in rules if r.get("type") == "pull_request"]
        ev = []
        best = 0
        for r in pr_rules:
            p = r.get("parameters") or {}
            best = max(best, int(p.get("required_approving_review_count") or 0))
            ev.append(f"ruleset pull_request: approvals={p.get('required_approving_review_count')}, "
                      f"dismiss_stale={p.get('dismiss_stale_reviews_on_push')}, code_owner_review={p.get('require_code_owner_review')}")
        prot = md.get("branch_protection")
        if prot.status == "ok" and isinstance(prot.data, dict):
            rpr = prot.data.get("required_pull_request_reviews")
            if rpr:
                best = max(best, int(rpr.get("required_approving_review_count") or 0))
                ev.append(f"classic protection: approvals={rpr.get('required_approving_review_count')}, "
                          f"dismiss_stale={rpr.get('dismiss_stale_reviews')}, code_owners={rpr.get('require_code_owner_reviews')}, "
                          f"enforce_admins={(prot.data.get('enforce_admins') or {}).get('enabled')}")
        if best >= 1:
            return RuleOutcome(Status.PASS, evidence=ev)
        branch = md.get("branch")
        is_protected = branch.status == "ok" and (branch.data or {}).get("protected")
        if is_protected and prot.status == "forbidden" and not pr_rules:
            return RuleOutcome(Status.NEEDS_MANUAL_VALIDATION, note=(
                "Branch is protected but its review settings need admin access to read. Verify required reviews manually."))
        if branch.status != "ok" and not rules:
            return RuleOutcome(Status.NOT_ASSESSED, note="Branch metadata unavailable.")
        return RuleOutcome(Status.FAIL, [self.finding(
            f"No rule requires an approving review before merging into `{md.default_branch}`.",
            file_path="(repository settings)", key="reviews", snippet="\n".join(ev) or "no pull_request rule / required reviews found")])


class DeploymentWithoutEnvironment(WorkflowRule):
    id = "PT-FC-003"
    category = "CICD-SEC-1"
    title = "Deployment job without environment protection"
    description = ("Jobs that deploy or publish do not use a GitHub `environment`, or use one with no required reviewers "
                   "or branch policy, so any code that reaches the workflow can deploy to production unattended.")
    severity = "medium"
    cwe = ["CWE-284"]
    references = [ENV_DOCS]
    remediation = ("Add `environment: production` to deploy jobs and configure required reviewers, wait timer and "
                   "deployment branch policy (protected branches only) for that environment; store deploy secrets as environment secrets.")
    evidence_requirements = "Job deploy indicators (actions/commands) + absent `environment:` or API showing no protection rules."
    false_positives = "Deploy detection is heuristic (job names, known deploy actions/commands); verify the job truly deploys."
    data_sources = ["workflows", "github_api"]

    def check(self, ctx, wf: Workflow):
        out = []
        env_api = ctx.metadata.get("environments")
        env_map = {}
        if env_api.status == "ok" and isinstance(env_api.data, list):
            env_map = {e.get("name"): e for e in env_api.data}
        for job in wf.jobs:
            ind = job_deploy_indicators(job)
            if not ind:
                continue
            if not job.environment:
                out.append(self.finding(
                    f"Job `{job.id}` appears to deploy ({'; '.join(ind[:3])}) but declares no `environment:`.",
                    wf=wf, job=job, line=job.line, confidence="medium", evidence_type="inferred", key=job.id, indicators=ind))
                continue
            env_name = re.sub(r"\$\{\{.*?\}\}", "*", job.environment)
            if env_map and env_name in env_map:
                rules = env_map[env_name].get("protection_rules") or []
                types = {r.get("type") for r in rules}
                policy = env_map[env_name].get("deployment_branch_policy")
                if not ({"required_reviewers", "wait_timer"} & types) and not policy:
                    out.append(self.finding(
                        f"Job `{job.id}` deploys to environment `{env_name}`, which has no required reviewers, wait timer or branch policy.",
                        wf=wf, job=job, line=job.key_line("environment"), key=f"{job.id}:{env_name}",
                        evidence_type="configuration", indicators=ind))
        return out


class WorkflowsCanApprove(WorkflowRule):
    id = "PT-FC-004"
    category = "CICD-SEC-1"
    title = "Pipeline can approve or force-merge changes"
    description = ("A workflow auto-approves pull requests, merges with admin override, or the repository allows GitHub "
                   "Actions to approve pull requests - letting automation bypass the human review gate.")
    severity = "medium"
    cwe = ["CWE-284"]
    references = [BP_DOCS]
    remediation = "Remove auto-approval automation for human-authored changes; disable 'Allow GitHub Actions to create and approve pull requests'."
    evidence_requirements = "Auto-approve action usage, `gh pr merge --admin`/`gh pr review --approve`, or repository setting via API."
    false_positives = "Dependabot auto-merge limited to patch updates and gated on checks is a common, accepted pattern - review conditions."
    data_sources = ["workflows", "github_api"]

    def evaluate(self, ctx):
        res = super().evaluate(ctx)
        wp = ctx.metadata.get("workflow_permissions")
        if wp.status == "ok" and (wp.data or {}).get("can_approve_pull_request_reviews"):
            res.findings.append(self.finding(
                "Repository setting allows GitHub Actions to create and approve pull requests.",
                file_path="(repository settings)", key="setting", snippet="can_approve_pull_request_reviews: true"))
            res.status = Status.FAIL
        return res

    def check(self, ctx, wf: Workflow):
        out = []
        for job in wf.jobs:
            for s in job.steps:
                u = (s.uses or "").lower()
                r = s.run or ""
                if "auto-approve" in u or re.search(r"gh\s+pr\s+review\s+.*--approve|gh\s+pr\s+merge\s+.*--admin", r):
                    out.append(self.finding(
                        f"Step `{s.name}` in job `{job.id}` approves or admin-merges pull requests automatically.",
                        wf=wf, job=job, line=s.line, key=f"{job.id}:{s.index}",
                        severity="low" if "dependabot" in (job.if_cond + str(s.data.get('if', ''))).lower() else "medium"))
        return out
