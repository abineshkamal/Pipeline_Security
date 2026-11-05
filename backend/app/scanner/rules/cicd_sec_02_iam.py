"""CICD-SEC-2: Inadequate Identity and Access Management."""
from __future__ import annotations

import fnmatch

from ..model import Rule, RuleOutcome, Status

CODEOWNERS_DOCS = "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners"


def _codeowners_text(ctx) -> tuple[str, str] | None:
    for p in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
        if p in ctx.files:
            t = ctx.read_text(p)
            if t is not None:
                return p, t
    return None


def _covers(pattern: str, path: str) -> bool:
    pat = pattern.strip()
    if pat in ("*", "/*", "**", "/**"):
        return True
    pat = pat.lstrip("/")
    if pat.endswith("/"):
        pat += "**"
    if path.startswith(pat.rstrip("*").rstrip("/") + "/") and not any(c in pat.rstrip("*") for c in "*?["):
        return True
    return fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(path, pat + "/**") or fnmatch.fnmatch(path, "**/" + pat)


class CodeOwnersForPipelines(Rule):
    id = "PT-IAM-001"
    category = "CICD-SEC-2"
    title = "Pipeline definitions have no designated code owners"
    description = ("No CODEOWNERS entry covers `.github/workflows/`, so changes to pipeline definitions - the most "
                   "privileged code in the repository - do not require approval from an accountable owner.")
    severity = "medium"
    cwe = ["CWE-284"]
    references = [CODEOWNERS_DOCS]
    remediation = "Add `/.github/ @org/security-team` (or similar) to CODEOWNERS and enable 'Require review from Code Owners'."
    evidence_requirements = "CODEOWNERS file content, or its absence."
    false_positives = "Code owner review only has effect when branch protection requires it."
    data_sources = ["repo_files"]

    def evaluate(self, ctx):
        if not ctx.workflows:
            return RuleOutcome(Status.NOT_APPLICABLE, note="No workflows in repository.")
        co = _codeowners_text(ctx)
        if co is None:
            return RuleOutcome(Status.FAIL, [self.finding("No CODEOWNERS file found.", file_path=".github/CODEOWNERS", key="missing",
                                                          snippet="(file not present)")])
        path, text = co
        target = ".github/workflows/ci.yml"
        owner_line = None
        for i, raw in enumerate(text.splitlines(), 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2 and _covers(parts[0], target):
                owner_line = (i, raw)  # last match wins in CODEOWNERS semantics
            elif len(parts) == 1 and _covers(parts[0], target):
                owner_line = None  # pattern with no owners removes ownership
        if owner_line:
            return RuleOutcome(Status.PASS, evidence=[f"{path}:{owner_line[0]} `{owner_line[1].strip()}` covers .github/workflows/"])
        return RuleOutcome(Status.FAIL, [self.finding(
            f"{path} exists but no rule assigns owners to `.github/workflows/`.", file_path=path, line=1, key="uncovered",
            snippet="\n".join(text.splitlines()[:8]))])


class AdminSprawl(Rule):
    id = "PT-IAM-002"
    category = "CICD-SEC-2"
    title = "Excessive administrative access to the repository"
    description = "Many identities hold admin rights, each of which can disable protections, change secrets, or modify workflows."
    severity = "medium"
    cwe = ["CWE-269"]
    references = ["https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/repository-roles-for-an-organization"]
    remediation = "Limit admin to a small group (ideally via a team), review access quarterly, and remove stale or outside collaborators with elevated roles."
    evidence_requirements = "GET /repos/{owner}/{repo}/collaborators with permissions (requires push access)."
    false_positives = "Threshold (more than 3 admins) is a heuristic; small teams may legitimately share admin."
    data_sources = ["github_api"]

    def evaluate(self, ctx):
        r = ctx.metadata.get("collaborators")
        if r.status != "ok":
            return RuleOutcome(Status.NOT_ASSESSED, note=f"Collaborator list unavailable: {r.detail or r.status} (needs push access).")
        admins = [c for c in (r.data or []) if (c.get("permissions") or {}).get("admin")]
        names = ", ".join(c.get("login", "?") for c in admins[:10])
        if len(admins) > 3:
            return RuleOutcome(Status.FAIL, [self.finding(
                f"{len(admins)} identities have admin on the repository ({names}).", file_path="(repository settings)",
                key="admins", snippet=f"admins: {names}", evidence_type="configuration")])
        return RuleOutcome(Status.PASS, evidence=[f"{len(admins)} admin(s): {names or 'none'}"])


class OrgAuthentication(Rule):
    id = "PT-IAM-003"
    category = "CICD-SEC-2"
    title = "Organization does not enforce two-factor authentication"
    description = "Accounts without 2FA/SSO are the most common entry point to CI/CD systems."
    severity = "high"
    cwe = ["CWE-308"]
    references = ["https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization"]
    remediation = "Require 2FA (and SAML SSO where available) for all organization members and outside collaborators; remove stale identities."
    evidence_requirements = "GET /orgs/{org} `two_factor_requirement_enabled` (only visible to organization owners)."
    false_positives = "Field is hidden from non-owners; result is then NEEDS MANUAL VALIDATION."
    data_sources = ["github_api"]

    def evaluate(self, ctx):
        md = ctx.metadata
        if md.source != "github":
            return RuleOutcome(Status.NOT_ASSESSED, note="Requires a GitHub connection.")
        if md.owner_type != "Organization":
            return RuleOutcome(Status.NEEDS_MANUAL_VALIDATION, note="Repository is user-owned; verify the owner account uses 2FA / passkeys.")
        r = md.get("org")
        val = (r.data or {}).get("two_factor_requirement_enabled") if r.status == "ok" else None
        if val is None:
            return RuleOutcome(Status.NEEDS_MANUAL_VALIDATION, note="2FA requirement is only visible to organization owners. Verify manually.")
        if val:
            return RuleOutcome(Status.PASS, evidence=["two_factor_requirement_enabled: true"])
        return RuleOutcome(Status.FAIL, [self.finding("Organization does not require two-factor authentication.",
                                                      file_path="(organization settings)", key="2fa",
                                                      snippet="two_factor_requirement_enabled: false")])
