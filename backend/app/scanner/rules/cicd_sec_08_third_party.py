"""CICD-SEC-8: Ungoverned Usage of Third-Party Services."""
from __future__ import annotations

import re

from ..gha import parse_uses
from ..model import Rule, RuleOutcome, Status, Workflow, WorkflowRule

PIN_DOCS = "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions"

# Actions with publicly documented supply-chain compromises (tags repointed to malicious commits).
KNOWN_COMPROMISED = {
    "tj-actions/changed-files": ("CVE-2025-30066 - all tags repointed to a secret-dumping commit (March 2025)",
                                 {"0e58ed8671d6b60d0890c21b07f8835ace038e67"}),
    "reviewdog/action-setup": ("CVE-2025-30154 - v1 tag repointed to a malicious commit (March 2025)", set()),
}


def _iter_uses(wf: Workflow):
    for job in wf.jobs:
        if job.uses:
            yield job, None, job.uses, job.key_line("uses")
        for s in job.steps:
            if s.uses:
                yield job, s, s.uses, s.key_line("uses")


class UnpinnedActions(WorkflowRule):
    id = "PT-3P-001"
    category = "CICD-SEC-8"
    title = "Third-party GitHub Action not pinned to a commit SHA"
    description = ("Tags and branches are mutable: whoever controls the action repository (or compromises it) can change "
                   "the code your pipeline runs, with your secrets and token. Only a full 40-character commit SHA is immutable.")
    severity = "medium"
    cwe = ["CWE-829", "CWE-494"]
    references = [PIN_DOCS]
    remediation = "Pin to the full commit SHA with the version as a comment (`uses: owner/action@<sha> # v4.2.1`) and let Dependabot/Renovate update the pins."
    evidence_requirements = "`uses:` reference with tag/branch ref."
    false_positives = "GitHub-owned actions (actions/*, github/*) are lower risk and reported as low."

    def check(self, ctx, wf: Workflow):
        out = []
        for job, step, uses, line in _iter_uses(wf):
            ref = parse_uses(uses)
            if not ref or ref.kind in ("local", "docker"):
                continue
            if ref.is_sha_pinned:
                continue
            if not ref.ref:
                sev, why = "high", "no ref at all"
            elif ref.looks_like_branch:
                sev, why = ("medium" if ref.is_first_party else "high"), f"branch `{ref.ref}`"
            else:
                sev, why = ("low" if ref.is_first_party else "medium"), f"tag `{ref.ref}`"
            out.append(self.finding(
                f"`{uses}` in job `{job.id}` is pinned to {why}" + (" (GitHub-owned)" if ref.is_first_party else " (third-party)") + ".",
                wf=wf, job=job, line=line, severity=sev, key=f"{job.id}:{uses}", action=ref.slug, ref=ref.ref,
                first_party=ref.is_first_party, reusable=ref.kind == "reusable"))
        return out


IMAGE_KEYS = ("container", "services")


class UnpinnedContainerImages(WorkflowRule):
    id = "PT-3P-002"
    category = "CICD-SEC-8"
    title = "Container image used without digest pinning"
    description = "Job containers, service containers and docker:// actions referenced by tag can be replaced upstream."
    severity = "low"
    cwe = ["CWE-494"]
    references = [PIN_DOCS]
    remediation = "Reference images by digest (`image@sha256:...`) and update digests through automation."
    evidence_requirements = "Image reference without @sha256 digest."
    false_positives = "Images from your own controlled registry with immutable tags are lower risk."

    def check(self, ctx, wf: Workflow):
        out = []
        for job in wf.jobs:
            images = []
            c = job.data.get("container")
            if isinstance(c, str):
                images.append(c)
            elif isinstance(c, dict) and c.get("image"):
                images.append(str(c["image"]))
            svcs = job.data.get("services")
            if isinstance(svcs, dict):
                for sv in svcs.values():
                    if isinstance(sv, dict) and sv.get("image"):
                        images.append(str(sv["image"]))
            for s in job.steps:
                if (s.uses or "").startswith("docker://"):
                    images.append(s.uses[len("docker://"):])
            for img in images:
                if "@sha256:" in img or "${{" in img:
                    continue
                tag = img.rsplit(":", 1)[1] if ":" in img.split("/")[-1] else "latest"
                out.append(self.finding(f"Image `{img}` in job `{job.id}` is referenced by tag `{tag}`.",
                                        wf=wf, job=job, line=wf.find_line(img, start=job.line) or job.line,
                                        severity="medium" if tag == "latest" else "low", key=f"{job.id}:{img}", image=img))
        return out


class AllowedActionsPolicy(Rule):
    id = "PT-3P-003"
    category = "CICD-SEC-8"
    title = "Repository allows any third-party action"
    description = "The Actions policy permits all actions and reusable workflows, so any contributor can introduce unreviewed third-party code into the pipeline."
    severity = "medium"
    cwe = ["CWE-829"]
    references = ["https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#allowing-select-actions-and-reusable-workflows-to-run"]
    remediation = "Set the policy to 'Allow select actions' with an allow-list of vetted actions (optionally require SHA pinning)."
    evidence_requirements = "GET /repos/{owner}/{repo}/actions/permissions (admin read)."
    false_positives = "Organization-level policy may already restrict actions; repository value then shows the effective setting."
    data_sources = ["github_api"]

    def evaluate(self, ctx):
        r = ctx.metadata.get("actions_permissions")
        if r.status != "ok":
            return RuleOutcome(Status.NOT_ASSESSED, note=f"Actions policy unavailable: {r.detail or r.status} (needs admin).")
        d = r.data or {}
        if not d.get("enabled", True):
            return RuleOutcome(Status.NOT_APPLICABLE, note="GitHub Actions disabled for this repository.")
        if d.get("allowed_actions") == "all":
            return RuleOutcome(Status.FAIL, [self.finding("Actions policy `allowed_actions: all`.", file_path="(repository settings)",
                                                          key="policy", snippet=f"allowed_actions: all\nsha_pinning_required: {d.get('sha_pinning_required')}")])
        return RuleOutcome(Status.PASS, evidence=[f"allowed_actions: {d.get('allowed_actions')}"])


class KnownCompromisedActions(WorkflowRule):
    id = "PT-3P-004"
    category = "CICD-SEC-8"
    title = "Use of an action with a known supply-chain compromise"
    description = "The workflow references an action whose tags were hijacked in a public incident."
    severity = "high"
    cwe = ["CWE-506", "CWE-829"]
    references = ["https://www.cve.org/CVERecord?id=CVE-2025-30066", "https://www.cve.org/CVERecord?id=CVE-2025-30154"]
    remediation = "Replace the action or pin a reviewed, known-good commit SHA; rotate any secrets exposed to runs during the incident window."
    evidence_requirements = "`uses:` reference to a listed action."
    false_positives = "A SHA pinned to a reviewed post-incident commit is safe (reported as info)."

    def check(self, ctx, wf: Workflow):
        out = []
        for job, step, uses, line in _iter_uses(wf):
            ref = parse_uses(uses)
            if not ref:
                continue
            key = f"{ref.owner}/{ref.repo}".lower()
            if key in KNOWN_COMPROMISED:
                why, bad_shas = KNOWN_COMPROMISED[key]
                if ref.ref in bad_shas:
                    sev = "critical"
                elif ref.is_sha_pinned:
                    sev = "info"
                else:
                    sev = "high"
                out.append(self.finding(f"`{uses}` - {why}.", wf=wf, job=job, line=line, severity=sev, key=f"{job.id}:{uses}"))
        return out


class ThirdPartyInventory(Rule):
    id = "PT-3P-005"
    category = "CICD-SEC-8"
    title = "Third-party action inventory requires governance review"
    description = "Lists every external action publisher. Whether each is approved is an organizational decision that cannot be inferred automatically."
    severity = "info"
    references = [PIN_DOCS]
    remediation = "Maintain an approved-actions list; review new publishers before use; prefer actions from verified creators."
    evidence_requirements = "Inventory of `uses:` references grouped by owner."
    false_positives = "Informational control."

    def evaluate(self, ctx):
        owners: dict[str, set[str]] = {}
        for wf in ctx.parsed_workflows:
            for _job, _s, uses, _l in _iter_uses(wf):
                ref = parse_uses(uses)
                if ref and ref.kind in ("action", "reusable") and not ref.is_first_party:
                    owners.setdefault(ref.owner, set()).add(f"{ref.owner}/{ref.repo}")
        if not ctx.parsed_workflows:
            return RuleOutcome(Status.NOT_APPLICABLE, note="No workflows.")
        if not owners:
            return RuleOutcome(Status.PASS, evidence=["Only GitHub-owned or local actions are used."])
        ev = [f"{o}: {', '.join(sorted(a))}" for o, a in sorted(owners.items())]
        return RuleOutcome(Status.NEEDS_MANUAL_VALIDATION, evidence=ev,
                           note=f"{sum(len(a) for a in owners.values())} third-party action(s) from {len(owners)} publisher(s) - confirm each is approved.")
