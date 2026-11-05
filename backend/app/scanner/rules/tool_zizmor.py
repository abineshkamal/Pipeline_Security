"""zizmor integration: independent static analysis of GitHub Actions.

zizmor findings that coincide with a built-in finding (same file, nearby line, same category) are attached to the
built-in finding as corroborating evidence by the engine; the rest are reported here under their mapped category.
"""
from __future__ import annotations

from ..model import Rule, RuleOutcome, Status
from ._util import tool_outcome

ZIZMOR_CATEGORY = {
    "template-injection": "CICD-SEC-4", "dangerous-triggers": "CICD-SEC-4", "github-env": "CICD-SEC-4",
    "unpinned-uses": "CICD-SEC-8", "unpinned-images": "CICD-SEC-8", "impostor-commit": "CICD-SEC-8",
    "known-vulnerable-actions": "CICD-SEC-8", "ref-confusion": "CICD-SEC-8", "stale-action-refs": "CICD-SEC-8",
    "forbidden-uses": "CICD-SEC-8", "archived-uses": "CICD-SEC-8",
    "excessive-permissions": "CICD-SEC-5", "secrets-inherit": "CICD-SEC-5", "undocumented-permissions": "CICD-SEC-5",
    "artipacked": "CICD-SEC-6", "hardcoded-container-credentials": "CICD-SEC-6", "overprovisioned-secrets": "CICD-SEC-6",
    "unredacted-secrets": "CICD-SEC-6", "secrets-outside-env": "CICD-SEC-6",
    "self-hosted-runner": "CICD-SEC-7", "insecure-commands": "CICD-SEC-7", "obfuscation": "CICD-SEC-7",
    "unsound-condition": "CICD-SEC-1", "bot-conditions": "CICD-SEC-1", "unsound-contains": "CICD-SEC-1",
    "cache-poisoning": "CICD-SEC-9", "use-trusted-publishing": "CICD-SEC-9",
    "anonymous-definition": "CICD-SEC-10", "concurrency-limits": "CICD-SEC-7",
    "dependabot-cooldown": "CICD-SEC-3", "dependabot-execution": "CICD-SEC-3", "self-repository": "CICD-SEC-8",
}
SEV = {"high": "high", "medium": "medium", "low": "low", "informational": "info", "unknown": "info"}


class ZizmorAudit(Rule):
    id = "PT-TOOL-ZIZMOR"
    category = "CICD-SEC-4"
    title = "zizmor GitHub Actions security audit"
    description = "Findings from the zizmor static analyzer not already covered by a built-in rule (mapped to OWASP CI/CD categories)."
    severity = "medium"
    references = ["https://docs.zizmor.sh/audits/"]
    remediation = "Follow the zizmor audit documentation for each finding."
    evidence_requirements = "zizmor finding with file and line."
    false_positives = "zizmor confidence is carried into the finding confidence."
    data_sources = ["tool:zizmor"]

    def evaluate(self, ctx):
        if not ctx.workflows:
            return RuleOutcome(Status.NOT_APPLICABLE, note="No workflows.")
        r, bad = tool_outcome(ctx, "zizmor")
        if bad:
            return bad
        out = []
        for f in r.get("findings", [])[:300]:
            ident = f.get("rule", "")
            fr = self.finding(f"zizmor [{ident}]: {f.get('message')}", file_path=f.get("file", ""), line=f.get("line"),
                              severity=SEV.get(f.get("severity", "unknown"), "low"), evidence_type="tool",
                              confidence={"high": "high", "medium": "medium"}.get(f.get("confidence", ""), "low"),
                              snippet=f.get("snippet", ""), key=f"{f.get('file')}:{f.get('line')}:{ident}", zizmor_rule=ident,
                              title=f"zizmor: {ident}")
            fr.category = ZIZMOR_CATEGORY.get(ident, "CICD-SEC-7")
            out.append(fr)
        res = self.outcome_from(out, pass_evidence="zizmor reported no findings.")
        if res.status == Status.FAIL and all(f.severity == "info" for f in out):
            res.status = Status.PASS
            res.evidence = [f"zizmor: {len(out)} informational finding(s) only."]
        return res
