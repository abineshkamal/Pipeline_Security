"""Least-privilege GITHUB_TOKEN permissions per job, inferred from what the job's steps do.

Known actions map to the scopes they need (documented by their publishers); `run:` scripts are matched against
GitHub CLI / git / API usage. Anything that may use the token in a way we cannot see (github-script, unknown
actions that receive the token) lowers confidence and is listed for review rather than guessed.
"""
from __future__ import annotations

import re

from ..scanner.gha import parse_uses

LEVEL = {"none": 0, "read": 1, "write": 2}
SAFE_TRIGGERS = {"workflow_dispatch", "schedule", "push", "workflow_call", "release", "repository_dispatch"}

# action (owner/repo[/path], lowercase) -> (scopes, note). Scopes needed with the default GITHUB_TOKEN.
KNOWN: dict[str, tuple[dict[str, str], str]] = {
    "actions/checkout": ({"contents": "read"}, "clone the repository"),
    "actions/setup-node": ({}, ""), "actions/setup-python": ({}, ""), "actions/setup-java": ({}, ""), "actions/setup-go": ({}, ""),
    "actions/setup-dotnet": ({}, ""), "actions/cache": ({}, ""), "actions/upload-artifact": ({}, ""), "actions/download-artifact": ({"actions": "read"}, "read artifacts of other runs (when run-id is set)"),
    "actions/configure-pages": ({"pages": "read"}, "read Pages settings"), "actions/upload-pages-artifact": ({}, ""),
    "actions/deploy-pages": ({"pages": "write", "id-token": "write"}, "deploy to GitHub Pages"),
    "actions/labeler": ({"contents": "read", "pull-requests": "write"}, "label pull requests"),
    "actions/stale": ({"issues": "write", "pull-requests": "write"}, "comment on / close stale issues and PRs"),
    "actions/dependency-review-action": ({"contents": "read", "pull-requests": "write"}, "read dependency diff, comment summary"),
    "actions/attest-build-provenance": ({"id-token": "write", "attestations": "write"}, "sign build provenance"),
    "actions/attest-sbom": ({"id-token": "write", "attestations": "write"}, "sign SBOM attestation"),
    "actions/create-github-app-token": ({}, "uses its own app credentials"),
    "github/codeql-action/init": ({"security-events": "write", "actions": "read", "contents": "read"}, "CodeQL"),
    "github/codeql-action/analyze": ({"security-events": "write", "actions": "read", "contents": "read"}, "upload code scanning results"),
    "github/codeql-action/autobuild": ({}, ""),
    "github/codeql-action/upload-sarif": ({"security-events": "write"}, "upload SARIF"),
    "softprops/action-gh-release": ({"contents": "write"}, "create releases"),
    "ncipollo/release-action": ({"contents": "write"}, "create releases"),
    "peter-evans/create-pull-request": ({"contents": "write", "pull-requests": "write"}, "push a branch and open a PR"),
    "peter-evans/create-or-update-comment": ({"issues": "write", "pull-requests": "write"}, "comment on issues / PRs"),
    "stefanzweifel/git-auto-commit-action": ({"contents": "write"}, "commit and push"),
    "dessant/lock-threads": ({"issues": "write", "pull-requests": "write", "discussions": "write"}, "lock threads"),
    "docker/setup-buildx-action": ({}, ""), "docker/setup-qemu-action": ({}, ""), "docker/metadata-action": ({}, ""),
    "docker/build-push-action": ({}, "registry credentials come from docker/login-action"),
    "aws-actions/configure-aws-credentials": ({"id-token": "write"}, "OIDC federation (when role-to-assume is used)"),
    "azure/login": ({"id-token": "write"}, "OIDC federation"),
    "google-github-actions/auth": ({"id-token": "write"}, "OIDC federation"),
    "dependabot/fetch-metadata": ({"pull-requests": "read"}, "read PR metadata"),
    "amannn/action-semantic-pull-request": ({"pull-requests": "read"}, "read PR title"),
    "codecov/codecov-action": ({}, "uses its own token / OIDC (add id-token: write when use_oidc is set)"),
    "coverallsapp/github-action": ({}, "uses its own repo token"),
    "cypress-io/github-action": ({}, ""), "gamesight/slack-workflow-status": ({"actions": "read"}, "read run status"),
    "akhileshns/heroku-deploy": ({}, "uses its own API key"),
}

RUN_PATTERNS: list[tuple[str, dict[str, str], str]] = [
    (r"\bgit\s+push\b", {"contents": "write"}, "git push"),
    (r"\bgh\s+release\s+(create|upload|edit|delete)", {"contents": "write"}, "gh release"),
    (r"\bgh\s+pr\s+(create|merge|edit|close|review|comment)", {"pull-requests": "write", "contents": "write"}, "gh pr write"),
    (r"\bgh\s+pr\s+(view|list|diff|checks)", {"pull-requests": "read"}, "gh pr read"),
    (r"\bgh\s+issue\s+(create|edit|close|comment|reopen|lock)", {"issues": "write"}, "gh issue write"),
    (r"\bgh\s+(issue\s+(view|list))", {"issues": "read"}, "gh issue read"),
    (r"\bgh\s+run\s+(rerun|cancel|delete)", {"actions": "write"}, "gh run write"),
    (r"\bgh\s+(run|workflow)\s+(view|list|download|watch)", {"actions": "read"}, "gh run read"),
    (r"\bgh\s+workflow\s+run\b", {"actions": "write"}, "gh workflow run"),
    (r"\bgh\s+label\s+(create|edit|delete)", {"issues": "write"}, "gh label"),
    (r"\bdocker\s+(push|login)\s+.*ghcr\.io|ghcr\.io.*\bdocker\s+push", {"packages": "write"}, "push to GHCR"),
    (r"\bnpm\s+publish\b.*--provenance|--provenance.*\bnpm\s+publish", {"id-token": "write"}, "npm provenance"),
    (r"ACTIONS_ID_TOKEN_REQUEST", {"id-token": "write"}, "requests an OIDC token"),
    (r"api\.github\.com|\bgh\s+api\b", {}, "calls the GitHub API (scopes depend on the endpoint)"),
]
TOKEN_EXPR = re.compile(r"\$\{\{\s*(secrets\.GITHUB_TOKEN|github\.token)\s*\}\}", re.I)


def _merge(acc: dict[str, str], add: dict[str, str]) -> None:
    for k, v in add.items():
        if LEVEL[v] > LEVEL.get(acc.get(k, "none"), 0):
            acc[k] = v


def _slug(uses: str) -> str | None:
    ref = parse_uses(uses)
    if not ref or ref.kind != "action":
        return None
    return ref.slug.lower()


def infer_job(job, ghes_packages: bool = False) -> dict:
    """{'permissions': {...}, 'reasons': [...], 'review': [...], 'confidence': 'high'|'medium'|'low'}"""
    perms: dict[str, str] = {}
    reasons, review = [], []
    if job.data.get("uses"):  # reusable workflow call: permissions are granted to the callee
        return {"permissions": None, "reasons": [], "review": ["Reusable workflow call: grant what the called workflow needs."],
                "confidence": "low", "reusable": True}
    for st in job.steps:
        if st.uses:
            slug = _slug(st.uses)
            if slug is None:
                continue  # local or docker action: no token unless passed explicitly (handled below)
            known = KNOWN.get(slug) or KNOWN.get("/".join(slug.split("/")[:2]))
            if slug.startswith("actions/github-script"):
                review.append(f"step {st.index + 1}: actions/github-script calls the API with the token; scopes depend on the script")
            elif known is not None:
                if known[0]:
                    _merge(perms, known[0])
                    reasons.append(f"{slug}: {', '.join(f'{k}: {v}' for k, v in known[0].items())}" + (f" ({known[1]})" if known[1] else ""))
                if slug == "aws-actions/configure-aws-credentials" and "role-to-assume" not in (st.data.get("with") or {}):
                    perms.pop("id-token", None)
            else:
                passes = TOKEN_EXPR.search(str(st.data.get("with") or "")) or TOKEN_EXPR.search(str(st.data.get("env") or ""))
                if passes:
                    review.append(f"step {st.index + 1}: {st.uses.split('@')[0]} receives the token; check its documentation for the scopes it needs")
        if st.run:
            for pat, add, why in RUN_PATTERNS:
                if re.search(pat, st.run, re.I):
                    if add:
                        _merge(perms, add)
                        reasons.append(f"run step {st.index + 1}: {why} ({', '.join(f'{k}: {v}' for k, v in add.items())})")
                    else:
                        review.append(f"run step {st.index + 1}: {why}")
    if perms.get("contents") is None and any(s.uses and (_slug(s.uses) or "").startswith("actions/checkout") for s in job.steps):
        perms["contents"] = "read"
    confidence = "high" if not review else "medium" if len(review) == 1 else "low"
    return {"permissions": dict(sorted(perms.items())), "reasons": reasons, "review": review, "confidence": confidence, "reusable": False}


def render_block(perms: dict[str, str], indent: int) -> list[str]:
    pad = " " * indent
    if not perms:
        return ["permissions: {}"]
    return ["permissions:"] + [f"{pad}{k}: {v}" for k, v in sorted(perms.items())]


def workflow_report(wf, inventory_wf: dict | None = None) -> list[dict]:
    out = []
    from ..scanner.gha import external_triggers

    jobs_inv = {j["id"]: j for j in (inventory_wf or {}).get("jobs", [])}
    untrusted = sorted(set(external_triggers(wf)) - SAFE_TRIGGERS)
    for job in wf.jobs:
        inf = infer_job(job)
        current = jobs_inv.get(job.id, {}).get("write_scopes")
        explicit = job.permissions is not None
        need_write = sorted(k for k, v in (inf["permissions"] or {}).items() if v == "write")
        if need_write and untrusted:
            inf["review"] = inf["review"] + [f"needs {', '.join(need_write)} write but runs on {', '.join(untrusted)}: move these steps to a workflow on push / "
                                             "workflow_dispatch rather than granting writes here (the automatic fix leaves this job read-only)"]
            inf["confidence"] = "low"
        excess = sorted(set(current or []) - set(need_write)) if current is not None else None
        out.append({"workflow": wf.path, "job": job.id, "name": job.name, "explicit": explicit,
                    "current_write_scopes": current, "recommended": inf["permissions"], "reasons": inf["reasons"],
                    "review": inf["review"], "confidence": inf["confidence"], "reusable": inf["reusable"],
                    "excess_write_scopes": excess,
                    "yaml": "\n".join(render_block(inf["permissions"], 2)) if inf["permissions"] is not None else ""})
    return out
