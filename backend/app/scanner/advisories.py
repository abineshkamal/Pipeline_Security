"""Supply-chain advisories for GitHub Actions (compromised-action watch).

Built-in entries cover publicly documented incidents; organizations add their own through the API. An advisory names
the action (owner/repo), the refs (tags, branches or commit SHAs) known to be malicious, and the incident window used to
find workflow runs that may have executed the bad code. Windows are dates (UTC) taken from the public advisories.
"""
from __future__ import annotations

from .gha import parse_uses

BUILTIN_ADVISORIES: list[dict] = [
    {
        "id": "CVE-2025-30066", "action": "tj-actions/changed-files", "severity": "critical",
        "title": "tj-actions/changed-files: all tags repointed to a secret-dumping commit",
        "bad_refs": ["0e58ed8671d6b60d0890c21b07f8835ace038e67"], "all_tags_affected": True,
        "window_start": "2025-03-14", "window_end": "2025-03-15",
        "references": ["https://www.cve.org/CVERecord?id=CVE-2025-30066"],
        "guidance": "Replace or pin a reviewed post-incident SHA; rotate every secret available to jobs that ran the action during the window and review their logs.",
    },
    {
        "id": "CVE-2025-30154", "action": "reviewdog/action-setup", "severity": "high",
        "title": "reviewdog/action-setup: v1 tag repointed to a malicious commit",
        "bad_refs": ["v1"], "all_tags_affected": False,
        "window_start": "2025-03-11", "window_end": "2025-03-11",
        "references": ["https://www.cve.org/CVERecord?id=CVE-2025-30154"],
        "guidance": "Pin a reviewed SHA; rotate secrets exposed to jobs that ran the action during the window.",
    },
]


def normalize(adv: dict) -> dict:
    a = dict(adv)
    a["action"] = str(a.get("action", "")).strip().lower()
    a["bad_refs"] = [str(r).strip() for r in (a.get("bad_refs") or []) if str(r).strip()]
    a.setdefault("all_tags_affected", False)
    a.setdefault("severity", "high")
    a.setdefault("references", [])
    a.setdefault("guidance", "")
    a.setdefault("source", "builtin")
    return a


def all_advisories(custom: list[dict] | None = None) -> list[dict]:
    return [normalize({**a, "source": "builtin"}) for a in BUILTIN_ADVISORIES] + [normalize({**a, "source": "organization"}) for a in (custom or [])]


def match(uses: str, advisories: list[dict]) -> tuple[dict, str, str] | None:
    """Return (advisory, severity, verdict) when `uses` references an affected action, else None.

    verdict: compromised_ref (exact bad ref / SHA) | mutable_ref (tag or branch that was or could be repointed)
             | pinned_sha (a different SHA: likely safe, verify it is a reviewed commit)
    """
    ref = parse_uses(uses)
    if not ref or ref.kind in ("local", "docker") or not ref.owner:
        return None
    key = f"{ref.owner}/{ref.repo}".lower()
    for a in advisories:
        if a["action"] != key:
            continue
        if ref.ref and ref.ref in a["bad_refs"]:
            return a, "critical", "compromised_ref"
        if ref.is_sha_pinned:
            return a, "info", "pinned_sha"
        return a, ("high" if a.get("all_tags_affected") or not a["bad_refs"] else "medium"), "mutable_ref"
    return None


VERDICT_TEXT = {
    "compromised_ref": "references the exact malicious ref",
    "mutable_ref": "uses a mutable tag/branch of an affected action",
    "pinned_sha": "is pinned to a different commit SHA (verify it is a reviewed, post-incident commit)",
}
