"""Third-party GitHub Action reputation across the organization, and an "allowed actions" policy generated from it.

Signals come from the GitHub API (repository metadata, owner verification) and the advisory feed; usage comes from
each project's latest inventory. Repository metadata is cached for 24 hours to stay within API rate limits.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from ..config import get_settings
from ..connectors.github import GitHubClient
from ..scanner.advisories import all_advisories, match

CACHE_TTL = 24 * 3600
FIRST_PARTY = ("actions", "github")


def _cache_path():
    p = get_settings().data_dir / "cache"
    p.mkdir(parents=True, exist_ok=True)
    return p / "action_repos.json"


def _load_cache() -> dict:
    try:
        return json.loads(_cache_path().read_text("utf-8"))
    except (OSError, ValueError):
        return {}


def _save_cache(c: dict) -> None:
    _cache_path().write_text(json.dumps(c), "utf-8")


def _days(ts: str | None) -> int | None:
    if not ts:
        return None
    try:
        return (datetime.now(timezone.utc) - datetime.fromisoformat(ts.replace("Z", "+00:00"))).days
    except ValueError:
        return None


def collect_usage(scans: list[tuple[object, object]]) -> dict[str, dict]:
    """repo slug (owner/repo) -> usage across projects."""
    out: dict[str, dict] = {}
    for project, scan in scans:
        for a in (scan.inventory or {}).get("actions", []):
            if a.get("kind") != "action" or not a.get("owner"):
                continue
            slug = "/".join(a["action"].split("/")[:2]).lower()
            e = out.setdefault(slug, {"slug": slug, "owner": a["owner"].lower(), "projects": set(), "uses": set(), "refs": set(),
                                      "pinned": 0, "unpinned": 0, "first_party": slug.split("/")[0] in FIRST_PARTY})
            e["projects"].add(project.name)
            e["uses"].add(a["uses"])
            e["refs"].add(a.get("ref") or "")
            if a.get("sha_pinned"):
                e["pinned"] += a.get("count", 1)
            else:
                e["unpinned"] += a.get("count", 1)
    return out


def fetch_meta(gh: GitHubClient, slugs: list[str], budget: int = 40, refresh: bool = False) -> tuple[dict, int]:
    cache = _load_cache()
    now = time.time()
    fetched = 0
    for slug in slugs:
        hit = cache.get(slug)
        if hit and not refresh and now - hit.get("_at", 0) < CACHE_TTL:
            continue
        if fetched >= budget:
            continue
        owner = slug.split("/")[0]
        r = gh.result(f"/repos/{slug}", none_on_404=True)
        fetched += 1
        if r.status == "ok":
            d = r.data
            meta = {"stars": d.get("stargazers_count"), "archived": d.get("archived"), "pushed_at": d.get("pushed_at"),
                    "created_at": d.get("created_at"), "owner_type": (d.get("owner") or {}).get("type"), "fork": d.get("fork"),
                    "license": (d.get("license") or {}).get("spdx_id"), "status": "ok"}
            okey = f"org:{owner}"
            if meta["owner_type"] == "Organization" and (refresh or okey not in cache or now - cache[okey].get("_at", 0) > CACHE_TTL) and fetched < budget:
                o = gh.result(f"/orgs/{owner}")
                fetched += 1
                cache[okey] = {"verified": bool(o.data.get("is_verified")) if o.status == "ok" else None, "_at": now}
            meta["verified_owner"] = (cache.get(okey) or {}).get("verified")
        elif r.status == "none":
            meta = {"status": "missing"}
        else:
            meta = {"status": "error", "detail": r.detail}
        meta["_at"] = now
        cache[slug] = meta
    _save_cache(cache)
    return cache, fetched


def score(e: dict, meta: dict | None, advisories: list[dict]) -> dict:
    reasons: list[str] = []
    blocked = False
    for u in e["uses"]:
        hit = match(u, advisories)
        if hit and hit[2] in ("compromised_ref", "mutable_ref"):
            blocked = True
            reasons.append(f"advisory {hit[0]['id']}: {hit[0]['title']}")
            break
    if e["first_party"]:
        s, reasons = 100, ["published by GitHub"] + reasons
    elif not meta or meta.get("status") != "ok":
        s = 40
        reasons.append("repository metadata not available yet" if not meta else
                       "repository not found (deleted or renamed: the reference can be taken over)" if meta.get("status") == "missing" else
                       f"metadata error: {meta.get('detail', '')}")
        if meta and meta.get("status") == "missing":
            s = 10
    else:
        s = 70
        if meta.get("verified_owner"):
            s += 15
            reasons.append("verified organization")
        elif meta.get("owner_type") == "User":
            s -= 10
            reasons.append("owned by an individual account")
        if meta.get("archived"):
            s -= 40
            reasons.append("repository archived (no security fixes)")
        idle = _days(meta.get("pushed_at"))
        if idle is not None and idle > 730:
            s -= 25
            reasons.append(f"no commits for {idle // 365} years")
        elif idle is not None and idle > 365:
            s -= 15
            reasons.append("no commits for over a year")
        age = _days(meta.get("created_at"))
        if age is not None and age < 90:
            s -= 15
            reasons.append(f"repository is only {age} days old")
        stars = meta.get("stars") or 0
        if stars >= 1000:
            s += 10
            reasons.append(f"{stars} stars")
        elif stars < 50:
            s -= 10
            reasons.append(f"only {stars} stars")
        if meta.get("fork"):
            s -= 10
            reasons.append("is a fork")
    if blocked:
        s = 0
    s = max(0, min(100, s))
    tier = "blocked" if blocked else "trusted" if s >= 80 else "acceptable" if s >= 60 else "review" if s >= 40 else "risky"
    return {"score": s, "tier": tier, "reasons": reasons}


TIER_RANK = {"blocked": 0, "risky": 1, "review": 2, "acceptable": 3, "trusted": 4}


def allowlist(entries: list[dict], min_tier: str = "acceptable", sha_only: bool = False, verified_allowed: bool = False) -> dict:
    allowed, excluded = [], []
    for e in entries:
        if e["first_party"]:
            continue  # covered by github_owned_allowed
        if TIER_RANK[e["tier"]] < TIER_RANK[min_tier]:
            excluded.append({"action": e["slug"], "tier": e["tier"], "reason": "; ".join(e["reasons"][:3]) or e["tier"]})
            continue
        if sha_only:
            shas = sorted(u.split("@", 1)[1] for u in e["uses"] if "@" in u and len(u.split("@", 1)[1]) == 40)
            if not shas:
                excluded.append({"action": e["slug"], "tier": e["tier"], "reason": "not pinned to a commit SHA anywhere (sha-only policy)"})
                continue
            allowed.extend(f"{u.split('@', 1)[0]}@{sha}" for u in sorted(e["uses"]) for sha in shas if u.endswith(sha))
        else:
            allowed.append(f"{e['slug']}@*")
            allowed.extend(f"{u.split('@', 1)[0]}@*" for u in sorted(e["uses"]) if u.count("/") > 1)  # sub-path actions
    patterns = sorted(set(allowed))
    body = {"github_owned_allowed": True, "verified_allowed": verified_allowed, "patterns_allowed": patterns}
    return {"policy": body, "excluded": excluded,
            "apply": {"organization": "gh api -X PUT /orgs/ORG/actions/permissions -f enabled_repositories=all -f allowed_actions=selected && "
                                      "gh api -X PUT /orgs/ORG/actions/permissions/selected-actions --input policy.json",
                      "repository": "gh api -X PUT /repos/OWNER/REPO/actions/permissions -F enabled=true -f allowed_actions=selected && "
                                    "gh api -X PUT /repos/OWNER/REPO/actions/permissions/selected-actions --input policy.json"},
            "note": "Workflows using an excluded action will fail once the policy is applied: fix or replace them first (see the reputation table)."}


def reputation(gh: GitHubClient, scans: list, custom_advisories: list[dict], refresh: bool = False) -> dict:
    usage = collect_usage(scans)
    meta, fetched = fetch_meta(gh, sorted(s for s, e in usage.items() if not e["first_party"]), refresh=refresh)
    advs = all_advisories(custom_advisories)
    rows = []
    for slug, e in usage.items():
        m = meta.get(slug)
        sc = score(e, m, advs)
        rows.append({"slug": slug, "first_party": e["first_party"], "projects": sorted(e["projects"]), "uses": sorted(e["uses"]),
                     "refs": sorted(e["refs"]), "pinned": e["pinned"], "unpinned": e["unpinned"], **sc,
                     "meta": {k: v for k, v in (m or {}).items() if not k.startswith("_")}})
    rows.sort(key=lambda r: (TIER_RANK[r["tier"]], r["score"], r["slug"]))
    pending = sum(1 for r in rows if not r["first_party"] and not r["meta"])
    return {"actions": rows, "fetched": fetched, "pending": pending,
            "counts": {t: sum(1 for r in rows if r["tier"] == t) for t in TIER_RANK}}
