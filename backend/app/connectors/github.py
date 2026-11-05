"""GitHub connector: read-only REST API collection + zipball download.

Recommended token: fine-grained PAT with read-only `Contents`, `Metadata`, `Actions`, `Administration` (read) and
`Environments` (read) on the selected repositories. Every call is a GET; nothing is written to GitHub.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import httpx

from ..config import get_settings
from ..scanner.model import ApiResult, RepoMetadata
from ..scanner.workspace import UnsafeArchive, safe_extract_zip
from .base import AcquiredWorkspace, Connector, ConnectorError

REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
WRITE_SCOPES = {"repo", "write:packages", "admin:org", "admin:repo_hook", "workflow", "delete_repo", "admin:public_key", "write:org"}


class GitHubClient:
    def __init__(self, token: str | None = None, api_url: str | None = None, timeout: float = 30.0):
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "PipelineTrust-Scanner"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self.client = httpx.Client(base_url=(api_url or get_settings().github_api_url).rstrip("/"), headers=headers,
                                   timeout=timeout, follow_redirects=False)

    def close(self):
        self.client.close()

    def get(self, path: str, **params) -> httpx.Response:
        return self.client.get(path, params=params or None)

    def result(self, path: str, none_on_404: bool = False, **params) -> ApiResult:
        try:
            r = self.get(path, **params)
        except httpx.HTTPError as exc:
            return ApiResult("error", detail=f"{type(exc).__name__}")
        if r.status_code == 200:
            return ApiResult("ok", r.json())
        if r.status_code == 404 and none_on_404:
            return ApiResult("none", None, detail="not configured")
        if r.status_code in (401, 403, 404):
            msg = ""
            try:
                msg = r.json().get("message", "")
            except ValueError:
                pass
            if r.status_code == 403 and "rate limit" in msg.lower():
                return ApiResult("error", detail="GitHub API rate limit exceeded")
            return ApiResult("forbidden", detail=f"HTTP {r.status_code}: {msg[:120]} (token lacks permission)")
        return ApiResult("error", detail=f"HTTP {r.status_code}")

    def token_info(self) -> dict:
        r = self.get("/user")
        if r.status_code != 200:
            return {"valid": False, "status": r.status_code}
        scopes = [s.strip() for s in r.headers.get("X-OAuth-Scopes", "").split(",") if s.strip()]
        excessive = sorted(set(scopes) & WRITE_SCOPES)
        return {"valid": True, "login": r.json().get("login"), "classic_scopes": scopes,
                "token_type": "classic" if "X-OAuth-Scopes" in r.headers else "fine-grained/app",
                "excessive_scopes": excessive,
                "advice": ("Token has write scopes " + ", ".join(excessive) + "; PipelineTrust only needs read access. "
                           "Prefer a fine-grained read-only token.") if excessive else "OK"}

    def list_repos(self, org: str | None = None, limit: int = 300) -> list[dict]:
        path = f"/orgs/{org}/repos" if org else "/user/repos"
        out, page = [], 1
        while len(out) < limit:
            r = self.get(path, per_page=100, page=page, sort="updated")
            if r.status_code != 200:
                raise ConnectorError(f"cannot list repositories: HTTP {r.status_code}")
            batch = r.json()
            out.extend({"full_name": x["full_name"], "private": x["private"], "default_branch": x.get("default_branch"),
                        "archived": x.get("archived"), "pushed_at": x.get("pushed_at"), "visibility": x.get("visibility")} for x in batch)
            if len(batch) < 100:
                break
            page += 1
        return out[:limit]

    def list_workflow_files(self, full_name: str, ref: str | None = None) -> list[dict]:
        r = self.result(f"/repos/{full_name}/contents/.github/workflows", none_on_404=True, **({"ref": ref} if ref else {}))
        if r.status != "ok":
            return []
        return [{"name": x["name"], "path": x["path"], "sha": x["sha"]} for x in r.data if x.get("type") == "file"]

    def resolve_sha(self, owner: str, repo: str, ref: str) -> str | None:
        r = self.client.get(f"/repos/{owner}/{repo}/commits/{ref}", headers={"Accept": "application/vnd.github.sha"})
        if r.status_code == 200 and re.fullmatch(r"[0-9a-f]{40}", r.text.strip()):
            return r.text.strip()
        return None

    def collect_metadata(self, full_name: str, ref: str | None = None) -> RepoMetadata:
        repo = self.result(f"/repos/{full_name}")
        if repo.status != "ok":
            raise ConnectorError(f"repository {full_name} not accessible: {repo.detail or repo.status}")
        d: dict[str, Any] = repo.data
        branch = ref or d.get("default_branch", "main")
        md = RepoMetadata(source="github", full_name=d["full_name"], default_branch=d.get("default_branch", ""),
                          visibility=d.get("visibility") or ("private" if d.get("private") else "public"),
                          owner_type=(d.get("owner") or {}).get("type", ""))
        md.collected["repo"] = ApiResult("ok", {k: d.get(k) for k in ("full_name", "private", "visibility", "default_branch", "archived", "fork", "allow_forking", "has_issues")})
        md.collected["branch"] = self.result(f"/repos/{full_name}/branches/{md.default_branch}")
        md.collected["branch_rules"] = self.result(f"/repos/{full_name}/rules/branches/{md.default_branch}")
        md.collected["branch_protection"] = self.result(f"/repos/{full_name}/branches/{md.default_branch}/protection", none_on_404=False)
        bp = md.collected["branch_protection"]
        if bp.status == "forbidden" and "Branch not protected" in bp.detail:
            md.collected["branch_protection"] = ApiResult("none", detail="branch not protected")
        envs = self.result(f"/repos/{full_name}/environments")
        if envs.status == "ok":
            envs = ApiResult("ok", envs.data.get("environments", []))
        md.collected["environments"] = envs
        md.collected["workflow_permissions"] = self.result(f"/repos/{full_name}/actions/permissions/workflow")
        md.collected["actions_permissions"] = self.result(f"/repos/{full_name}/actions/permissions")
        md.collected["collaborators"] = self.result(f"/repos/{full_name}/collaborators", per_page=100)
        if md.owner_type == "Organization":
            md.collected["org"] = self.result(f"/orgs/{full_name.split('/')[0]}")
        md.collected["_ref"] = ApiResult("ok", {"ref": branch})
        return md

    def download_zipball(self, full_name: str, ref: str, dest: Path, max_bytes: int) -> tuple[Path, str]:
        sha = self.resolve_sha(*full_name.split("/", 1), ref) or ""
        r = self.client.get(f"/repos/{full_name}/zipball/{sha or ref}")
        if r.status_code not in (301, 302, 303, 307):
            if r.status_code == 200:
                content = r.content
            else:
                raise ConnectorError(f"zipball download failed: HTTP {r.status_code}")
        else:
            loc = r.headers["location"]
            if not loc.startswith("https://"):
                raise ConnectorError("refusing non-HTTPS archive redirect")
            # Archive host (codeload.github.com) must not receive the API token.
            with httpx.stream("GET", loc, timeout=120, follow_redirects=True, headers={"User-Agent": "PipelineTrust-Scanner"}) as s:
                if s.status_code != 200:
                    raise ConnectorError(f"archive download failed: HTTP {s.status_code}")
                buf = bytearray()
                for chunk in s.iter_bytes():
                    buf.extend(chunk)
                    if len(buf) > max_bytes:
                        raise ConnectorError("repository archive exceeds upload size limit")
                content = bytes(buf)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(content)
        return dest, sha


class GitHubConnector(Connector):
    name = "github"
    display_name = "GitHub Actions"

    def acquire(self, *, project, secret, workdir: Path, upload_path, progress) -> AcquiredWorkspace:
        if not REPO_RE.match(project.repo_full_name or ""):
            raise ConnectorError("project repository must be in owner/repo form")
        s = get_settings()
        gh = GitHubClient(secret)
        try:
            progress("Collecting repository metadata from GitHub API")
            md = gh.collect_metadata(project.repo_full_name, project.ref or None)
            ref = project.ref or md.default_branch
            progress(f"Downloading {project.repo_full_name}@{ref}")
            zpath, sha = gh.download_zipball(project.repo_full_name, ref, workdir / "repo.zip", s.max_upload_mb * 1024 * 1024 * 4)
            progress("Extracting repository archive")
            try:
                root = safe_extract_zip(zpath, workdir / "src", s.max_extracted_mb * 1024 * 1024, s.max_extracted_files)
            except UnsafeArchive as exc:
                raise ConnectorError(f"archive rejected: {exc}") from exc
            zpath.unlink(missing_ok=True)
        except ConnectorError:
            gh.close()
            raise
        except httpx.HTTPError as exc:
            gh.close()
            raise ConnectorError(f"GitHub API error: {type(exc).__name__}") from exc

        def resolver(owner: str, repo: str, r: str) -> str | None:
            return gh.resolve_sha(owner, repo, r)

        ws = AcquiredWorkspace(root=root, metadata=md, commit_sha=sha, sha_resolver=resolver)
        ws._client = gh  # closed by the scan runner
        return ws
