"""Deterministic fixes for workflow findings, verified by re-running the rules on the patched file.

Supported (rule -> change):
  PT-3P-001   pin `owner/action@tag` to the tag's commit SHA, keeping the tag as a comment
  PT-PBAC-001 add a workflow-level `permissions: contents: read` block
  PT-CRED-005 add `persist-credentials: false` to actions/checkout
  PT-PPE-003  move untrusted `${{ ... }}` values used in `run:` scripts into step `env:` variables

Edits are line-based on the original text (comments and formatting are preserved). Each patched file is re-parsed and
every workflow rule is run on the original and patched versions: a fix is reported as verified only when its finding
disappears and the file still parses. Nothing here executes repository code.
"""
from __future__ import annotations

import base64
import difflib
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import httpx

from ..config import get_settings
from ..models import Finding
from ..scanner.gha import external_triggers
from .permissions import SAFE_TRIGGERS
from ..scanner.advisories import all_advisories
from ..scanner.advisories import match as match_advisory
from ..scanner.model import RepoMetadata, ScanContext, Workflow, WorkflowRule, parse_workflow
from ..scanner.rules import load_rules

FIXABLE_RULES = {"PT-3P-001", "PT-PBAC-001", "PT-CRED-005", "PT-PPE-003"}
FIX_LABELS = {
    "PT-3P-001": "Pin action to a commit SHA",
    "PT-PBAC-001": "Add read-only workflow permissions",
    "PT-CRED-005": "Stop persisting the checkout token",
    "PT-PPE-003": "Move untrusted input into environment variables",
}
WRITE_HINTS = ("git push", "gh pr ", "gh issue", "gh release", "github-script", "create-release", "upload-release-asset",
               "create-pull-request", "git-auto-commit", "actions/stale", "lock-threads", "deploy-pages", "upload-pages-artifact",
               "id-token", "codeql-action", "softprops/action-gh-release", "ncipollo/release-action")
PinResolver = Callable[[str, str, str], "str | None"]


@dataclass
class FileEdit:
    path: str
    lines: list[str]
    newline: str
    trailing_newline: bool
    replace: dict[int, str] = field(default_factory=dict)  # 0-based index -> new text
    insert: list[tuple[int, list[str]]] = field(default_factory=list)  # insert before 0-based index

    def current(self, i: int) -> str:
        return self.replace.get(i, self.lines[i])

    def render(self) -> str:
        out = [self.replace.get(i, ln) for i, ln in enumerate(self.lines)]
        for idx, new in sorted(self.insert, key=lambda x: -x[0]):
            out[idx:idx] = new
        text = self.newline.join(out)
        return text + (self.newline if self.trailing_newline else "")


def _split(text: str) -> tuple[list[str], str, bool]:
    nl = "\r\n" if "\r\n" in text else "\n"
    trailing = text.endswith(("\n", "\r"))
    return text.splitlines(), nl, trailing


def _key_col(line: str) -> int:
    m = re.match(r"^(\s*)(-\s+)?", line)
    return m.end() if m else 0


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _block_end(lines: list[str], start: int, col: int) -> int:
    """First index after `start` whose content is at indent <= col (end of a key's block)."""
    for j in range(start + 1, len(lines)):
        s = lines[j].strip()
        if s and not s.startswith("#") and _indent(lines[j]) <= col:
            return j
    return len(lines)


def _child_indent(lines: list[str], key_idx: int, key_col: int) -> int:
    for j in range(key_idx + 1, len(lines)):
        if lines[j].strip():
            return _indent(lines[j]) if _indent(lines[j]) > key_col else key_col + 2
    return key_col + 2


def _var_name(expr_inner: str, taken: set[str]) -> str:
    s = re.sub(r"^github\.(event\.)?", "", expr_inner.strip())
    s = re.sub(r"\[.*?\]", "", s)
    name = re.sub(r"[^A-Za-z0-9]+", "_", s).strip("_").upper() or "UNTRUSTED_VALUE"
    if name[0].isdigit():
        name = "V_" + name
    base, n = name, 2
    while name in taken:
        name = f"{base}_{n}"
        n += 1
    taken.add(name)
    return name


def _step(wf: Workflow, job_id: str, index: int):
    job = next((j for j in wf.jobs if j.id == job_id), None)
    if not job or index >= len(job.steps):
        return None, None
    return job, job.steps[index]


# ---------------------------------------------------------------- generators (return (status, reason, review))

def _fix_pin(fe: FileEdit, f: Finding, resolve: PinResolver | None, cache: dict, advisories: list[dict]) -> tuple[str, str, str]:
    slug, ref = (f.extra or {}).get("action"), (f.extra or {}).get("ref")
    if not slug or not ref:
        return "skipped", "Action reference has no tag or branch to pin.", ""
    hit = match_advisory(f"{slug}@{ref}", advisories)
    if hit:
        return "skipped", (f"`{slug}` is affected by {hit[0]['id']}: pinning whatever its tag points to now could pin a malicious "
                           "commit. Choose a reviewed commit SHA (or replace the action) manually."), ""
    sha = None
    pin = (f.extra or {}).get("suggested_pin") or ""
    m = re.search(r"@([0-9a-f]{40})", pin)
    if m:
        sha = m.group(1)
    elif resolve:
        owner_repo = "/".join(slug.split("/")[:2])
        k = (owner_repo, ref)
        if k not in cache and len(cache) < 60:
            try:
                cache[k] = resolve(*owner_repo.split("/", 1), ref)
            except Exception:  # noqa: BLE001 - network failures just skip the fix
                cache[k] = None
        sha = cache.get(k)
    if not sha:
        return "skipped", f"Could not resolve `{slug}@{ref}` to a commit SHA (GitHub API unreachable or ref not found).", ""
    needle = f"{slug}@{ref}"
    for i in [x for x in (f.line - 1 if f.line else -1, f.line, f.line - 2 if f.line else -1) if 0 <= x < len(fe.lines)]:
        cur = fe.current(i)
        if needle in cur:
            new = cur.replace(needle, f"{slug}@{sha}", 1)
            if "#" not in new.split(f"{slug}@{sha}", 1)[1]:
                new = f"{new.rstrip()} # {ref}"
            fe.replace[i] = new
            return "applied", f"`{needle}` -> `{slug}@{sha[:12]}…` (# {ref})", ""
    return "skipped", f"Could not find `{needle}` on line {f.line}.", ""


def _fix_permissions(fe: FileEdit, f: Finding, wf: Workflow) -> tuple[str, str, str]:
    """Workflow-level `contents: read`, plus a least-privilege job-level block for every job whose steps need more
    (inferred from known actions and run scripts, see insights/permissions.py)."""
    from .permissions import infer_job, render_block

    if wf.has_permissions_key:
        return "skipped", "Workflow already declares permissions.", ""
    if any(lines and any(new.strip().startswith("permissions:") for new in lines) for _i, lines in fe.insert):
        return "applied", "Least-privilege permissions already added by another fix.", ""
    jobs_idx = next((i for i, ln in enumerate(fe.lines) if re.match(r"^jobs\s*:\s*(#.*)?$", ln)), None)
    if jobs_idx is None:
        return "skipped", "Top-level `jobs:` key not found (flow-style YAML?).", ""
    child = _child_indent(fe.lines, jobs_idx, 0)
    fe.insert.append((jobs_idx, ["permissions:", " " * child + "contents: read", ""]))
    granted, reviews = [], []
    for job in wf.jobs:
        inf = infer_job(job)
        if inf["review"]:
            reviews.extend(f"job `{job.id}`: {r}" for r in inf["review"])
        untrusted = set(external_triggers(wf)) - SAFE_TRIGGERS
        if job.permissions is not None or inf["reusable"]:
            continue
        need = inf["permissions"] or {}
        if not need or need == {"contents": "read"}:
            continue
        writes = sorted(k for k, v in need.items() if v == "write")
        if writes and untrusted:
            # never hand write scopes to code that pull requests / comments can run: leave it read-only and say why
            reviews.append(f"job `{job.id}` needs {', '.join(f'{w}: write' for w in writes)} but this workflow runs on {', '.join(sorted(untrusted))}; "
                           "move that step to a separate workflow on push / workflow_dispatch instead of granting writes here")
            need = {k: v for k, v in need.items() if v != "write"}
            if not need or need == {"contents": "read"}:
                continue
        ki = job.line - 1
        if not (0 <= ki < len(fe.lines)) or not re.match(rf"^\s*{re.escape(job.id)}\s*:\s*(#.*)?$", fe.lines[ki]):
            reviews.append(f"job `{job.id}` needs {need} but its key line could not be located; add it manually")
            continue
        kcol = _key_col(fe.lines[ki])
        ci = _child_indent(fe.lines, ki, kcol)
        block = render_block({"contents": "read", **need} if "contents" not in need else need, 2)
        fe.insert.append((ki + 1, [" " * ci + block[0]] + [" " * ci + ln for ln in block[1:]]))
        granted.append(f"`{job.id}` ({', '.join(f'{k}: {v}' for k, v in sorted(need.items()))})")
    detail = "Added `permissions: contents: read` at workflow level" + (f" and least-privilege job permissions for {'; '.join(granted)}." if granted else ".")
    return "applied", detail, ("Check before merging - " + "; ".join(reviews)) if reviews else ""


def _fix_persist(fe: FileEdit, f: Finding, wf: Workflow) -> tuple[str, str, str]:
    jid, _, idx = str((f.extra or {}).get("key", "")).partition(":")
    job, step = _step(wf, jid or f.job, int(idx) if idx.isdigit() else -1)
    if not step:
        return "skipped", "Could not locate the checkout step.", ""
    if "persist-credentials" in (step.with_ or {}):
        return "skipped", "`persist-credentials` is already set (to a non-false value); change it manually.", ""
    dash = step.line - 1
    if not (0 <= dash < len(fe.lines)):
        return "skipped", "Step line out of range.", ""
    kcol = _key_col(fe.lines[dash])
    review = "This job pushes with git; it needs a token for that push." if "git push" in str(job.data).lower() else ""
    if "with" in step.data:
        wi = step.key_line("with") - 1
        if not re.match(rf"^\s*(-\s+)?with\s*:\s*(#.*)?$", fe.lines[wi]):
            return "skipped", "`with:` uses inline/flow style; add `persist-credentials: false` manually.", ""
        fe.insert.append((wi + 1, [" " * _child_indent(fe.lines, wi, kcol) + "persist-credentials: false"]))
    else:
        uses_line = (step.key_line("uses") or step.line) - 1
        fe.insert.append((uses_line + 1, [" " * kcol + "with:", " " * (kcol + 2) + "persist-credentials: false"]))
    return "applied", f"Added `persist-credentials: false` to actions/checkout in job `{job.id}`.", review


def _fix_injection(fe: FileEdit, group: list[Finding], wf: Workflow, runs_on_windows: bool) -> tuple[str, str, str]:
    f0 = group[0]
    parts = str((f0.extra or {}).get("key", "")).split(":")
    if len(parts) < 3 or not parts[1].isdigit():
        return "skipped", "Could not locate the step.", ""
    job, step = _step(wf, parts[0], int(parts[1]))
    if not step or step.run is None:
        return "skipped", "Only `run:` scripts are fixed automatically; for github-script read values from `process.env` manually.", ""
    run_line = (step.key_line("run") or 0) - 1
    if run_line < 0:
        return "skipped", "Could not locate the `run:` key.", ""
    kcol = _key_col(fe.lines[run_line])
    defaults = job.data.get("defaults") if isinstance(job.data.get("defaults"), dict) else {}
    drun = defaults.get("run") if isinstance(defaults.get("run"), dict) else {}
    shell = str(step.data.get("shell") or drun.get("shell") or "").lower()
    if shell == "cmd":
        return "skipped", "cmd shell scripts are not rewritten automatically.", ""
    pwsh = "pwsh" in shell or "powershell" in shell or (not shell and runs_on_windows)
    env = step.data.get("env") if isinstance(step.data.get("env"), dict) else {}
    taken = {str(k).upper() for k in env}
    end = _block_end(fe.lines, run_line, kcol)
    exprs = list(dict.fromkeys(str((f.extra or {}).get("expression", "")) for f in group if (f.extra or {}).get("expression")))
    new_env, changed = [], 0
    for expr in exprs:
        inner = expr[3:-2].strip() if expr.startswith("${{") else expr
        var = _var_name(inner, taken)
        pat = re.compile(r"\$\{\{\s*" + re.escape(inner) + r"\s*\}\}")
        ref = f"$env:{var}" if pwsh else "${" + var + "}"
        hit = False
        for i in range(run_line, end):
            cur = fe.current(i)
            if i == run_line:  # only the value part of `run: ...`
                head, sep, tail = cur.partition("run:")
                new = head + sep + pat.sub(lambda _m: ref, tail)
            else:
                new = pat.sub(lambda _m: ref, cur)
            if new != cur:
                fe.replace[i] = new
                hit = True
        if hit:
            changed += 1
            new_env.append(f"{var}: {expr}")
    if not changed:
        return "skipped", "Expression not found in the run script.", ""
    if "env" in step.data:
        ei = step.key_line("env") - 1
        if not re.match(r"^\s*(-\s+)?env\s*:\s*(#.*)?$", fe.lines[ei]):
            return "skipped", "Step `env:` uses inline style; move the values manually.", ""
        ci = _child_indent(fe.lines, ei, kcol)
        fe.insert.append((ei + 1, [" " * ci + e for e in new_env]))
    else:
        # Before `run:`, unless `run:` is on the step's `- ` line; then after the script block (key order does not matter).
        at = end if re.match(r"^\s*-\s", fe.lines[run_line]) else run_line
        fe.insert.append((at, [" " * kcol + "env:"] + [" " * (kcol + 2) + e for e in new_env]))
    review = "Check the script's quoting: values are now expanded by the shell, not pasted into the code." if "'" in "".join(fe.lines[run_line:end]) else ""
    return "applied", f"Moved {changed} untrusted value(s) into env var(s) in job `{job.id}`.", review


# ---------------------------------------------------------------- verification

def _workflow_rule_keys(path: str, text: str) -> tuple[set[tuple], str | None]:
    wf = parse_workflow(path, text)
    if wf.error and not wf.jobs:
        return set(), wf.error
    ctx = ScanContext(root=Path("."), files=[path], workflows=[wf], metadata=RepoMetadata(source="upload"), options={})
    keys = set()
    for cls in load_rules().values():
        if not issubclass(cls, WorkflowRule):
            continue
        try:
            for fr in cls().check(ctx, wf):
                keys.add((fr.rule_id, fr.job, str(fr.extra.get("key", ""))))
        except Exception:  # noqa: BLE001 - a rule crash must not hide the result of others
            continue
    return keys, wf.error


def _fkey(f: Finding) -> tuple:
    return (f.rule_id, f.job, str((f.extra or {}).get("key", "")))


# ---------------------------------------------------------------- planning

def plan_fixes(sources: dict[str, str], findings: list[Finding], inventory: dict, resolve: PinResolver | None = None,
               custom_advisories: list[dict] | None = None) -> dict:
    advisories = all_advisories(custom_advisories)
    fixable = [f for f in findings if f.rule_id in FIXABLE_RULES and f.file_path in sources and f.triage_status not in ("false_positive", "fixed")]
    windows_jobs = {(w["path"], j["id"]) for w in inventory.get("workflows", []) for j in w.get("jobs") or []
                    if any("windows" in str(r).lower() for r in j.get("runs_on") or [])}
    by_file: dict[str, list[Finding]] = {}
    for f in fixable:
        by_file.setdefault(f.file_path, []).append(f)

    files, results, cache = [], [], {}
    for path, fs in sorted(by_file.items()):
        text = sources[path]
        lines, nl, trailing = _split(text)
        fe = FileEdit(path=path, lines=lines, newline=nl, trailing_newline=trailing)
        wf = parse_workflow(path, text)
        file_results = []
        groups: dict[tuple, list[Finding]] = {}
        for f in sorted(fs, key=lambda x: (x.line or 0)):
            if f.rule_id == "PT-PPE-003":
                parts = str((f.extra or {}).get("key", "")).split(":")
                groups.setdefault((parts[0], parts[1] if len(parts) > 1 else ""), []).append(f)
                continue
            if f.rule_id == "PT-3P-001":
                st = _fix_pin(fe, f, resolve, cache, advisories)
            elif f.rule_id == "PT-PBAC-001":
                st = _fix_permissions(fe, f, wf)
            else:
                st = _fix_persist(fe, f, wf)
            file_results.append((f, *st))
        for (jid, _sidx), group in groups.items():
            st = _fix_injection(fe, group, wf, (path, jid) in windows_jobs)
            file_results.extend((f, *st) for f in group)

        applied = [r for r in file_results if r[1] == "applied"]
        if not applied:
            results.extend(file_results)
            continue
        patched = fe.render()
        before, _ = _workflow_rule_keys(path, text)
        after, perr = _workflow_rule_keys(path, patched)
        ok_parse = not perr
        # Some rules key findings by line index, so compare counts per (rule, job) to detect genuinely new findings.
        cnt_b, cnt_a = {}, {}
        for k in before:
            cnt_b[k[:2]] = cnt_b.get(k[:2], 0) + 1
        for k in after:
            cnt_a[k[:2]] = cnt_a.get(k[:2], 0) + 1
        introduced = sorted(k for k, n in cnt_a.items() if n > cnt_b.get(k, 0))
        final = []
        for f, status, reason, review in file_results:
            verified = status == "applied" and ok_parse and _fkey(f) not in after
            final.append((f, status, reason, review, verified))
        results.extend(final)
        diff = "".join(difflib.unified_diff(text.splitlines(keepends=True), patched.splitlines(keepends=True),
                                            fromfile=f"a/{path}", tofile=f"b/{path}"))
        files.append({"path": path, "diff": diff, "patched": patched, "parse_error": perr,
                      "verified": ok_parse and not introduced, "introduced": [{"rule_id": k[0], "job": k[1]} for k in introduced],
                      "resolved": sum(1 for r in final if r[4]), "applied": len(applied)})

    out_fixes = []
    for r in results:
        f, status, reason, review = r[:4]
        verified = r[4] if len(r) > 4 else False
        out_fixes.append({"finding_id": f.id, "rule_id": f.rule_id, "label": FIX_LABELS[f.rule_id], "title": f.title, "severity": f.severity,
                          "file": f.file_path, "line": f.line, "job": f.job, "status": status, "detail": reason, "review": review,
                          "verified": bool(verified)})
    out_fixes.sort(key=lambda x: (x["file"], x["line"] or 0))
    patch = "".join(fl["diff"] for fl in files if not fl["parse_error"])
    return {
        "files": files, "fixes": out_fixes, "patch": patch,
        "summary": {"candidates": len(fixable), "applied": sum(1 for x in out_fixes if x["status"] == "applied"),
                    "verified": sum(1 for x in out_fixes if x["verified"]), "skipped": sum(1 for x in out_fixes if x["status"] == "skipped"),
                    "needs_review": sum(1 for x in out_fixes if x["review"]), "files": len(files),
                    "introduced": sum(len(fl["introduced"]) for fl in files)},
    }


# ---------------------------------------------------------------- GitHub I/O

class GitHubWriteError(Exception):
    pass


def _gh(token: str | None) -> httpx.Client:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "PipelineTrust-Fixer"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(base_url=get_settings().github_api_url.rstrip("/"), headers=headers, timeout=30.0, follow_redirects=False)


def fetch_sources(full_name: str, ref: str, paths: list[str], token: str | None) -> dict[str, str]:
    """Read workflow files at the scanned commit (fallback for scans made before sources were stored)."""
    out = {}
    with _gh(token) as c:
        for p in paths[:100]:
            r = c.get(f"/repos/{full_name}/contents/{p}", params={"ref": ref} if ref else None)
            if r.status_code == 200 and r.json().get("encoding") == "base64":
                out[p] = base64.b64decode(r.json()["content"]).decode("utf-8", errors="replace")
    return out


def open_pull_request(full_name: str, base_sha: str, files: dict[str, str], token: str, title: str, body: str) -> dict:
    """Create a branch at the scanned commit, commit the patched files and open a PR against the default branch.
    Needs a token with `contents: write` and `pull_requests: write` on the repository."""
    def need(r: httpx.Response, what: str):
        if r.status_code in (401, 403, 404):
            raise GitHubWriteError(f"{what}: HTTP {r.status_code} - the credential needs Contents: write and Pull requests: write on {full_name}")
        if r.status_code >= 300:
            msg = ""
            try:
                msg = r.json().get("message", "")
            except ValueError:
                pass
            raise GitHubWriteError(f"{what}: HTTP {r.status_code} {msg[:200]}")
        return r.json()

    with _gh(token) as c:
        repo = need(c.get(f"/repos/{full_name}"), "read repository")
        base_branch = repo.get("default_branch", "main")
        if not base_sha:
            base_sha = need(c.get(f"/repos/{full_name}/commits/{base_branch}"), "read default branch")["sha"]
        branch = f"pipelinetrust/fixes-{time.strftime('%Y%m%d-%H%M%S')}"
        need(c.post(f"/repos/{full_name}/git/refs", json={"ref": f"refs/heads/{branch}", "sha": base_sha}), "create branch")
        for path, text in files.items():
            cur = need(c.get(f"/repos/{full_name}/contents/{path}", params={"ref": branch}), f"read {path}")
            need(c.put(f"/repos/{full_name}/contents/{path}", json={
                "message": f"Harden {path}", "branch": branch, "sha": cur["sha"],
                "content": base64.b64encode(text.encode("utf-8")).decode("ascii")}), f"update {path}")
        pr = need(c.post(f"/repos/{full_name}/pulls", json={"title": title, "head": branch, "base": base_branch, "body": body}), "open pull request")
    return {"url": pr.get("html_url"), "number": pr.get("number"), "branch": branch, "base": base_branch}
