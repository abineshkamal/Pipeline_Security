"""GitHub Actions security semantics shared by rules."""
from __future__ import annotations

import re
from dataclasses import dataclass

from .model import EXPR_RE, Job, Step, Workflow

# Events an outside actor (no write access) can cause to fire.
EXTERNAL_TRIGGERS = {
    "pull_request", "pull_request_target", "issue_comment", "issues", "discussion", "discussion_comment",
    "pull_request_review", "pull_request_review_comment", "fork", "watch", "workflow_run",
}
# Externally-triggerable events that nevertheless run in the *base repository* context with secrets
# and a potentially write-scoped GITHUB_TOKEN.
PRIVILEGED_EXTERNAL_TRIGGERS = {"pull_request_target", "issue_comment", "issues", "discussion", "discussion_comment", "workflow_run"}

# Attacker-controllable expression contexts (GitHub Security Lab list, extended).
UNTRUSTED_EXPR_PATTERNS = [
    r"github\.event\.(issue|pull_request|discussion)\.(title|body)",
    r"github\.event\.(comment|review|review_comment|discussion_comment)\.body",
    r"github\.event\.pull_request\.head\.(ref|label|repo\.default_branch|repo\.description|repo\.name)",
    r"github\.event\.pull_request\.head\.repo\.owner",
    r"github\.head_ref",
    r"github\.event\.(head_commit|commits\[?.*?\]?|commits\.\*)\.(message|author\.(email|name))",
    r"github\.event\.commits",
    r"github\.event\.head_commit\.(message|author)",
    r"github\.event\.workflow_run\.(head_branch|head_commit\.(message|author)|display_title|pull_requests)",
    r"github\.event\.pages\.",
    r"github\.event\.(issue|pull_request)\.labels",
    r"github\.event\.inputs\.",  # dispatch inputs are typically trusted, flagged low elsewhere
]
_UNTRUSTED_RE = re.compile("|".join(f"(?:{p})" for p in UNTRUSTED_EXPR_PATTERNS[:-1]))
_DISPATCH_INPUT_RE = re.compile(r"(github\.event\.inputs\.|inputs\.)[A-Za-z0-9_-]+")

PR_HEAD_REF_RE = re.compile(
    r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|refs/pull/|github\.event\.workflow_run\.head_(sha|branch)"
    r"|github\.event\.issue\.number|github\.event\.number|steps\.[\w-]+\.outputs\.(head_)?(sha|ref)"
)
PR_CHECKOUT_CMD_RE = re.compile(r"\b(gh\s+pr\s+checkout|git\s+fetch\s+\S+\s+(\+)?refs?/?pull|git\s+fetch\s+origin\s+pull/|git\s+checkout\s+.*(head|pr|pull))", re.I)

SECRET_REF_RE = re.compile(r"secrets\.([A-Za-z_][A-Za-z0-9_]*)|secrets\[\s*['\"]([^'\"]+)['\"]\s*\]")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
FIRST_PARTY_OWNERS = {"actions", "github"}

WRITE_SCOPES = {
    "actions", "attestations", "checks", "contents", "deployments", "discussions", "id-token", "issues",
    "packages", "pages", "pull-requests", "repository-projects", "security-events", "statuses", "models",
}
HIGH_IMPACT_WRITE = {"contents", "packages", "id-token", "actions", "deployments", "pull-requests", "pages", "attestations"}


def untrusted_expressions(text: str) -> list[str]:
    """Return attacker-controllable ${{ }} expressions found in text."""
    out = []
    for m in EXPR_RE.finditer(text or ""):
        expr = m.group(1)
        if _UNTRUSTED_RE.search(expr):
            out.append(m.group(0))
    return out


def dispatch_input_expressions(text: str) -> list[str]:
    return [m.group(0) for m in EXPR_RE.finditer(text or "") if _DISPATCH_INPUT_RE.search(m.group(1))]


def secret_names(text: str) -> set[str]:
    names = set()
    for m in SECRET_REF_RE.finditer(text or ""):
        n = m.group(1) or m.group(2)
        if n:
            names.add(n)
    return names


def job_secret_names(job: Job) -> set[str]:
    names = secret_names(job.text())
    names.discard("GITHUB_TOKEN")
    return names


@dataclass
class ActionRef:
    raw: str
    kind: str  # action | docker | local | reusable
    owner: str = ""
    repo: str = ""
    path: str = ""
    ref: str = ""

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}" + (f"/{self.path}" if self.path else "")

    @property
    def is_sha_pinned(self) -> bool:
        return bool(SHA_RE.match(self.ref))

    @property
    def is_first_party(self) -> bool:
        return self.owner.lower() in FIRST_PARTY_OWNERS

    @property
    def looks_like_branch(self) -> bool:
        return self.ref.lower() in {"main", "master", "develop", "dev", "trunk", "latest", "head"} or (
            not self.ref[:1].isdigit() and not self.ref.lower().startswith("v") and not self.is_sha_pinned)


def parse_uses(uses: str) -> ActionRef | None:
    if not uses:
        return None
    u = uses.strip()
    if u.startswith("./") or u.startswith("../"):
        return ActionRef(raw=u, kind="local", path=u)
    if u.startswith("docker://"):
        img = u[len("docker://"):]
        return ActionRef(raw=u, kind="docker", path=img, ref=img.split("@", 1)[1] if "@" in img else "")
    if "@" not in u:
        return ActionRef(raw=u, kind="action", owner=u.split("/")[0], repo=(u.split("/") + [""])[1], ref="")
    target, ref = u.rsplit("@", 1)
    parts = target.split("/")
    kind = "reusable" if "/.github/workflows/" in target else "action"
    return ActionRef(raw=u, kind=kind, owner=parts[0], repo=parts[1] if len(parts) > 1 else "",
                     path="/".join(parts[2:]), ref=ref)


def normalize_permissions(perms) -> dict[str, str] | None:
    """Return {scope: level} or None when not declared. 'write-all'/'read-all' expanded; {} = no permissions."""
    if perms is None:
        return None
    if isinstance(perms, str):
        p = perms.strip().lower()
        if p == "write-all":
            return {s: "write" for s in WRITE_SCOPES}
        if p == "read-all":
            return {s: "read" for s in WRITE_SCOPES}
        return {}
    if isinstance(perms, dict):
        return {str(k): str(v).lower() for k, v in perms.items()}
    return {}


def write_scopes(perms) -> set[str]:
    norm = normalize_permissions(perms)
    if not norm:
        return set()
    return {k for k, v in norm.items() if v == "write"}


def effective_job_permissions(wf: Workflow, job: Job):
    """Job-level permissions override workflow-level ones. Returns (perms|None, source)."""
    if job.has_permissions_key:
        return job.permissions, "job"
    if wf.has_permissions_key:
        return wf.permissions, "workflow"
    return None, "default"


def is_self_hosted(job: Job) -> bool:
    labels = [x.lower() for x in job.runs_on]
    if any("self-hosted" in x for x in labels):
        return True
    # runner groups and non-GitHub-hosted labels are typically self-hosted / larger runners
    if any(x.startswith("group:") for x in labels):
        return True
    return False


def external_triggers(wf: Workflow) -> set[str]:
    return set(wf.triggers) & EXTERNAL_TRIGGERS


def privileged_external_triggers(wf: Workflow) -> set[str]:
    return set(wf.triggers) & PRIVILEGED_EXTERNAL_TRIGGERS


def step_executes_code(step: Step) -> bool:
    """A step that runs commands or third-party code (as opposed to pure metadata)."""
    if step.run:
        return True
    ref = parse_uses(step.uses or "")
    if not ref:
        return False
    if ref.kind in ("local", "docker"):
        return True
    benign = {"actions/checkout", "actions/upload-artifact", "actions/download-artifact", "actions/cache", "actions/github-script"}
    return f"{ref.owner}/{ref.repo}".lower() not in benign or (f"{ref.owner}/{ref.repo}".lower() == "actions/github-script")


def checkout_steps(job: Job) -> list[Step]:
    return [s for s in job.steps if (s.uses or "").lower().startswith("actions/checkout")]


def untrusted_checkout(job: Job) -> tuple[Step, str] | None:
    """Return (step, reason) if the job checks out PR-controlled code."""
    for s in job.steps:
        uses = (s.uses or "").lower()
        if uses.startswith("actions/checkout"):
            ref = str(s.with_.get("ref", "")) + " " + str(s.with_.get("repository", ""))
            if PR_HEAD_REF_RE.search(ref) or "head.repo.full_name" in ref:
                return s, f"actions/checkout with ref/repository `{ref.strip()}`"
        if s.run and PR_CHECKOUT_CMD_RE.search(s.run):
            return s, "shell command fetching/checking out PR code"
    return None


DEPLOY_ACTIONS = (
    "aws-actions/configure-aws-credentials", "azure/login", "google-github-actions/auth", "azure/webapps-deploy",
    "peaceiris/actions-gh-pages", "actions/deploy-pages", "jamesives/github-pages-deploy-action", "appleboy/ssh-action",
    "pypa/gh-action-pypi-publish", "softprops/action-gh-release", "azure/k8s-deploy", "google-github-actions/deploy-",
    "aws-actions/amazon-ecs-deploy-task-definition", "cloudflare/wrangler-action", "amondnet/vercel-action",
    "hashicorp/setup-terraform", "azure/functions-action", "google-github-actions/get-gke-credentials",
)
DEPLOY_CMD_RE = re.compile(
    r"\b(kubectl\s+(apply|set|rollout|create)|helm\s+(upgrade|install)|terraform\s+apply|pulumi\s+up|npm\s+publish|yarn\s+publish|"
    r"pnpm\s+publish|twine\s+upload|docker\s+push|gh\s+release\s+create|vercel\s+.*--prod|firebase\s+deploy|serverless\s+deploy|"
    r"sls\s+deploy|aws\s+s3\s+(sync|cp)|az\s+webapp\s+deploy|gcloud\s+(run|app|functions)\s+deploy|cargo\s+publish|gem\s+push|"
    r"mvn\s+.*deploy|gradle\s+.*publish|goreleaser|ansible-playbook|scp\s+|rsync\s+.*@|dotnet\s+nuget\s+push|poetry\s+publish)",
    re.I,
)
PUBLISH_CMD_RE = re.compile(
    r"\b(npm\s+publish|yarn\s+publish|pnpm\s+publish|twine\s+upload|docker\s+push|gh\s+release\s+create|cargo\s+publish|gem\s+push|"
    r"mvn\s+.*deploy|gradle\s+.*publish|goreleaser|dotnet\s+nuget\s+push|poetry\s+publish|docker\s+buildx\s+.*--push|crane\s+push|ko\s+publish)",
    re.I,
)
PUBLISH_ACTIONS = ("docker/build-push-action", "pypa/gh-action-pypi-publish", "softprops/action-gh-release",
                   "goreleaser/goreleaser-action", "ncipollo/release-action", "actions/create-release", "jreleaser/release-action")


def job_deploy_indicators(job: Job) -> list[str]:
    hits = []
    name = f"{job.id} {job.name}".lower()
    if any(k in name for k in ("deploy", "release", "publish", "prod", "rollout", "ship")):
        hits.append(f"job name `{job.id}`")
    for s in job.steps:
        u = (s.uses or "").lower()
        if any(u.startswith(a) for a in DEPLOY_ACTIONS + PUBLISH_ACTIONS):
            if u.startswith("docker/build-push-action") and str(s.with_.get("push", "false")).lower() == "false":
                continue
            hits.append(f"step uses `{s.uses}`")
        if s.run:
            m = DEPLOY_CMD_RE.search(s.run)
            if m:
                hits.append(f"command `{m.group(0).strip()[:60]}`")
    return hits


def job_publishes(job: Job) -> list[str]:
    hits = []
    for s in job.steps:
        u = (s.uses or "").lower()
        if any(u.startswith(a) for a in PUBLISH_ACTIONS):
            if u.startswith("docker/build-push-action") and str(s.with_.get("push", "false")).lower() == "false":
                continue
            hits.append(f"`{s.uses}`")
        if s.run:
            m = PUBLISH_CMD_RE.search(s.run)
            if m:
                hits.append(f"`{m.group(0).strip()[:60]}`")
    return hits


GATE_RE = re.compile(r"labels|github\.actor\s*==|author_association|github\.event\.pull_request\.head\.repo\.full_name\s*==|github\.repository_owner|fork\s*==\s*false|head\.repo\.fork", re.I)


def job_is_gated(job: Job, wf: Workflow) -> str:
    """Return a description of a mitigating gate on the job (label/actor/fork check, protected environment)."""
    conds = [job.if_cond]
    for s in job.steps[:1]:
        conds.append(str(s.data.get("if", "")))
    joined = " ".join(c for c in conds if c)
    if GATE_RE.search(joined):
        return f"job condition `{joined.strip()[:160]}`"
    if job.environment:
        return f"environment `{job.environment}` (may require approval)"
    return ""
