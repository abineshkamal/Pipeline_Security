"""Core scanner data model: workspace, parsed workflows, rule framework and results."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, ClassVar

from .yamlsafe import LineDict, LineList


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_ASSESSED = "NOT_ASSESSED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NEEDS_MANUAL_VALIDATION = "NEEDS_MANUAL_VALIDATION"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

CATEGORIES: dict[str, str] = {
    "CICD-SEC-1": "Insufficient Flow Control Mechanisms",
    "CICD-SEC-2": "Inadequate Identity and Access Management",
    "CICD-SEC-3": "Dependency Chain Abuse",
    "CICD-SEC-4": "Poisoned Pipeline Execution (PPE)",
    "CICD-SEC-5": "Insufficient Pipeline-Based Access Controls (PBAC)",
    "CICD-SEC-6": "Insufficient Credential Hygiene",
    "CICD-SEC-7": "Insecure System Configuration",
    "CICD-SEC-8": "Ungoverned Usage of Third-Party Services",
    "CICD-SEC-9": "Improper Artifact Integrity Validation",
    "CICD-SEC-10": "Insufficient Logging and Visibility",
}

CATEGORY_OBJECTIVES: dict[str, str] = {
    "CICD-SEC-1": "No single identity can push code or artifacts through the pipeline to production without independent review and approval.",
    "CICD-SEC-2": "Identities with access to CI/CD systems are known, least-privileged, strongly authenticated and reviewed.",
    "CICD-SEC-3": "Dependencies are fetched from trusted sources, pinned and verified, and known-vulnerable packages are visible.",
    "CICD-SEC-4": "Untrusted code or input (forks, PR metadata, comments) can never execute with access to secrets or write permissions.",
    "CICD-SEC-5": "Each pipeline job receives only the permissions and secrets it needs, scoped to the job.",
    "CICD-SEC-6": "Secrets are never hard-coded, exposed to untrusted contexts or printed; short-lived federated credentials are preferred.",
    "CICD-SEC-7": "Runners and pipeline infrastructure are hardened, isolated from untrusted workloads and free of dangerous settings.",
    "CICD-SEC-8": "Third-party actions, images and services are inventoried, governed and pinned to immutable references.",
    "CICD-SEC-9": "Artifacts are accompanied by an SBOM, signed, carry provenance, and are verified before consumption.",
    "CICD-SEC-10": "Pipeline activity, security checks and audit events are retained and visible to defenders.",
}

OWASP_REF = "https://owasp.org/www-project-top-10-ci-cd-security-risks/"
CATEGORY_REF = {
    "CICD-SEC-1": OWASP_REF + "CICD-SEC-01-Insufficient-Flow-Control-Mechanisms",
    "CICD-SEC-2": OWASP_REF + "CICD-SEC-02-Inadequate-Identity-And-Access-Management",
    "CICD-SEC-3": OWASP_REF + "CICD-SEC-03-Dependency-Chain-Abuse",
    "CICD-SEC-4": OWASP_REF + "CICD-SEC-04-Poisoned-Pipeline-Execution",
    "CICD-SEC-5": OWASP_REF + "CICD-SEC-05-Insufficient-PBAC",
    "CICD-SEC-6": OWASP_REF + "CICD-SEC-06-Insufficient-Credential-Hygiene",
    "CICD-SEC-7": OWASP_REF + "CICD-SEC-07-Insecure-System-Configuration",
    "CICD-SEC-8": OWASP_REF + "CICD-SEC-08-Ungoverned-Usage-of-3rd-Party-Services",
    "CICD-SEC-9": OWASP_REF + "CICD-SEC-09-Improper-Artifact-Integrity-Validation",
    "CICD-SEC-10": OWASP_REF + "CICD-SEC-10-Insufficient-Logging-And-Visibility",
}
GH_HARDENING = "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions"


# ---------------------------------------------------------------- workflow model

EXPR_RE = re.compile(r"\$\{\{\s*(.*?)\s*\}\}", re.S)


@dataclass
class Step:
    index: int
    data: dict
    line: int
    job_id: str

    @property
    def uses(self) -> str | None:
        v = self.data.get("uses")
        return str(v).strip() if isinstance(v, (str, int, float)) else None

    @property
    def run(self) -> str | None:
        v = self.data.get("run")
        return str(v) if v is not None and not isinstance(v, (dict, list)) else None

    @property
    def name(self) -> str:
        return str(self.data.get("name") or self.data.get("id") or self.uses or f"step {self.index + 1}")

    @property
    def with_(self) -> dict:
        w = self.data.get("with")
        return w if isinstance(w, dict) else {}

    @property
    def env(self) -> dict:
        e = self.data.get("env")
        return e if isinstance(e, dict) else {}

    def key_line(self, key: str) -> int:
        if isinstance(self.data, LineDict):
            return self.data.key_lines.get(key, self.line)
        return self.line

    def with_line(self, key: str) -> int:
        w = self.data.get("with")
        if isinstance(w, LineDict):
            return w.key_lines.get(key, self.key_line("with"))
        return self.key_line("with")

    def text(self) -> str:
        """All scalar text in the step (for keyword indicators)."""
        return flatten_text(self.data)


@dataclass
class Job:
    id: str
    data: dict
    line: int
    steps: list[Step] = field(default_factory=list)

    @property
    def name(self) -> str:
        return str(self.data.get("name") or self.id)

    @property
    def permissions(self) -> Any:
        return self.data.get("permissions", None)

    @property
    def has_permissions_key(self) -> bool:
        return "permissions" in self.data

    @property
    def runs_on(self) -> list[str]:
        ro = self.data.get("runs-on")
        if ro is None:
            return []
        if isinstance(ro, str):
            return [ro]
        if isinstance(ro, list):
            return [str(x) for x in ro]
        if isinstance(ro, dict):
            labels = ro.get("labels") or []
            group = ro.get("group")
            out = [str(x) for x in (labels if isinstance(labels, list) else [labels])]
            if group:
                out.append(f"group:{group}")
            return out
        return [str(ro)]

    @property
    def environment(self) -> str | None:
        env = self.data.get("environment")
        if isinstance(env, dict):
            return str(env.get("name")) if env.get("name") else None
        return str(env) if env else None

    @property
    def uses(self) -> str | None:  # reusable-workflow call
        u = self.data.get("uses")
        return str(u) if isinstance(u, str) else None

    @property
    def if_cond(self) -> str:
        v = self.data.get("if")
        return str(v) if v is not None else ""

    def key_line(self, key: str) -> int:
        if isinstance(self.data, LineDict):
            return self.data.key_lines.get(key, self.line)
        return self.line

    def text(self) -> str:
        return flatten_text(self.data)


@dataclass
class Workflow:
    path: str  # repo-relative, forward slashes
    text: str
    data: dict | None
    error: str | None = None
    error_line: int | None = None
    jobs: list[Job] = field(default_factory=list)

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()

    @property
    def name(self) -> str:
        if isinstance(self.data, dict) and self.data.get("name"):
            return str(self.data["name"])
        return self.path.rsplit("/", 1)[-1]

    @property
    def triggers(self) -> dict[str, Any]:
        on = self.data.get("on") if isinstance(self.data, dict) else None
        if on is None and isinstance(self.data, dict):
            on = self.data.get(True)
        if isinstance(on, str):
            return {on: None}
        if isinstance(on, list):
            return {str(x): None for x in on}
        if isinstance(on, dict):
            return {str(k): v for k, v in on.items()}
        return {}

    @property
    def permissions(self) -> Any:
        return self.data.get("permissions") if isinstance(self.data, dict) else None

    @property
    def has_permissions_key(self) -> bool:
        return isinstance(self.data, dict) and "permissions" in self.data

    def key_line(self, key: str) -> int | None:
        if isinstance(self.data, LineDict):
            return self.data.key_lines.get(key)
        return None

    def snippet(self, line: int | None, context: int = 1) -> str:
        if not line:
            return ""
        lines = self.lines
        lo, hi = max(0, line - 1 - context), min(len(lines), line + context)
        return "\n".join(f"{i + 1:>4} | {lines[i]}" for i in range(lo, hi))

    def find_line(self, needle: str, start: int = 1, end: int | None = None) -> int | None:
        lines = self.lines
        stop = min(len(lines), end) if end else len(lines)
        for i in range(max(0, start - 1), stop):
            if needle in lines[i]:
                return i + 1
        return None

    def env_at(self, job: Job, step: Step | None = None) -> dict:
        env: dict = {}
        for src in (self.data.get("env") if isinstance(self.data, dict) else None, job.data.get("env"), step.env if step else None):
            if isinstance(src, dict):
                env.update(src)
        return env


def flatten_text(obj: Any) -> str:
    out: list[str] = []

    def walk(o: Any, depth: int = 0) -> None:
        if depth > 30:
            return
        if isinstance(o, dict):
            for k, v in o.items():
                out.append(str(k))
                walk(v, depth + 1)
        elif isinstance(o, list):
            for v in o:
                walk(v, depth + 1)
        elif o is not None:
            out.append(str(o))

    walk(obj)
    return "\n".join(out)


def parse_workflow(path: str, text: str) -> Workflow:
    from .yamlsafe import YamlError, load_yaml

    try:
        data = load_yaml(text)
    except YamlError as exc:
        return Workflow(path=path, text=text, data=None, error=str(exc), error_line=exc.line)
    if not isinstance(data, dict):
        return Workflow(path=path, text=text, data=None, error="top-level YAML value is not a mapping")
    wf = Workflow(path=path, text=text, data=data)
    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        wf.error = "workflow has no 'jobs' mapping"
        return wf
    for jid, jdata in jobs.items():
        if not isinstance(jdata, dict):
            continue
        jline = jobs.key_lines.get(jid, 0) if isinstance(jobs, LineDict) else 0
        job = Job(id=str(jid), data=jdata, line=jline)
        steps = jdata.get("steps")
        if isinstance(steps, list):
            for i, s in enumerate(steps):
                if isinstance(s, dict):
                    sline = steps.item_lines[i] if isinstance(steps, LineList) and i < len(steps.item_lines) else jline
                    job.steps.append(Step(index=i, data=s, line=sline, job_id=job.id))
        wf.jobs.append(job)
    return wf


# ---------------------------------------------------------------- assessment context

@dataclass
class ApiResult:
    """Result of one GitHub API metadata collection. status: ok | none | forbidden | error | skipped"""
    status: str
    data: Any = None
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status in ("ok", "none")


@dataclass
class RepoMetadata:
    source: str  # github | upload
    full_name: str = ""
    default_branch: str = ""
    visibility: str = ""  # public | private | internal | ""
    owner_type: str = ""
    collected: dict[str, ApiResult] = field(default_factory=dict)

    def get(self, key: str) -> ApiResult:
        return self.collected.get(key) or ApiResult("skipped", detail="not collected (offline / ZIP assessment)")

    @property
    def is_public(self) -> bool | None:
        return None if not self.visibility else self.visibility == "public"


@dataclass
class ScanContext:
    root: Path
    files: list[str]  # all repo-relative file paths (forward slashes)
    workflows: list[Workflow]
    metadata: RepoMetadata
    options: dict = field(default_factory=dict)
    tool_results: dict[str, Any] = field(default_factory=dict)

    @property
    def parsed_workflows(self) -> list[Workflow]:
        return [w for w in self.workflows if w.data is not None and not (w.error and not w.jobs)]

    def read_text(self, rel: str, limit: int = 1_000_000) -> str | None:
        p = (self.root / rel).resolve()
        try:
            if not p.is_relative_to(self.root.resolve()) or not p.is_file() or p.stat().st_size > limit:
                return None
            return p.read_text("utf-8", errors="replace")
        except OSError:
            return None


# ---------------------------------------------------------------- results

@dataclass
class FindingResult:
    rule_id: str
    category: str
    title: str
    severity: str
    message: str
    evidence_type: str = "configuration"  # configuration | inferred | tool
    confidence: str = "high"
    file_path: str = ""
    line: int | None = None
    snippet: str = ""
    workflow: str = ""
    job: str = ""
    extra: dict = field(default_factory=dict)
    risk_score: float = 0.0

    @property
    def fingerprint(self) -> str:
        key = "|".join([self.rule_id, self.file_path, self.job, str(self.extra.get("key", "")), self.message[:160]])
        return hashlib.sha256(key.encode()).hexdigest()[:32]


@dataclass
class RuleOutcome:
    status: Status
    findings: list[FindingResult] = field(default_factory=list)
    note: str = ""
    evidence: list[str] = field(default_factory=list)  # human-readable evidence for PASS / manual


class Rule:
    """Base class for detection rules. Subclasses are auto-registered on import."""

    registry: ClassVar[dict[str, type[Rule]]] = {}

    id: ClassVar[str] = ""
    category: ClassVar[str] = ""
    title: ClassVar[str] = ""
    description: ClassVar[str] = ""
    severity: ClassVar[str] = "medium"
    cwe: ClassVar[list[str]] = []
    references: ClassVar[list[str]] = []
    remediation: ClassVar[str] = ""
    evidence_requirements: ClassVar[str] = ""
    false_positives: ClassVar[str] = ""
    data_sources: ClassVar[list[str]] = ["workflows"]  # workflows | repo_files | github_api | tool:<name>

    def __init_subclass__(cls, **kw):
        super().__init_subclass__(**kw)
        if cls.id:
            if cls.id in Rule.registry and Rule.registry[cls.id] is not cls:
                raise ValueError(f"duplicate rule id {cls.id}")
            Rule.registry[cls.id] = cls

    # -- helpers
    def finding(self, message: str, *, wf: Workflow | None = None, job: Job | None = None, line: int | None = None,
                severity: str | None = None, evidence_type: str = "configuration", confidence: str = "high",
                file_path: str | None = None, snippet: str | None = None, title: str | None = None, **extra) -> FindingResult:
        return FindingResult(
            rule_id=self.id, category=self.category, title=title or self.title, severity=severity or self.severity,
            message=message, evidence_type=evidence_type, confidence=confidence,
            file_path=file_path if file_path is not None else (wf.path if wf else ""),
            line=line, snippet=snippet if snippet is not None else (wf.snippet(line) if wf and line else ""),
            workflow=wf.name if wf else "", job=job.id if job else "", extra=extra,
        )

    def outcome_from(self, findings: list[FindingResult], pass_evidence: str = "", note: str = "") -> RuleOutcome:
        if findings:
            return RuleOutcome(Status.FAIL, findings, note=note)
        return RuleOutcome(Status.PASS, [], note=note, evidence=[pass_evidence] if pass_evidence else [])

    def evaluate(self, ctx: ScanContext) -> RuleOutcome:  # pragma: no cover - abstract
        raise NotImplementedError

    @classmethod
    def describe(cls) -> dict:
        return {
            "id": cls.id, "category": cls.category, "category_name": CATEGORIES.get(cls.category, ""),
            "title": cls.title, "description": cls.description, "severity": cls.severity, "cwe": cls.cwe,
            "references": [CATEGORY_REF.get(cls.category, OWASP_REF), *cls.references],
            "remediation": cls.remediation, "evidence_requirements": cls.evidence_requirements,
            "false_positives": cls.false_positives, "data_sources": cls.data_sources,
            "objective": CATEGORY_OBJECTIVES.get(cls.category, ""),
        }


class WorkflowRule(Rule):
    """Rule over GitHub Actions workflows. NOT_APPLICABLE when the repository has none."""

    def evaluate(self, ctx: ScanContext) -> RuleOutcome:
        wfs = ctx.parsed_workflows
        if not wfs:
            return RuleOutcome(Status.NOT_APPLICABLE, note="No parseable GitHub Actions workflows found.")
        findings: list[FindingResult] = []
        for wf in wfs:
            findings.extend(self.check(ctx, wf))
        return self.outcome_from(findings, pass_evidence=f"Checked {len(wfs)} workflow(s); no violations.")

    def check(self, ctx: ScanContext, wf: Workflow) -> list[FindingResult]:  # pragma: no cover
        raise NotImplementedError
