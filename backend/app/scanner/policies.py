"""Organization policies (policy-as-code).

A policy is a small YAML/JSON document evaluated against the scan inventory. It produces ordinary findings and a
control, so policies take part in scoring, triage, reports, attack paths and compliance exactly like built-in rules.

    id: ORG-PUB-001
    title: Only approved action publishers
    severity: high                 # critical | high | medium | low | info
    category: CICD-SEC-8           # an OWASP CI/CD category
    target: action                 # workflow | job | action
    when:                          # every condition must hold (AND)
      - {field: first_party, equals: false}
      - {field: owner, not_in: [my-org, docker]}
    unless:                        # optional exceptions: skip the item if all of these hold
      - {field: workflow, matches: "^\\.github/workflows/experimental-"}
    message: "{uses} comes from unapproved publisher {owner}"
    remediation: Use an approved action or ask the platform team to vet this one.

Operators: equals, not_equals, in, not_in, contains, not_contains, matches, not_matches, is_empty (true/false).
`contains` checks list membership for list fields and substring for text. Regexes are length-limited.
"""
from __future__ import annotations

import re
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from .model import CATEGORIES, FindingResult

TARGET_FIELDS: dict[str, dict[str, str]] = {
    "workflow": {"path": "text", "name": "text", "triggers": "list", "external_triggers": "list", "privileged_triggers": "list",
                 "has_permissions": "bool", "job_count": "number"},
    "job": {"workflow": "text", "workflow_name": "text", "triggers": "list", "external_triggers": "list", "privileged_triggers": "list",
            "id": "text", "name": "text", "runs_on": "list", "self_hosted": "bool", "environment": "text", "secrets": "list",
            "write_scopes": "list", "permissions_source": "text", "deploys": "bool", "steps": "number", "reusable": "text"},
    "action": {"uses": "text", "owner": "text", "action": "text", "ref": "text", "kind": "text", "sha_pinned": "bool",
               "first_party": "bool", "workflow": "text", "job": "text"},
}
OPERATORS = ("equals", "not_equals", "in", "not_in", "contains", "not_contains", "matches", "not_matches", "is_empty")
SEVERITIES = ("critical", "high", "medium", "low", "info")
MAX_REGEX = 200


class PolicyError(ValueError):
    pass


class Condition(BaseModel):
    model_config = {"extra": "forbid"}
    field: str
    equals: Any = None
    not_equals: Any = None
    in_: list | None = Field(default=None, alias="in")
    not_in: list | None = None
    contains: Any = None
    not_contains: Any = None
    matches: str | None = None
    not_matches: str | None = None
    is_empty: bool | None = None

    @model_validator(mode="after")
    def one_operator(self):
        used = [op for op in OPERATORS if getattr(self, "in_" if op == "in" else op) is not None]
        if len(used) != 1:
            raise ValueError(f"condition on '{self.field}' must use exactly one operator ({', '.join(OPERATORS)})")
        for op in ("matches", "not_matches"):
            pat = getattr(self, op)
            if pat is not None:
                if len(pat) > MAX_REGEX:
                    raise ValueError(f"regex longer than {MAX_REGEX} characters")
                try:
                    re.compile(pat)
                except re.error as exc:
                    raise ValueError(f"invalid regex: {exc}") from exc
        return self

    @property
    def op(self) -> tuple[str, Any]:
        for op in OPERATORS:
            v = getattr(self, "in_" if op == "in" else op)
            if v is not None:
                return op, v
        raise PolicyError("no operator")  # pragma: no cover - guarded by validator


class Policy(BaseModel):
    model_config = {"extra": "forbid"}
    id: str = Field(pattern=r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$", max_length=40)
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=2000)
    severity: str = "medium"
    category: str
    target: str
    when: list[Condition] = Field(min_length=1, max_length=20)
    unless: list[Condition] = Field(default_factory=list, max_length=20)
    message: str = Field(default="", max_length=500)
    remediation: str = Field(default="", max_length=2000)

    @field_validator("id")
    @classmethod
    def not_builtin(cls, v: str) -> str:
        if v.startswith("PT-"):
            raise ValueError("ids starting with PT- are reserved for built-in rules")
        return v

    @field_validator("severity")
    @classmethod
    def sev(cls, v: str) -> str:
        if v not in SEVERITIES:
            raise ValueError(f"severity must be one of {', '.join(SEVERITIES)}")
        return v

    @field_validator("category")
    @classmethod
    def cat(cls, v: str) -> str:
        if v not in CATEGORIES:
            raise ValueError(f"category must be one of {', '.join(CATEGORIES)}")
        return v

    @model_validator(mode="after")
    def fields_exist(self):
        if self.target not in TARGET_FIELDS:
            raise ValueError(f"target must be one of {', '.join(TARGET_FIELDS)}")
        known = TARGET_FIELDS[self.target]
        for c in [*self.when, *self.unless]:
            if c.field not in known:
                raise ValueError(f"unknown field '{c.field}' for target '{self.target}' (known: {', '.join(known)})")
        return self


def parse_policy(source: str) -> dict:
    """Parse and validate a policy document (YAML or JSON). Returns the normalized definition."""
    if len(source) > 20_000:
        raise PolicyError("policy document is too large")
    try:
        data = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise PolicyError(f"invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError("policy must be a mapping")
    try:
        p = Policy.model_validate(data)
    except ValidationError as exc:
        raise PolicyError("; ".join(f"{'.'.join(str(x) for x in e['loc']) or 'policy'}: {e['msg']}" for e in exc.errors())) from exc
    return p.model_dump(by_alias=True, exclude_none=True)


# ---------------------------------------------------------------- evaluation

def _items(target: str, inv: dict) -> list[tuple[dict, dict]]:
    """(record, location) pairs for a target type, built from the stored inventory."""
    out = []
    wfs = inv.get("workflows", [])
    if target == "workflow":
        for w in wfs:
            out.append(({"path": w["path"], "name": w.get("name") or "", "triggers": w.get("triggers") or [],
                         "external_triggers": w.get("external_triggers") or [], "privileged_triggers": w.get("privileged_triggers") or [],
                         "has_permissions": w.get("permissions") is not None, "job_count": len(w.get("jobs") or [])},
                        {"file_path": w["path"], "line": 1, "job": "", "workflow": w.get("name") or ""}))
    elif target == "job":
        for w in wfs:
            for j in w.get("jobs") or []:
                out.append(({"workflow": w["path"], "workflow_name": w.get("name") or "", "triggers": w.get("triggers") or [],
                             "external_triggers": w.get("external_triggers") or [], "privileged_triggers": w.get("privileged_triggers") or [],
                             "id": j["id"], "name": j.get("name") or "", "runs_on": j.get("runs_on") or [], "self_hosted": bool(j.get("self_hosted")),
                             "environment": j.get("environment") or "", "secrets": j.get("secrets") or [], "write_scopes": j.get("write_scopes") or [],
                             "permissions_source": j.get("permissions_source") or "", "deploys": bool(j.get("deploy_indicators")),
                             "steps": j.get("steps") or 0, "reusable": j.get("reusable") or ""},
                            {"file_path": w["path"], "line": j.get("line") or None, "job": j["id"], "workflow": w.get("name") or ""}))
    elif target == "action":
        names = {w["path"]: w.get("name") or "" for w in wfs}
        for a in inv.get("actions", []):
            occ = a.get("occurrences") or [{"workflow": p, "job": "", "line": None} for p in a.get("workflows", [])]
            for o in occ:
                out.append(({"uses": a["uses"], "owner": a.get("owner") or "", "action": a.get("action") or "", "ref": a.get("ref") or "",
                             "kind": a.get("kind") or "", "sha_pinned": bool(a.get("sha_pinned")), "first_party": bool(a.get("first_party")),
                             "workflow": o["workflow"], "job": o.get("job") or ""},
                            {"file_path": o["workflow"], "line": o.get("line"), "job": o.get("job") or "", "workflow": names.get(o["workflow"], "")}))
    return out


def _norm(v):
    return v.lower() if isinstance(v, str) else v


def _check(cond: dict, rec: dict) -> bool:
    val = rec.get(cond["field"])
    op = next(o for o in OPERATORS if o in cond)
    arg = cond[op]
    if op == "equals":
        return _norm(val) == _norm(arg)
    if op == "not_equals":
        return _norm(val) != _norm(arg)
    if op in ("in", "not_in"):
        opts = {_norm(x) for x in arg}
        hit = bool(opts & {_norm(x) for x in val}) if isinstance(val, list) else _norm(val) in opts
        return hit if op == "in" else not hit
    if op in ("contains", "not_contains"):
        if isinstance(val, list):
            hit = _norm(arg) in {_norm(x) for x in val}
        else:
            hit = str(_norm(arg)) in str(_norm(val) or "")
        return hit if op == "contains" else not hit
    if op in ("matches", "not_matches"):
        vals = val if isinstance(val, list) else [val]
        hit = any(re.search(arg, str(x or "")) for x in vals)
        return hit if op == "matches" else not hit
    if op == "is_empty":
        empty = val in (None, "", [], 0, False)
        return empty if arg else not empty
    return False  # pragma: no cover


def _fmt(template: str, rec: dict) -> str:
    def sub(m):
        v = rec.get(m.group(1))
        return ", ".join(map(str, v)) if isinstance(v, list) else str(v) if v is not None else m.group(0)
    return re.sub(r"\{(\w+)\}", sub, template)


def evaluate_policy(p: dict, inv: dict) -> tuple[dict, list[FindingResult]]:
    items = _items(p["target"], inv)
    findings = []
    for rec, loc in items:
        if all(_check(c, rec) for c in p["when"]) and not (p.get("unless") and all(_check(c, rec) for c in p["unless"])):
            label = rec.get("uses") or (f"job `{rec.get('id')}`" if p["target"] == "job" else rec.get("path") or "")
            msg = _fmt(p["message"], rec) if p.get("message") else f"{p['title']}: {label}"
            findings.append(FindingResult(
                rule_id=p["id"], category=p["category"], title=p["title"], severity=p["severity"], message=msg,
                evidence_type="configuration", confidence="high", file_path=loc["file_path"], line=loc["line"],
                workflow=loc["workflow"], job=loc["job"],
                extra={"key": f"{loc['file_path']}:{loc['job']}:{rec.get('uses', '')}", "policy": True, "target": p["target"]},
            ))
    status = "NOT_APPLICABLE" if not items else "FAIL" if findings else "PASS"
    control = {
        "rule_id": p["id"], "category": p["category"], "category_name": CATEGORIES.get(p["category"], ""), "title": p["title"],
        "severity": p["severity"], "status": status, "note": "Organization policy" + (f" - checked {len(items)} {p['target']}(s)" if items else ""),
        "evidence": [] if findings else ([f"Checked {len(items)} {p['target']}(s); no violations."] if items else []),
        "finding_count": len(findings), "data_sources": ["policy"],
    }
    return control, findings


def evaluate_policies(policies: list[dict], inv: dict) -> tuple[list[dict], list[FindingResult]]:
    controls, findings = [], []
    for p in policies:
        c, fs = evaluate_policy(p, inv)
        controls.append(c)
        findings.extend(fs)
    return controls, findings


EXAMPLES = [
    """id: ORG-PUB-001
title: Only approved action publishers
severity: high
category: CICD-SEC-8
target: action
when:
  - {field: first_party, equals: false}
  - {field: owner, not_in: [docker, aws-actions, azure, google-github-actions]}
message: "{uses} comes from publisher {owner}, which is not on the approved list"
remediation: Use an approved action, or ask the platform team to vet this publisher.""",
    """id: ORG-DEPLOY-001
title: Deploy jobs must use a protected environment
severity: high
category: CICD-SEC-1
target: job
when:
  - {field: deploys, equals: true}
  - {field: environment, is_empty: true}
message: "Job {id} in {workflow} deploys without an environment"
remediation: Add `environment:` with required reviewers to every deploy job.""",
    """id: ORG-RUNNER-001
title: No self-hosted runners on externally triggered workflows
severity: critical
category: CICD-SEC-7
target: job
when:
  - {field: self_hosted, equals: true}
  - {field: external_triggers, is_empty: false}
message: "Job {id} runs on a self-hosted runner and can be triggered by {external_triggers}"
remediation: Use GitHub-hosted runners for workflows that outsiders can trigger.""",
]
