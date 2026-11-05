"""Detection-rule tests against the vulnerable and hardened sample repositories (no external tools)."""
from pathlib import Path

import pytest

from app.scanner.engine import run_assessment
from app.scanner.model import ApiResult, RepoMetadata, parse_workflow
from app.scanner.rules import load_rules
from app.scanner.yamlsafe import YamlError, load_yaml

from .conftest import SAMPLES


@pytest.fixture(scope="module")
def vuln():
    return run_assessment(SAMPLES / "vulnerable-repo", RepoMetadata(source="upload"), {"run_tools": False})


@pytest.fixture(scope="module")
def hardened():
    return run_assessment(SAMPLES / "hardened-repo", RepoMetadata(source="upload"), {"run_tools": False})


def status(res, rid):
    return next(c["status"] for c in res.controls if c["rule_id"] == rid)


def findings(res, rid):
    return [f for f in res.findings if f.rule_id == rid]


def test_rule_registry_covers_all_ten_categories():
    rules = load_rules()
    cats = {c.category for c in rules.values()}
    assert {f"CICD-SEC-{i}" for i in range(1, 11)} <= cats
    assert len(rules) >= 40
    for rid, c in rules.items():
        d = c.describe()
        assert d["title"] and d["description"] and d["remediation"] and d["severity"], rid
        assert d["references"], rid


@pytest.mark.parametrize("rid,expected_line,needle", [
    ("PT-PPE-001", 10, "pull_request_target"),
    ("PT-CRED-001", 14, "AWS access key"),
    ("PT-SYS-001", 12, "self-hosted"),
])
def test_exact_line_evidence(vuln, rid, expected_line, needle):
    fs = findings(vuln, rid)
    assert fs, rid
    assert any(f.line == expected_line and needle in f.message for f in fs), [(f.line, f.message) for f in fs]


def test_script_injection_lines(vuln):
    fs = findings(vuln, "PT-PPE-003")
    assert {(f.file_path, f.line) for f in fs} == {(".github/workflows/issue-triage.yml", 17), (".github/workflows/issue-triage.yml", 18),
                                                   (".github/workflows/issue-triage.yml", 22)}
    assert all(f.severity == "critical" for f in fs)  # privileged triggers


def test_secrets_redacted_in_evidence(vuln):
    f = findings(vuln, "PT-CRED-001")[0]
    assert "AKIAIOSFODNN7EXAMPLE" not in f.snippet and "AKIA" in f.snippet


def test_expected_failures(vuln):
    for rid in ["PT-PPE-001", "PT-PPE-002", "PT-PPE-003", "PT-PPE-004", "PT-PPE-005", "PT-PBAC-001", "PT-PBAC-002",
                "PT-PBAC-003", "PT-CRED-002", "PT-CRED-003", "PT-CRED-004", "PT-CRED-005", "PT-DEP-001", "PT-DEP-002",
                "PT-DEP-003", "PT-SYS-002", "PT-3P-001", "PT-3P-002", "PT-3P-004", "PT-ART-001", "PT-ART-002", "PT-ART-003",
                "PT-FC-003", "PT-IAM-001", "PT-LOG-002", "PT-LOG-003"]:
        assert status(vuln, rid) == "FAIL", rid


def test_hardened_repo_has_no_failures(hardened):
    fails = [c["rule_id"] for c in hardened.controls if c["status"] == "FAIL"]
    assert fails == [], [(f.rule_id, f.message) for f in hardened.findings]
    assert hardened.summary["posture_score"] == 100.0


def test_offline_scan_marks_api_controls_not_assessed(vuln):
    for rid in ["PT-FC-001", "PT-FC-002", "PT-PBAC-005", "PT-3P-003", "PT-IAM-002"]:
        assert status(vuln, rid) == "NOT_ASSESSED", rid
    assert status(vuln, "PT-LOG-001") == "NEEDS_MANUAL_VALIDATION"
    assert status(vuln, "PT-DEP-004") == "NOT_ASSESSED"  # tools disabled -> never PASS


def test_malformed_yaml_is_reported_not_crashing(vuln):
    assert status(vuln, "PT-SYS-004") == "NEEDS_MANUAL_VALIDATION"
    assert any("broken.yml" in n for n in vuln.coverage_notes)
    assert any("GitLab" in n for n in vuln.coverage_notes)


def test_yaml_on_key_and_line_numbers():
    wf = parse_workflow("x.yml", "on:\n  push:\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
    assert "push" in wf.triggers
    assert wf.jobs[0].line == 4 and wf.jobs[0].steps[0].line == 7


def test_yaml_alias_bomb_rejected():
    bomb = "a: &a [x,x,x,x,x,x,x,x,x]\n" + "".join(f"{chr(98 + i % 20)}{i}: &n{i} [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n" for i in range(30))
    with pytest.raises(YamlError):
        load_yaml(bomb)


def test_yaml_unsafe_tags_not_constructed():
    with pytest.raises(YamlError):
        load_yaml("x: !!python/object/apply:os.system ['echo pwned']")


def test_attack_paths_are_evidence_backed(vuln):
    g = vuln.attack_graph
    assert g["paths"], "expected attack paths"
    fps = {f.fingerprint for f in vuln.findings}
    for p in g["paths"]:
        assert p["findings"] and set(p["findings"]) <= fps
    impacts = {p["impact"] for p in g["paths"]}
    assert "Secret exfiltration" in impacts and any("runner" in i for i in impacts)


def test_github_metadata_drives_api_rules():
    md = RepoMetadata(source="github", full_name="o/r", default_branch="main", visibility="public", owner_type="User")
    md.collected = {
        "branch": ApiResult("ok", {"protected": False}), "branch_rules": ApiResult("ok", []),
        "branch_protection": ApiResult("none"), "workflow_permissions": ApiResult("ok", {"default_workflow_permissions": "write", "can_approve_pull_request_reviews": True}),
        "actions_permissions": ApiResult("ok", {"enabled": True, "allowed_actions": "all"}),
        "environments": ApiResult("ok", []), "collaborators": ApiResult("forbidden", detail="HTTP 403"),
    }
    r = run_assessment(SAMPLES / "hardened-repo", md, {"run_tools": False})
    assert status(r, "PT-FC-001") == "FAIL"
    assert status(r, "PT-FC-002") == "FAIL"
    assert status(r, "PT-PBAC-005") == "FAIL"
    assert status(r, "PT-3P-003") == "FAIL"
    assert status(r, "PT-FC-004") == "FAIL"
    assert status(r, "PT-IAM-002") == "NOT_ASSESSED"
    assert status(r, "PT-IAM-003") == "NEEDS_MANUAL_VALIDATION"


def test_rulesets_satisfy_branch_controls():
    md = RepoMetadata(source="github", full_name="o/r", default_branch="main", visibility="private")
    md.collected = {"branch": ApiResult("ok", {"protected": False}), "branch_protection": ApiResult("forbidden"),
                    "branch_rules": ApiResult("ok", [{"type": "pull_request", "parameters": {"required_approving_review_count": 2}},
                                                     {"type": "non_fast_forward"}])}
    r = run_assessment(SAMPLES / "hardened-repo", md, {"run_tools": False})
    assert status(r, "PT-FC-001") == "PASS"
    assert status(r, "PT-FC-002") == "PASS"
