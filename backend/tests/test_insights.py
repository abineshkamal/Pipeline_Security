"""Secret blast radius, what-if, verified fixes, compliance packs, Ask, custom policies and the compromised-action watch."""
import pytest

from .conftest import SAMPLES, register, zip_dir

FAKE_SHA = "b" * 40


@pytest.fixture(scope="module")
def env(client, tmp_path_factory):
    admin = register(client, "owner@insights.example.com", org="Insights Org")
    other = register(client, "mallory@else.example.com", org="Else Org")
    pid = client.post("/api/projects", headers=admin, json={"name": "Vuln", "source_type": "upload"}).json()["id"]
    z = zip_dir(SAMPLES / "vulnerable-repo", tmp_path_factory.mktemp("zi") / "r.zip")
    with open(z, "rb") as fh:
        sid = client.post(f"/api/projects/{pid}/scans/upload?tools=&ai=false", headers=admin, files={"file": ("r.zip", fh)}).json()["id"]
    assert client.get(f"/api/scans/{sid}", headers=admin).json()["status"] == "completed"
    return {"admin": admin, "other": other, "pid": pid, "sid": sid, "zip": z}


@pytest.fixture(autouse=True)
def offline_pins(monkeypatch):
    import app.api.insights as ins
    monkeypatch.setattr(ins.GitHubClient, "resolve_sha", lambda self, o, r, ref: FAKE_SHA)


def test_secret_blast_radius(client, env):
    d = client.get(f"/api/scans/{env['sid']}/secrets", headers=env["admin"]).json()
    by = {s["name"]: s for s in d["secrets"]}
    assert "NPM_TOKEN" in by and by["NPM_TOKEN"]["reach"] == "outsiders"   # pull_request_target workflow
    assert by["NPM_TOKEN"]["level"] == "critical"                          # and untrusted PR code runs in that job
    assert d["outsider_reachable"] >= 1
    pipe = by["NPM_TOKEN"]["uses"][0]["workflow"]
    one = client.get(f"/api/scans/{env['sid']}/secrets", params={"pipeline": pipe}, headers=env["admin"]).json()
    assert all(u["workflow"] == pipe for s in one["secrets"] for u in s["uses"])
    assert client.get(f"/api/scans/{env['sid']}/secrets", headers=env["other"]).status_code == 404


def test_whatif_matches_scan_and_breaks_paths(client, env):
    a, sid = env["admin"], env["sid"]
    scan = client.get(f"/api/scans/{sid}", headers=a).json()
    base = client.post(f"/api/scans/{sid}/whatif", headers=a, json={"finding_ids": []}).json()
    assert base["before"]["posture_score"] == scan["posture_score"] == base["after"]["posture_score"]
    assert base["before"]["attack_paths"] == len(scan["attack_graph"]["paths"])
    path = scan["attack_graph"]["paths"][0]
    r = client.post(f"/api/scans/{sid}/whatif", headers=a, json={"finding_ids": path["finding_ids"]}).json()
    assert path["id"] in r["removed_paths"] and r["after"]["attack_paths"] < r["before"]["attack_paths"]
    every = [f["id"] for f in client.get(f"/api/scans/{sid}/findings", headers=a).json()]
    allfix = client.post(f"/api/scans/{sid}/whatif", headers=a, json={"finding_ids": every}).json()
    assert allfix["after"]["attack_paths"] == 0 and allfix["after"]["findings"] == 0
    assert allfix["after"]["posture_score"] >= base["before"]["posture_score"]
    rec = client.get(f"/api/scans/{sid}/whatif/recommendations", headers=a).json()
    assert rec["by_rule"] and rec["by_rule"][0]["paths_removed"] >= rec["by_rule"][-1]["paths_removed"]
    assert any(x["auto_fixable"] for x in rec["by_rule"])


def test_fixes_are_verified_and_exportable(client, env):
    a, sid = env["admin"], env["sid"]
    plan = client.get(f"/api/scans/{sid}/fixes", headers=a).json()
    s = plan["summary"]
    assert s["applied"] >= 10 and s["verified"] == s["applied"] and s["introduced"] == 0
    assert all(f["verified"] and not f["parse_error"] for f in plan["files"])
    rules = {x["rule_id"] for x in plan["fixes"] if x["status"] == "applied"}
    assert {"PT-3P-001", "PT-PBAC-001", "PT-CRED-005", "PT-PPE-003"} <= rules
    assert any(FAKE_SHA in f["patched"] for f in plan["files"])
    # the compromised action is never auto-pinned
    tj = [x for x in plan["fixes"] if x["rule_id"] == "PT-3P-001" and "changed-files" in x["detail"]]
    assert tj and all(x["status"] == "skipped" for x in tj)
    one = plan["files"][0]["path"]
    sub = client.get(f"/api/scans/{sid}/fixes", params={"pipeline": one}, headers=a).json()
    assert {f["path"] for f in sub["files"]} == {one}
    patch = client.get(f"/api/scans/{sid}/fixes.patch", headers=a)
    assert patch.status_code == 200 and patch.text.startswith("--- a/.github/workflows/")
    r = client.post(f"/api/scans/{sid}/fixes/pull-request", headers=a, json={"credential_id": "x"})
    assert r.status_code == 400  # upload projects cannot open pull requests


@pytest.mark.parametrize("fw", ["ssdf", "slsa", "cis-ssc", "soc2", "iso27001"])
def test_compliance_packs(client, env, fw):
    a, sid = env["admin"], env["sid"]
    pack = client.get(f"/api/scans/{sid}/compliance/{fw}", headers=a).json()
    assert pack["requirements"] and pack["disclaimer"]
    assert {r["status"] for r in pack["requirements"]} <= {"PASS", "FAIL", "PARTIAL", "NOT_ASSESSED", "NEEDS_MANUAL_VALIDATION", "NOT_APPLICABLE"}
    assert any(r["status"] == "FAIL" for r in pack["requirements"])
    html = client.get(f"/api/scans/{sid}/compliance/{fw}/export.html", headers=a)
    assert html.status_code == 200 and "<table>" in html.text
    assert client.get(f"/api/scans/{sid}/compliance/{fw}/export.csv", headers=a).text.startswith("framework,")
    assert client.get(f"/api/scans/{sid}/compliance/nope", headers=a).status_code == 404


def test_ask_deterministic_and_llm_guardrail(client, env, monkeypatch):
    a, sid = env["admin"], env["sid"]
    r = client.post(f"/api/scans/{sid}/ask", headers=a, json={"question": "Which secrets can outsiders reach?"}).json()
    assert r["mode"] == "deterministic" and "NPM_TOKEN" in r["answer"] and r["references"]
    r = client.post(f"/api/scans/{sid}/ask", headers=a, json={"question": "Which jobs run on self-hosted runners?"}).json()
    assert "self-hosted" in r["answer"]
    r = client.post(f"/api/scans/{sid}/ask", headers=a, json={"question": "tell me a joke"}).json()
    assert r["intent"] is None and r["examples"]

    import app.insights.ask as ask_mod
    from app.agents.llm import FakeProvider
    monkeypatch.setattr(ask_mod, "get_provider", lambda *x: FakeProvider())
    r = client.post(f"/api/scans/{sid}/ask", headers=a, json={"question": "What is risky?", "mode": "llm"}).json()
    assert r["mode"] == "llm"
    assert r["guardrail"]["dropped_count"] == 2 and "HALLUCINATED" not in r["answer"]
    assert len(r["references"]) == 1 and r["references"][0]["kind"] == "finding"


POLICY = """id: ORG-RUNNER-001
title: No self-hosted runners on externally triggered workflows
severity: critical
category: CICD-SEC-7
target: job
when:
  - {field: self_hosted, equals: true}
  - {field: external_triggers, is_empty: false}
message: "Job {id} runs on a self-hosted runner and can be triggered by {external_triggers}"
"""


def test_policies_crud_dry_run_and_scan(client, env):
    a, sid = env["admin"], env["sid"]
    bad = client.post("/api/policies", headers=a, json={"source": POLICY.replace("is_empty: false", "bogus: 1")})
    assert bad.status_code == 422
    assert client.post("/api/policies", headers=a, json={"source": POLICY.replace("ORG-RUNNER-001", "PT-FAKE-1")}).status_code == 422
    dry = client.post("/api/policies/test", headers=a, json={"source": POLICY, "scan_id": sid}).json()
    assert dry["violations"] >= 1 and "self-hosted" in dry["scans"][0]["violations"][0]["message"]
    p = client.post("/api/policies", headers=a, json={"source": POLICY})
    assert p.status_code == 201
    assert client.post("/api/policies", headers=a, json={"source": POLICY}).status_code == 409
    assert client.get("/api/policies", headers=env["other"]).json()["policies"] == []
    # a new scan evaluates the policy like a built-in rule
    with open(env["zip"], "rb") as fh:
        sid2 = client.post(f"/api/projects/{env['pid']}/scans/upload?tools=&ai=false", headers=a, files={"file": ("r.zip", fh)}).json()["id"]
    s2 = client.get(f"/api/scans/{sid2}", headers=a).json()
    ctrl = next(c for c in s2["controls"] if c["rule_id"] == "ORG-RUNNER-001")
    assert ctrl["status"] == "FAIL" and ctrl["data_sources"] == ["policy"]
    fs = client.get(f"/api/scans/{sid2}/findings", params={"rule_id": "ORG-RUNNER-001"}, headers=a).json()
    assert fs and all(f["severity"] == "critical" for f in fs)
    assert s2["summary"]["policies_applied"] == ["ORG-RUNNER-001"]
    # disable, then delete
    pid_ = p.json()["id"]
    assert client.put(f"/api/policies/{pid_}", headers=a, json={"source": POLICY, "enabled": False}).json()["enabled"] is False
    assert client.delete(f"/api/policies/{pid_}", headers=a).status_code == 204


def test_advisories_and_watch(client, env):
    a = env["admin"]
    w = client.get("/api/watch/exposures", headers=a).json()
    tj = [x for x in w["exposures"] if "tj-actions/changed-files" in x["uses"]]
    assert tj and tj[0]["advisory"] == "CVE-2025-30066" and tj[0]["verdict"] == "mutable_ref"
    r = client.post("/api/advisories", headers=a, json={"advisory_id": "INT-2026-001", "action": "Actions/Checkout", "title": "Internal test advisory",
                                                        "bad_refs": ["v4"], "window_start": "2026-01-01", "window_end": "2026-01-02"})
    assert r.status_code == 201 and r.json()["action"] == "actions/checkout"
    w = client.get("/api/watch/exposures", headers=a).json()
    co = [x for x in w["exposures"] if x["advisory"] == "INT-2026-001"]
    assert co and all(x["verdict"] == "compromised_ref" and x["severity"] == "critical" for x in co)
    assert client.get("/api/watch/exposures", headers=env["other"]).json()["exposures"] == []
    assert client.post("/api/watch/runs", headers=a, json={"project_id": env["pid"], "workflow": ".github/workflows/ci.yml",
                                                          "advisory": "INT-2026-001"}).status_code == 400  # upload project
    rec = next(x for x in client.get("/api/advisories", headers=a).json() if x["id"] == "INT-2026-001")
    assert client.delete(f"/api/advisories/{rec['record_id']}", headers=a).status_code == 204
    assert client.post("/api/advisories", headers=a, json={"advisory_id": "X-1", "action": "not a repo", "title": "bad"}).status_code == 422
