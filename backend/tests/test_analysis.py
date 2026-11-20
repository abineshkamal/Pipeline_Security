"""Release diff, attacker walkthrough, runtime evidence, runner inventory, executive report, ticketing, scan ref, CLI gate."""
from types import SimpleNamespace

import pytest

from .conftest import SAMPLES, register, zip_dir


def _upload(client, h, pid, sample, tmp):
    z = zip_dir(SAMPLES / sample, tmp / f"{sample}.zip")
    with open(z, "rb") as fh:
        sid = client.post(f"/api/projects/{pid}/scans/upload?tools=&ai=false", headers=h, files={"file": ("r.zip", fh)}).json()["id"]
    assert client.get(f"/api/scans/{sid}", headers=h).json()["status"] == "completed"
    return sid


@pytest.fixture(scope="module")
def env(client, tmp_path_factory):
    tmp = tmp_path_factory.mktemp("an")
    h = register(client, "lead@analysis.example.com", org="Analysis Org")
    pid = client.post("/api/projects", headers=h, json={"name": "Release", "source_type": "upload"}).json()["id"]
    good = _upload(client, h, pid, "hardened-repo", tmp)
    bad = _upload(client, h, pid, "vulnerable-repo", tmp)
    return {"h": h, "pid": pid, "good": good, "bad": bad, "tmp": tmp, "other": register(client, "x@nosy.example.com", org="Nosy")}


def test_pipeline_diff_between_releases(client, env):
    h = env["h"]
    d = client.get(f"/api/scans/{env['bad']}/pipeline-diff/{env['good']}", headers=h).json()
    c = d["counts"]
    assert c["increase"] > 0 and c["new_paths"] > 0 and c["new_findings"] > 0 and d["score_delta"] < 0
    kinds = {x["kind"] for x in d["changes"] if x["risk"] == "increase"}
    assert "workflow_added" in kinds or "trigger_added" in kinds
    assert d["changes"][0]["risk"] == "increase"                                  # risk increases listed first
    back = client.get(f"/api/scans/{env['good']}/pipeline-diff/{env['bad']}", headers=h).json()
    assert back["counts"]["removed_paths"] == c["new_paths"] and back["counts"]["fixed_findings"] == c["new_findings"]
    assert client.get(f"/api/scans/{env['bad']}/pipeline-diff/{env['good']}", headers=env["other"]).status_code == 404


def test_attack_path_walkthrough_breakers_are_real(client, env):
    h, sid = env["h"], env["bad"]
    scan = client.get(f"/api/scans/{sid}", headers=h).json()
    p = scan["attack_graph"]["paths"][0]
    st = client.get(f"/api/scans/{sid}/attack-paths/{p['id']}/story", headers=h).json()
    assert len(st["steps"]) == len(p["nodes"]) and st["steps"][0]["type"] == "actor" and st["story"].startswith("1. ")
    assert any(s["evidence"] for s in st["steps"])
    assert st["breakers"], "the top path should be breakable by one fix"
    sim = client.post(f"/api/scans/{sid}/whatif", headers=h, json={"finding_ids": [st["breakers"][0]["id"]]}).json()
    assert p["id"] in sim["removed_paths"] and len(sim["removed_paths"]) == st["breakers"][0]["paths_removed"]
    assert client.get(f"/api/scans/{sid}/attack-paths/AP-99/story", headers=h).status_code == 404


class FakeGH:
    def __init__(self, data):
        self.data = data

    def result(self, path, none_on_404=False, **params):
        for k, v in self.data.items():
            if path.endswith(k):
                return SimpleNamespace(status=v[0], data=v[1], detail=v[2] if len(v) > 2 else "")
        return SimpleNamespace(status="none", data=None, detail="not configured")


def test_runtime_evidence_observes_fork_runs():
    from app.insights.runtime import run_evidence
    inv = {"workflows": [
        {"path": ".github/workflows/pr.yml", "name": "PR bot", "triggers": ["pull_request_target"], "privileged_triggers": ["pull_request_target"],
         "jobs": [{"id": "b", "secrets": ["NPM_TOKEN"]}]},
        {"path": ".github/workflows/old.yml", "name": "Old deploy", "triggers": ["push"], "privileged_triggers": [], "jobs": [{"id": "d", "secrets": ["AWS"]}]}]}
    runs = [{"path": ".github/workflows/pr.yml", "event": "pull_request_target", "head_repository": {"full_name": "evil/fork"},
             "author_association": "FIRST_TIME_CONTRIBUTOR", "created_at": "2026-11-18T10:00:00Z", "conclusion": "success", "html_url": "u1",
             "actor": {"login": "eve"}},
            {"path": ".github/workflows/pr.yml", "event": "pull_request_target", "head_repository": {"full_name": "o/r"},
             "author_association": "MEMBER", "created_at": "2025-06-01T10:00:00Z", "conclusion": "failure", "html_url": "u2", "actor": {"login": "bob"}}]
    f = SimpleNamespace(rule_id="PT-PPE-001", file_path=".github/workflows/pr.yml", triage_status="open")
    d = run_evidence(FakeGH({"/actions/runs": ("ok", {"workflow_runs": runs})}), "o/r", inv, [f])
    pr = next(w for w in d["workflows"] if w["name"] == "PR bot")
    assert pr["privileged_fork_runs"] == 1 and "observed_untrusted_trigger" in pr["flags"] and pr["examples"][0]["head"] == "evil/fork"
    assert d["observed"] and d["observed"][0]["workflow"] == ".github/workflows/pr.yml"
    old = next(w for w in d["workflows"] if w["name"] == "Old deploy")
    assert "dormant_with_secrets" in old["flags"]                  # holds secrets, no runs in 90+ days of history
    err = run_evidence(FakeGH({"/actions/runs": ("forbidden", None, "HTTP 403")}), "o/r", inv, [])
    assert err["status"] == "error"


def test_runner_inventory_flags():
    from app.insights.runtime import runner_inventory
    inv = {"workflows": [{"path": ".github/workflows/ci.yml", "name": "CI", "triggers": ["pull_request"],
                          "jobs": [{"id": "t", "self_hosted": True, "runs_on": ["self-hosted", "linux"], "secrets": []}]}]}
    gh = FakeGH({"/repos/o/r/actions/runners": ("ok", {"runners": [{"name": "r1", "os": "Linux", "status": "online", "busy": False, "ephemeral": False,
                                                                    "labels": [{"name": "self-hosted"}, {"name": "Linux"}]}]}),
                 "/orgs/o/actions/runners": ("forbidden", None, "HTTP 403"),
                 "/orgs/o/actions/runner-groups": ("ok", {"runner_groups": [{"name": "Default", "visibility": "all", "allows_public_repositories": True}]})})
    d = runner_inventory(gh, "o/r", inv, True)
    assert d["self_hosted_jobs"][0]["matching_runners"] == ["r1"] and d["self_hosted_jobs"][0]["fork_reachable"]
    texts = " ".join(r["text"] for r in d["risks"])
    assert "outsider can run code" in texts and "persistent" in texts and "allows public repositories" in texts
    assert d["risks"][0]["severity"] == "critical" and d["note"]                 # org runners forbidden -> note


def test_runtime_needs_github_project(client, env):
    assert client.get(f"/api/scans/{env['bad']}/runtime", headers=env["h"]).status_code == 400


def test_executive_report(client, env):
    h = env["h"]
    html = client.get("/api/reports/executive.html", headers=h)
    assert html.status_code == 200 and "Analysis Org" in html.text and "Riskiest projects" in html.text and "<script" not in html.text
    d = client.get("/api/reports/executive.json?days=90", headers=h).json()
    assert d["summary"]["assessed"] >= 1 and d["riskiest"][0]["name"] == "Release" and d["top_rules"]
    assert d["summary"]["new_findings"] >= 0 and len(d["trend"]) >= 2
    assert client.get("/api/reports/executive.json", headers=env["other"]).json()["summary"]["assessed"] == 0


def test_tickets_open_and_auto_close(client, env, monkeypatch):
    import app.services.tickets as tk
    calls = []

    def fake(method, url, auth, body=None):
        calls.append((method, url, body))
        if url.endswith("/rest/api/2/issue"):
            return 201, {"key": f"SEC-{len(calls)}", "id": "1000"}
        if url.endswith("/transitions") and method == "GET":
            return 200, {"transitions": [{"id": "31", "name": "Done"}]}
        return 204, {}
    monkeypatch.setattr(tk, "request", fake)
    h = env["h"]
    r = client.post("/api/integrations/tickets", headers=h, json={"name": "Jira", "kind": "jira", "base_url": "https://acme.atlassian.example.com",
                                                                 "target": "SEC", "username": "bot@acme.example.com", "secret": "api-token-123", "close_action": "Done"})
    assert r.status_code == 201 and "secret" not in r.json()
    iid = r.json()["id"]
    assert client.post("/api/integrations/tickets", headers=h, json={**r.json(), "secret": "x" * 8, "base_url": "http://plain.example.com"}).status_code == 422
    pid = client.post("/api/projects", headers=h, json={"name": "Tix", "source_type": "upload"}).json()["id"]
    sid = _upload(client, h, pid, "vulnerable-repo", env["tmp"])
    f = next(x for x in client.get(f"/api/scans/{sid}/findings", headers=h).json() if x["severity"] == "critical")
    out = client.post("/api/tickets", headers=h, json={"integration_id": iid, "finding_ids": [f["id"]]}).json()
    assert out["created"][0]["key"].startswith("SEC-") and out["created"][0]["url"].endswith(out["created"][0]["key"])
    body = calls[0][2]["fields"]
    assert body["project"] == {"key": "SEC"} and f["rule_id"] in body["summary"] and f["fingerprint"] in body["description"]
    again = client.post("/api/tickets", headers=h, json={"integration_id": iid, "finding_ids": [f["id"]]}).json()
    assert again["skipped"] and not again["created"]                                   # one open ticket per finding
    fresh = next(x for x in client.get(f"/api/scans/{sid}/findings", headers=h).json() if x["id"] == f["id"])
    assert fresh["extra"]["ticket"]["status"] == "open"
    # the same finding in a re-scan keeps the ticket; a clean re-scan closes it
    sid2 = _upload(client, h, pid, "vulnerable-repo", env["tmp"])
    same = next(x for x in client.get(f"/api/scans/{sid2}/findings", headers=h).json() if x["fingerprint"] == f["fingerprint"])
    assert same["extra"]["ticket"]["key"] == out["created"][0]["key"]
    n = len(calls)
    _upload(client, h, pid, "hardened-repo", env["tmp"])
    t = client.get(f"/api/tickets?project_id={pid}", headers=h).json()[0]
    assert t["status"] == "resolved" and "transition 'Done'" in t["sync_detail"]
    sent = calls[n:]
    assert any(u.endswith("/comment") for _, u, _ in sent) and any(m == "POST" and u.endswith("/transitions") for m, u, _ in sent)
    _upload(client, h, pid, "vulnerable-repo", env["tmp"])                              # regression reopens the link
    assert client.get(f"/api/tickets?project_id={pid}", headers=h).json()[0]["status"] == "open"
    assert client.get("/api/tickets", headers=env["other"]).json() == []


def test_servicenow_payload(monkeypatch):
    import app.services.tickets as tk
    seen = {}
    monkeypatch.setattr(tk, "request", lambda m, u, a, b=None: seen.update(url=u, body=b) or (201, {"result": {"sys_id": "abc", "number": "INC001"}}))
    monkeypatch.setattr(tk, "decrypt_secret", lambda s: "pw")
    it = SimpleNamespace(kind="servicenow", base_url="https://acme.service-now.example.com", target="incident", username="u", secret_encrypted="x")
    f = SimpleNamespace(rule_id="PT-PPE-001", title="t", severity="critical", category="CICD-SEC-4", risk_score=9.1, message="m", file_path="a.yml",
                        line=3, job="j", snippet="", fingerprint="fp", id="F1")
    r = tk.create_ticket(it, f, SimpleNamespace(name="P", repo_full_name="o/r"), SimpleNamespace(id="S"))
    assert r["key"] == "INC001" and seen["url"].endswith("/api/now/table/incident") and seen["body"]["urgency"] == "1"


def test_scan_ref_option(client, env, monkeypatch):
    import app.api.scans as scans_api
    monkeypatch.setattr(scans_api, "enqueue_scan", lambda sid: "test")
    h = env["h"]
    pid = client.post("/api/projects", headers=h, json={"name": "Ref", "source_type": "github", "repo_full_name": "octo/ref"}).json()["id"]
    assert client.post(f"/api/projects/{pid}/scans", headers=h, json={"tools": [], "ref": "../../etc"}).status_code == 422
    assert client.post(f"/api/projects/{pid}/scans", headers=h, json={"tools": [], "ref": "-x"}).status_code == 422
    s = client.post(f"/api/projects/{pid}/scans", headers=h, json={"tools": [], "ref": "v1.2.0"}).json()
    assert s["ref"] == "v1.2.0" and s["options"]["ref"] == "v1.2.0"


def test_cli_gate(tmp_path):
    from app.cli import main
    from app.scanner.policies import EXAMPLES
    pol = tmp_path / "p.yml"
    pol.write_text("\n---\n".join(EXAMPLES), "utf-8")
    summ = tmp_path / "s.md"
    args = ["scan", str(SAMPLES / "vulnerable-repo"), "--tools", "none", "--format", "json", "--out", str(tmp_path / "o.json")]
    assert main(args) == 0                                                              # no gate options
    assert main(args + ["--policies", str(pol), "--fail-on-policy", "--summary", str(summ)]) == 1
    assert "custom policy violation" in summ.read_text("utf-8")
    assert main(args + ["--max-attack-paths", "0"]) == 1
    good = ["scan", str(SAMPLES / "hardened-repo"), "--tools", "none", "--format", "json", "--out", str(tmp_path / "g.json")]
    assert main(good + ["--max-attack-paths", "0", "--fail-on", "critical"]) == 0
    bad_pol = tmp_path / "bad.yml"
    bad_pol.write_text("id: PT-NOPE\n", "utf-8")
    assert main(good + ["--policies", str(bad_pol)]) == 2


def test_release_scans_do_not_change_current_posture(client, env, tmp_path):
    from app.db import SessionLocal
    from app.models import DriftAlert, Scan
    from app.services.monitoring import after_scan
    h = env["h"]
    pid = client.post("/api/projects", headers=h, json={"name": "Side", "source_type": "upload"}).json()["id"]
    main_sid = _upload(client, h, pid, "hardened-repo", tmp_path)
    side_sid = _upload(client, h, pid, "vulnerable-repo", tmp_path)
    with SessionLocal() as db:  # make the newer scan a release-tag scan, as POST /scans with {"ref": ...} does
        db.query(DriftAlert).filter(DriftAlert.scan_id == side_sid).delete()
        s = db.get(Scan, side_sid)
        s.ref_override = "v1.0.0"
        db.commit()
        assert after_scan(db, s) is None                                              # no drift alert for a release scan
    row = next(p for p in client.get("/api/portfolio", headers=h).json()["projects"] if p["project_id"] == pid)
    assert row["scan_id"] == main_sid
    assert client.get(f"/api/projects/{pid}/pipelines", headers=h).json()["scan"]["id"] == main_sid
    d = client.get(f"/api/scans/{side_sid}/pipeline-diff/{main_sid}", headers=h).json()   # but it can still be compared
    assert d["counts"]["new_paths"] > 0
