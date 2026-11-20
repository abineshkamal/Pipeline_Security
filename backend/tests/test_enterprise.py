"""Least-privilege permissions, fix campaigns, action reputation + allowlist, SLAs, API tokens, SIEM export,
plain-English policies and golden templates."""
import hashlib
import hmac
import json
from datetime import timedelta
from types import SimpleNamespace

import pytest

from .conftest import SAMPLES, register, zip_dir

RELEASE_WF = """name: Release
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm test
  publish:
    runs-on: ubuntu-latest
    needs: build
    steps:
      - uses: actions/checkout@v4
      - run: gh release create v1.0.0 dist/*
      - uses: peter-evans/create-pull-request@v6
"""
CI_WF = """name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: npm ci
      - run: npm test
      - run: npm run lint
"""


def _repo(tmp, name, files: dict[str, str]):
    d = tmp / name
    for path, text in files.items():
        f = d / path
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text, "utf-8")
    return d


def _scan_dir(client, h, name, d, tmp):
    pid = client.post("/api/projects", headers=h, json={"name": name, "source_type": "upload"}).json()["id"]
    z = zip_dir(d, tmp / f"{name}.zip")
    with open(z, "rb") as fh:
        sid = client.post(f"/api/projects/{pid}/scans/upload?tools=&ai=false", headers=h, files={"file": ("r.zip", fh)}).json()["id"]
    assert client.get(f"/api/scans/{sid}", headers=h).json()["status"] == "completed"
    return pid, sid


@pytest.fixture(scope="module")
def org(client, tmp_path_factory):
    tmp = tmp_path_factory.mktemp("ent")
    h = register(client, "boss@enterprise.example.com", org="Enterprise Org")
    rel = _repo(tmp, "rel", {".github/workflows/release.yml": RELEASE_WF})
    pid, sid = _scan_dir(client, h, "Releaser", rel, tmp)
    return {"h": h, "tmp": tmp, "rel_pid": pid, "rel_sid": sid, "other": register(client, "o@other-ent.example.com", org="Other Ent")}


@pytest.fixture(autouse=True)
def offline_pins(monkeypatch):
    from app.connectors.github import GitHubClient
    monkeypatch.setattr(GitHubClient, "resolve_sha", lambda self, o, r, ref: "c" * 40)


def test_least_privilege_permissions_and_fix(client, org):
    h, sid = org["h"], org["rel_sid"]
    d = client.get(f"/api/scans/{sid}/permissions", headers=h).json()
    jobs = {j["job"]: j for j in d["jobs"]}
    assert jobs["build"]["recommended"] == {"contents": "read"} and jobs["build"]["confidence"] == "high"
    assert jobs["publish"]["recommended"] == {"contents": "write", "pull-requests": "write"}
    assert any("gh release" in r for r in jobs["publish"]["reasons"])
    plan = client.get(f"/api/scans/{sid}/fixes", headers=h).json()
    fx = next(x for x in plan["fixes"] if x["rule_id"] == "PT-PBAC-001")
    assert fx["status"] == "applied" and "`publish` (contents: write, pull-requests: write)" in fx["detail"]
    patched = next(f["patched"] for f in plan["files"] if f["path"].endswith("release.yml"))
    assert "permissions:\n  contents: read\n" in patched and "    permissions:\n      contents: write\n      pull-requests: write" in patched
    assert next(f for f in plan["files"] if f["path"].endswith("release.yml"))["verified"]


def test_fix_campaign_dry_run_then_pull_requests(client, org, monkeypatch):
    import app.services.campaigns as camp
    from app.db import SessionLocal
    from app.insights import fixes
    from app.models import Project
    monkeypatch.setattr(camp, "start", camp.run_campaign)                     # run synchronously
    h = org["h"]
    pid2, _ = _scan_dir(client, h, "Releaser2", _repo(org["tmp"], "rel2", {".github/workflows/release.yml": RELEASE_WF}), org["tmp"])
    cands = client.get("/api/campaigns/candidates?rule_ids=PT-PBAC-001", headers=h).json()
    assert {c["project_id"] for c in cands} >= {org["rel_pid"], pid2}
    dry = client.post("/api/campaigns", headers=h, json={"name": "Least privilege", "rule_ids": ["PT-PBAC-001"],
                                                         "project_ids": [org["rel_pid"], pid2], "dry_run": True}).json()
    full = client.get(f"/api/campaigns/{dry['id']}", headers=h).json()
    assert full["status"] == "done" and full["by_status"]["planned"] == 2 and all(i["fixes_applied"] >= 1 for i in full["items"])
    assert client.post("/api/campaigns", headers=h, json={"name": "Real", "rule_ids": ["PT-PBAC-001"], "project_ids": [pid2]}).status_code == 422
    assert client.post("/api/campaigns", headers=h, json={"name": "Bad", "rule_ids": ["PT-FC-001"], "project_ids": [pid2], "dry_run": True}).status_code == 422
    with SessionLocal() as db:  # pretend the project is a GitHub repository
        p = db.get(Project, pid2)
        p.source_type, p.repo_full_name = "github", "acme/releaser2"
        db.commit()
    cred = client.post("/api/credentials", headers=h, json={"name": "writer", "secret": "ghp_writetoken123"}).json()["id"]
    opened = []
    monkeypatch.setattr(fixes, "open_pull_request", lambda repo, sha, files, tok, title, body: opened.append((repo, tok, title, body))
                        or {"url": f"https://github.com/{repo}/pull/7", "number": 7, "branch": "pipelinetrust/fixes-x", "base": "main"})
    real = client.post("/api/campaigns", headers=h, json={"name": "Least privilege", "rule_ids": ["PT-PBAC-001"], "project_ids": [pid2],
                                                          "credential_id": cred}).json()
    item = client.get(f"/api/campaigns/{real['id']}", headers=h).json()["items"][0]
    assert item["status"] == "pr_open" and item["pr_number"] == 7 and opened[0][1] == "ghp_writetoken123" and "Least privilege" in opened[0][3]
    from app.connectors.github import GitHubClient
    monkeypatch.setattr(GitHubClient, "result", lambda self, path, none_on_404=False, **k: SimpleNamespace(status="ok", data={"merged_at": "2026-11-20T00:00:00Z", "state": "closed"}, detail=""))
    ref = client.post(f"/api/campaigns/{real['id']}/refresh", headers=h).json()
    assert ref["items"][0]["status"] == "merged" and ref["items"][0]["remaining"] >= 1   # re-scan not run yet
    assert client.get(f"/api/campaigns/{real['id']}", headers=org["other"]).status_code == 404


def test_action_reputation_and_allowlist(client, org, monkeypatch):
    from app.connectors.github import GitHubClient
    meta = {"/repos/peter-evans/create-pull-request": {"stargazers_count": 2500, "archived": False, "pushed_at": "2026-11-01T00:00:00Z",
                                                       "created_at": "2019-01-01T00:00:00Z", "owner": {"type": "User"}}}

    def fake(self, path, none_on_404=False, **k):
        if path in meta:
            return SimpleNamespace(status="ok", data=meta[path], detail="")
        if path.startswith("/repos/"):
            return SimpleNamespace(status="ok", data={"stargazers_count": 3, "archived": True, "pushed_at": "2021-01-01T00:00:00Z",
                                                      "created_at": "2020-01-01T00:00:00Z", "owner": {"type": "User"}}, detail="")
        return SimpleNamespace(status="ok", data={"is_verified": False}, detail="")
    monkeypatch.setattr(GitHubClient, "result", fake)
    h = org["h"]
    _scan_dir(client, h, "Vuln", SAMPLES / "vulnerable-repo", org["tmp"])
    r = client.get("/api/actions/reputation?refresh=true", headers=h).json()
    by = {a["slug"]: a for a in r["actions"]}
    assert by["actions/checkout"]["tier"] == "trusted" and by["peter-evans/create-pull-request"]["tier"] in ("trusted", "acceptable")
    risky = [a for a in r["actions"] if a["tier"] in ("risky", "blocked")]
    assert risky and any("archived" in " ".join(a["reasons"]) or "advisory" in " ".join(a["reasons"]) for a in risky)
    al = client.post("/api/actions/allowlist", headers=h, json={"min_tier": "acceptable"}).json()
    assert al["policy"]["github_owned_allowed"] is True and "peter-evans/create-pull-request@*" in al["policy"]["patterns_allowed"]
    assert {e["action"] for e in al["excluded"]} >= {a["slug"] for a in risky if not a["first_party"]}
    assert not any(p.startswith("actions/") for p in al["policy"]["patterns_allowed"])


def test_remediation_sla(client, org):
    from app.db import SessionLocal
    from app.models import Scan
    h = register(client, "sla@sla.example.com", org="SLA Org")
    pid = client.post("/api/projects", headers=h, json={"name": "S", "source_type": "upload"}).json()["id"]

    def up(sample):
        z = zip_dir(SAMPLES / sample, org["tmp"] / f"sla-{sample}.zip")
        with open(z, "rb") as fh:
            return client.post(f"/api/projects/{pid}/scans/upload?tools=&ai=false", headers=h, files={"file": ("r.zip", fh)}).json()["id"]
    first = up("vulnerable-repo")
    with SessionLocal() as db:  # first found 40 days ago
        s = db.get(Scan, first)
        s.created_at = s.created_at - timedelta(days=40)
        db.commit()
    d = client.get("/api/sla", headers=h).json()
    assert d["by_severity"]["critical"]["overdue"] == d["by_severity"]["critical"]["open"] > 0      # 40 days > 7-day target
    assert d["by_severity"]["low"]["overdue"] == 0 and d["overdue"][0]["severity"] == "critical"
    up("hardened-repo")                                                                             # most findings fixed
    d2 = client.get("/api/sla", headers=h).json()
    assert d2["by_severity"]["critical"]["fixed"] > 0 and d2["by_severity"]["critical"]["mttr_days"] >= 39
    assert d2["by_severity"]["critical"]["within_target_pct"] == 0
    assert client.put("/api/sla/targets", headers=h, json={"critical": 60, "high": 60, "medium": 90, "low": 180}).json()["critical"] == 60
    assert client.get("/api/sla", headers=h).json()["by_severity"]["critical"]["within_target_pct"] == 100


def test_api_tokens(client, org):
    h = org["h"]
    r = client.post("/api/tokens", headers=h, json={"name": "ci-bot", "role": "viewer", "expires_in_days": 30}).json()
    raw = r["token"]
    assert raw.startswith("pt_") and "token" not in client.get("/api/tokens", headers=h).json()[0]
    th = {"Authorization": f"Bearer {raw}"}
    assert client.get("/api/projects", headers=th).status_code == 200
    assert client.post("/api/projects", headers=th, json={"name": "x", "source_type": "upload"}).status_code == 403   # viewer
    assert client.post("/api/tokens", headers=th, json={"name": "yy"}).status_code == 403                              # tokens can't mint tokens
    assert client.get("/api/projects", headers={**th, "X-Org-Id": "someone-else"}).status_code == 403
    admin_tok = client.post("/api/tokens", headers=h, json={"name": "automation", "role": "admin"}).json()["token"]
    ah = {"Authorization": f"Bearer {admin_tok}"}
    assert client.post("/api/tokens", headers=ah, json={"name": "zz"}).status_code == 403
    assert client.post("/api/projects", headers=ah, json={"name": "via token", "source_type": "upload"}).status_code == 201
    client.delete(f"/api/tokens/{r['id']}", headers=h)
    assert client.get("/api/projects", headers=th).status_code == 401
    assert client.get("/api/projects", headers={"Authorization": "Bearer pt_not-a-real-token"}).status_code == 401


def test_siem_export(client, org, monkeypatch):
    import app.services.siem as siem
    sent = []
    monkeypatch.setattr(siem, "post", lambda url, headers, body: sent.append((url, headers, body)) or 200)
    h = org["h"]
    assert client.post("/api/siem/sinks", headers=h, json={"name": "splunk", "kind": "splunk", "url": "https://splunk.example.com:8088/services/collector"}).status_code == 422
    s = client.post("/api/siem/sinks", headers=h, json={"name": "hook", "kind": "webhook", "url": "https://siem.example.com/in",
                                                        "secret": "hmac-key", "events": ["audit"]}).json()
    assert s["has_secret"] and "secret" not in s
    client.post("/api/projects", headers=h, json={"name": "Audited", "source_type": "upload"})
    siem.flush()
    ev = [json.loads(b) for _, _, b in sent if json.loads(b)["event"].get("action") == "project.create"]
    assert ev and ev[0]["type"] == "audit"
    url, hdr, body = next(x for x in sent if json.loads(x[2])["event"].get("action") == "project.create")
    assert hdr["X-PipelineTrust-Signature"] == "sha256=" + hmac.new(b"hmac-key", body, hashlib.sha256).hexdigest()
    hd, bd = siem.build("splunk", "alert", {"x": 1}, "hec-token")
    assert hd["Authorization"] == "Splunk hec-token" and json.loads(bd)["sourcetype"] == "pipelinetrust:alert"
    hd, bd = siem.build("datadog", "audit", {"x": 1}, "dd-key")
    assert hd["DD-API-KEY"] == "dd-key" and json.loads(bd)[0]["ddsource"] == "pipelinetrust"
    sink = client.get("/api/siem/sinks", headers=h).json()[0]
    assert sink["delivered"] >= 1
    lines = client.get("/api/audit/export.jsonl?days=1", headers=h).text.strip().splitlines()
    assert any(json.loads(x)["action"] == "project.create" for x in lines)
    assert client.get("/api/siem/sinks", headers=org["other"]).json() == []


def test_policy_from_plain_english(client, org, monkeypatch):
    h = org["h"]
    d = client.post("/api/policies/draft", headers=h, json={"description": "Every third-party action must be pinned to a commit SHA"}).json()
    assert d["method"] == "template" and d["definition"]["target"] == "action" and d["test"]["violations"] > 0
    assert client.post("/api/policies/draft", headers=h, json={"description": "something nobody can parse at all"}).json()["method"] == "none"
    import app.insights.policy_author as pa
    from app.agents.llm import FakeProvider
    monkeypatch.setattr(pa, "get_provider", lambda: FakeProvider())
    d2 = client.post("/api/policies/draft", headers=h, json={"description": "flag jobs on self-hosted runners"}).json()
    assert d2["method"] == "llm" and d2["definition"]["id"].startswith("ORG-AI-") and "test" in d2


def test_golden_templates(client, org):
    from app.db import SessionLocal
    from app.models import Project
    h = register(client, "plat@golden.example.com", org="Golden Org")
    t = org["tmp"]
    src, _ = _scan_dir(client, h, "golden", _repo(t, "golden", {".github/workflows/ci.yml": CI_WF}), t)
    _scan_dir(client, h, "copycat", _repo(t, "copycat", {".github/workflows/ci.yml": CI_WF}), t)
    _scan_dir(client, h, "drifter", _repo(t, "drifter", {".github/workflows/build.yml": CI_WF.replace("      - run: npm run lint\n", "      - run: npm run e2e\n")}), t)
    caller = "name: CI\non: [push]\njobs:\n  ci:\n    uses: acme/golden/.github/workflows/ci.yml@v2\n"
    _scan_dir(client, h, "caller", _repo(t, "caller", {".github/workflows/ci.yml": caller}), t)
    _scan_dir(client, h, "other", _repo(t, "other", {".github/workflows/ci-legacy.yml": "on: [push]\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"}), t)
    with SessionLocal() as db:
        db.get(Project, src).repo_full_name = "acme/golden"
        db.commit()
    assert client.post("/api/templates", headers=h, json={"name": "x", "source_project_id": src, "workflow_path": ".github/workflows/nope.yml"}).status_code == 422
    assert client.post("/api/templates", headers=h, json={"name": "Standard CI", "source_project_id": src, "workflow_path": ".github/workflows/ci.yml",
                                                          "applies_to": "ci", "approved_refs": ["v3"]}).status_code == 201
    c = client.get("/api/templates/compliance", headers=h).json()[0]
    st = {r["project"]: r["status"] for r in c["rows"]}
    assert st == {"copycat": "copy", "drifter": "drifted_copy", "caller": "unapproved_ref", "other": "not_adopted"}
    drift = next(r for r in c["rows"] if r["project"] == "drifter")
    assert "run: npm run lint" in drift["missing_steps"] and "run: npm run e2e" in drift["extra_steps"]
    assert client.get("/api/templates/compliance", headers=org["other"]).json() == []


def test_no_write_scopes_for_pull_request_workflows(client, org):
    wf = ("name: PR bot\non: [pull_request]\njobs:\n  bot:\n    runs-on: ubuntu-latest\n    steps:\n"
          "      - uses: actions/checkout@v4\n      - run: gh pr comment 1 --body hi\n")
    pid, sid = _scan_dir(client, org["h"], "PRBot", _repo(org["tmp"], "prbot", {".github/workflows/pr.yml": wf}), org["tmp"])
    plan = client.get(f"/api/scans/{sid}/fixes", headers=org["h"]).json()
    fx = next(x for x in plan["fixes"] if x["rule_id"] == "PT-PBAC-001")
    patched = plan["files"][0]["patched"]
    assert "write" not in patched and "runs on pull_request" in fx["review"] and plan["summary"]["introduced"] == 0
