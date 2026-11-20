"""Organization import + leaderboard, scheduled scans, drift alerts and delivery, risk exceptions, secret rotation."""
from datetime import date, datetime, timedelta, timezone

import pytest

from .conftest import SAMPLES, register, zip_dir

PW = "Str0ng!Passw0rd"


def _upload(client, h, pid, sample, tmp):
    z = zip_dir(SAMPLES / sample, tmp / f"{sample}.zip")
    with open(z, "rb") as fh:
        sid = client.post(f"/api/projects/{pid}/scans/upload?tools=&ai=false", headers=h, files={"file": ("r.zip", fh)}).json()["id"]
    assert client.get(f"/api/scans/{sid}", headers=h).json()["status"] == "completed"
    return sid


def _login(client, email):
    r = client.post("/api/auth/login", json={"email": email, "password": PW})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="module")
def org(client):
    admin = register(client, "admin@monitor.example.com", org="Monitor Org")
    for email, role in (("analyst@monitor.example.com", "analyst"), ("admin2@monitor.example.com", "admin")):
        assert client.post("/api/org/members", headers=admin, json={"email": email, "password": PW, "role": role}).status_code == 201
    return {"admin": admin, "analyst": _login(client, "analyst@monitor.example.com"), "admin2": _login(client, "admin2@monitor.example.com"),
            "other": register(client, "eve@outside.example.com", org="Outside Org")}


@pytest.fixture()
def sent(monkeypatch):
    import app.services.monitoring as mon
    calls = []
    monkeypatch.setattr(mon, "post_json", lambda url, body: calls.append((url, body)) or 200)
    return calls


def test_drift_alert_on_regression_and_delivery(client, org, sent, tmp_path):
    a = org["admin"]
    ch = client.post("/api/notifications/channels", headers=a, json={"name": "secops", "kind": "slack",
                                                                      "url": "https://hooks.slack.example.com/services/T/B/x", "min_severity": "high"})
    assert ch.status_code == 201 and "url" not in ch.json() and ch.json()["url_hint"].startswith("https://hooks.slack.example.com/")
    assert client.post("/api/notifications/channels", headers=a, json={"name": "x", "kind": "webhook", "url": "http://example.com/h"}).status_code == 422
    assert client.post("/api/notifications/channels", headers=org["analyst"], json={"name": "x", "kind": "slack",
                                                                                     "url": "https://hooks.slack.example.com/a"}).status_code == 403
    pid = client.post("/api/projects", headers=a, json={"name": "Drift", "source_type": "upload"}).json()["id"]
    _upload(client, a, pid, "hardened-repo", tmp_path)
    assert client.get("/api/alerts", headers=a, params={"project_id": pid}).json() == []   # first scan: nothing to compare
    sid = _upload(client, a, pid, "vulnerable-repo", tmp_path)
    alerts = client.get("/api/alerts", headers=a, params={"project_id": pid}).json()
    assert len(alerts) == 1
    al = alerts[0]
    kinds = {i["kind"] for i in al["items"]}
    assert al["scan_id"] == sid and {"score_drop", "new_finding", "new_attack_path", "secret_exposed"} <= kinds
    assert al["severity"] == "critical" and al["deliveries"][0]["ok"]
    url, body = sent[-1]
    assert url.endswith("/services/T/B/x") and "posture worsened" in body["text"]
    assert client.get("/api/alerts", headers=org["other"]).json() == []                   # tenant isolation
    # an improvement (vulnerable -> hardened) raises nothing
    n = len(sent)
    _upload(client, a, pid, "hardened-repo", tmp_path)
    assert len(client.get("/api/alerts", headers=a, params={"project_id": pid}).json()) == 1 and len(sent) == n
    acked = client.post(f"/api/alerts/{al['id']}/ack", headers=org["analyst"]).json()
    assert acked["acknowledged_by"] == "analyst@monitor.example.com"
    assert client.get("/api/alerts", headers=a, params={"project_id": pid}).json() == []
    test = client.post(f"/api/notifications/channels/{ch.json()['id']}/test", headers=a).json()
    assert test["ok"] and "Test message" in sent[-1][1]["text"]


def test_teams_and_webhook_payloads():
    from app.models import DriftAlert, Project
    from app.services.monitoring import payload
    al = DriftAlert(id="A1", scan_id="S", previous_scan_id="P", severity="high", title="t",
                    items=[{"kind": "new_finding", "severity": "high", "text": "x"}])
    pr = Project(id="p", name="n", repo_full_name="o/r")
    teams = payload("teams", al, pr)
    assert teams["attachments"][0]["content"]["type"] == "AdaptiveCard"
    hook = payload("webhook", al, pr)
    assert hook["event"] == "drift_alert" and hook["items"][0]["text"] == "x" and hook["project"]["repository"] == "o/r"


def test_webhook_url_guard(monkeypatch):
    from app.config import get_settings
    from app.services.monitoring import UnsafeURL, validate_webhook_url
    monkeypatch.setattr(get_settings(), "allow_private_webhooks", False)
    for bad in ("https://127.0.0.1/x", "https://localhost/x", "https://10.0.0.5/hook", "https://169.254.169.254/latest", "https://u:p@example.com/"):
        with pytest.raises(UnsafeURL):
            validate_webhook_url(bad)


def test_scheduler_queues_due_scans_once(client, org, monkeypatch):
    from app.services import jobs, scheduler
    queued = []
    monkeypatch.setattr(jobs, "enqueue_scan", lambda sid: queued.append(sid) or "test")
    a = org["admin"]
    up = client.post("/api/projects", headers=a, json={"name": "Zip", "source_type": "upload"}).json()["id"]
    assert client.put(f"/api/projects/{up}/schedule", headers=a, json={"schedule": "daily"}).status_code == 400
    pid = client.post("/api/projects", headers=a, json={"name": "Sched", "source_type": "github", "repo_full_name": "octo/sched"}).json()["id"]
    r = client.put(f"/api/projects/{pid}/schedule", headers=a, json={"schedule": "weekly"}).json()
    nxt = datetime.fromisoformat(r["next_scan_at"])
    nxt = nxt if nxt.tzinfo else nxt.replace(tzinfo=timezone.utc)
    assert timedelta(days=6, hours=23) < nxt - datetime.now(timezone.utc) <= timedelta(days=7)
    assert scheduler.run_due() == []                                            # not due yet
    later = datetime.now(timezone.utc) + timedelta(days=7, minutes=1)
    ids = scheduler.run_due(later)
    assert len(ids) == 1 and queued == ids
    assert scheduler.run_due(later) == []                                       # claimed: no double queue
    scan = client.get(f"/api/scans/{ids[0]}", headers=a).json()
    assert scan["options"]["trigger"] == "schedule"
    proj = client.get(f"/api/projects/{pid}", headers=a).json()
    assert proj["schedule"] == "weekly" and datetime.fromisoformat(proj["next_scan_at"]).replace(tzinfo=timezone.utc) > later
    assert client.put(f"/api/projects/{pid}/schedule", headers=a, json={"schedule": ""}).json()["next_scan_at"] is None
    assert client.put(f"/api/projects/{pid}/schedule", headers=org["other"], json={"schedule": "daily"}).status_code == 404


def test_risk_exception_four_eyes_expiry_and_rescan(client, org, tmp_path, monkeypatch):
    a, an, a2 = org["admin"], org["analyst"], org["admin2"]
    pid = client.post("/api/projects", headers=a, json={"name": "Exc", "source_type": "upload"}).json()["id"]
    sid = _upload(client, a, pid, "vulnerable-repo", tmp_path)
    fs = client.get(f"/api/scans/{sid}/findings", headers=a).json()
    f = next(x for x in fs if x["rule_id"] == "PT-3P-001" and x["file_path"])
    soon = (date.today() + timedelta(days=30)).isoformat()
    body = {"finding_id": f["id"], "scope": "rule_in_workflow", "reason": "Vendor action, pinned via internal mirror",
            "owner": "platform-team", "expires_on": soon}
    assert client.post("/api/exceptions", headers=an, json={**body, "expires_on": (date.today() + timedelta(days=400)).isoformat()}).status_code == 422
    assert client.post("/api/exceptions", headers=an, json={**body, "reason": "short"}).status_code == 422
    ex = client.post("/api/exceptions", headers=an, json=body).json()
    assert ex["state"] == "pending" and ex["matched_findings"] >= 1 and ex["workflow"] == f["file_path"]
    assert client.post("/api/exceptions", headers=an, json=body).status_code == 409           # duplicate
    assert client.post(f"/api/exceptions/{ex['id']}/decision", headers=an, json={"decision": "approve"}).status_code == 403  # analyst
    mine = client.post("/api/exceptions", headers=a, json={**body, "scope": "finding",
                                                           "finding_id": next(x["id"] for x in fs if x["rule_id"] == "PT-PBAC-001")}).json()
    assert client.post(f"/api/exceptions/{mine['id']}/decision", headers=a, json={"decision": "approve"}).status_code == 403  # own request
    ok = client.post(f"/api/exceptions/{ex['id']}/decision", headers=a2, json={"decision": "approve", "note": "ok until Q1"}).json()
    assert ok["state"] == "active" and ok["decided_by"] == "admin2@monitor.example.com" and ok["applied"]["covered"] == ok["matched_findings"]
    covered = [x for x in client.get(f"/api/scans/{sid}/findings", headers=a).json()
               if x["rule_id"] == "PT-3P-001" and x["file_path"] == f["file_path"]]
    assert covered and all(x["triage_status"] == "accepted_risk" and x["extra"]["exception"]["id"] == ex["id"] for x in covered)
    others = [x for x in client.get(f"/api/scans/{sid}/findings", headers=a).json() if x["rule_id"] == "PT-3P-001" and x["file_path"] != f["file_path"]]
    assert all(x["triage_status"] == "open" for x in others)
    # a re-scan re-applies the exception
    sid2 = _upload(client, a, pid, "vulnerable-repo", tmp_path)
    again = [x for x in client.get(f"/api/scans/{sid2}/findings", headers=a).json() if x["rule_id"] == "PT-3P-001" and x["file_path"] == f["file_path"]]
    assert again and all(x["triage_status"] == "accepted_risk" for x in again)
    # expiry reopens the findings, and a re-scan does not carry the acceptance over
    import app.services.exceptions as exs
    from app.services import scheduler
    monkeypatch.setattr(exs, "today", lambda: (date.today() + timedelta(days=31)).isoformat())
    scheduler.run_due()
    reopened = [x for x in client.get(f"/api/scans/{sid2}/findings", headers=a).json() if x["rule_id"] == "PT-3P-001" and x["file_path"] == f["file_path"]]
    assert all(x["triage_status"] == "open" and "exception" not in x["extra"] for x in reopened)
    assert client.get("/api/exceptions", headers=a, params={"state": "expired"}).json()[0]["id"] == ex["id"]
    monkeypatch.undo()
    # revoke: only requester or admin
    assert client.post(f"/api/exceptions/{mine['id']}/revoke", headers=an).status_code == 403
    assert client.post(f"/api/exceptions/{mine['id']}/revoke", headers=a).json()["state"] == "revoked"
    assert client.get("/api/exceptions", headers=org["other"]).json() == []


def test_portfolio_import_and_leaderboard(client, org, monkeypatch, tmp_path):
    from app.connectors.github import GitHubClient
    from app.services import jobs
    queued = []
    monkeypatch.setattr(jobs, "enqueue_scan", lambda sid: queued.append(sid) or "test")
    repos = [{"full_name": "acme/api", "private": False, "archived": False, "fork": False},
             {"full_name": "acme/web", "private": False, "archived": False, "fork": False},
             {"full_name": "acme/old", "private": False, "archived": True, "fork": False},
             {"full_name": "acme/forked", "private": False, "archived": False, "fork": True}]
    monkeypatch.setattr(GitHubClient, "list_owner_repos", lambda self, owner, limit=300: repos)
    a = org["admin"]
    assert client.post("/api/portfolio/import", headers=org["analyst"], json={"owner": "acme"}).status_code == 403
    assert client.post("/api/portfolio/import", headers=a, json={"owner": "bad/name"}).status_code == 422
    r = client.post("/api/portfolio/import", headers=a, json={"owner": "acme", "schedule": "daily"}).json()
    assert r["found"] == 4 and r["eligible"] == 2 and r["skipped_filtered"] == 2 and len(r["created"]) == 2 and r["scans_queued"] == 2
    again = client.post("/api/portfolio/import", headers=a, json={"owner": "acme", "scan_now": False}).json()
    assert again["created"] == [] and again["skipped_existing"] == 2
    pf = client.get("/api/portfolio", headers=a).json()
    rows = {p["repo"]: p for p in pf["projects"]}
    assert rows["acme/api"]["schedule"] == "daily" and rows["acme/api"]["team"] == "acme"
    assert pf["totals"]["scheduled"] >= 2
    scored = [p for p in pf["projects"] if p["posture_score"] is not None]
    assert scored == sorted(scored, key=lambda p: p["posture_score"]) and pf["projects"][0]["rank"] == 1
    assert all(p["posture_score"] is None for p in pf["projects"][len(scored):])                  # never-scanned last
    worst = scored[0]
    assert worst["attack_paths"] > 0 and worst["outsider_secrets"] >= 1
    assert any(t["team"] == "acme" and t["projects"] == 2 for t in pf["teams"])
    bulk = client.post("/api/portfolio/scan", headers=a, json={"project_ids": [rows["acme/web"]["project_id"], worst["project_id"]]}).json()
    assert bulk["queued"] + len(bulk["skipped"]) == 2
    assert client.put("/api/portfolio/schedule", headers=a, json={"schedule": "weekly", "project_ids": [rows["acme/web"]["project_id"]]}).json()["updated"] == 1
    assert client.get("/api/portfolio", headers=org["other"]).json()["totals"]["projects"] == 0


def test_secret_rotation_ages():
    from app.insights.secrets import rotation
    now = datetime(2026, 11, 19, tzinfo=timezone.utc)
    meta = {"status": "ok", "secrets": [
        {"name": "NPM_TOKEN", "scope": "repository", "updated_at": "2025-01-01T00:00:00Z"},
        {"name": "DEPLOY_KEY", "scope": "organization", "updated_at": "2026-10-01T00:00:00Z"},
        {"name": "DEPLOY_KEY", "scope": "environment:prod", "updated_at": "2026-07-15T00:00:00Z"},
        {"name": "AWS_KEY", "scope": "repository", "updated_at": "2026-07-01T00:00:00Z"}]}
    assert rotation("NPM_TOKEN", set(), meta, now)["status"] == "stale"
    assert rotation("AWS_KEY", set(), meta, now)["status"] == "aging"
    d = rotation("DEPLOY_KEY", {"prod"}, meta, now)                 # environment secret wins over the organization one
    assert d["status"] == "aging" and d["scope"] == "environment:prod"
    assert rotation("DEPLOY_KEY", set(), meta, now)["status"] == "ok"
    assert rotation("MISSING", set(), meta, now)["status"] == "missing"
    assert rotation("GITHUB_TOKEN", set(), meta, now)["status"] == "automatic"
    u = rotation("X", set(), {"status": "forbidden", "detail": "HTTP 403"}, now)
    assert u["status"] == "unknown" and "Secrets: read" in u["detail"]


def test_secret_map_reports_rotation(client, org, tmp_path):
    a = org["admin"]
    pid = client.post("/api/projects", headers=a, json={"name": "Rot", "source_type": "upload"}).json()["id"]
    sid = _upload(client, a, pid, "vulnerable-repo", tmp_path)
    d = client.get(f"/api/scans/{sid}/secrets", headers=a).json()
    assert d["rotation"]["status"] == "skipped" and all(s["rotation"]["status"] in ("unknown", "automatic") for s in d["secrets"])
