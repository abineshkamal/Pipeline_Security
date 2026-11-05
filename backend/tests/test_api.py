"""End-to-end API tests: auth, RBAC, tenant isolation, ZIP scan, triage, reports, credentials, audit."""
import json

import pytest
from sqlalchemy import select

from .conftest import SAMPLES, register, zip_dir


@pytest.fixture(scope="module")
def ctx(client, tmp_path_factory):
    admin = register(client, "admin@acme-sec.example.com")
    other = register(client, "eve@other-org.example.com", org="Other Org")
    r = client.post("/api/projects", headers=admin, json={"name": "Vulnerable App", "source_type": "upload"})
    assert r.status_code == 201
    pid = r.json()["id"]
    z = zip_dir(SAMPLES / "vulnerable-repo", tmp_path_factory.mktemp("z") / "repo.zip")
    with open(z, "rb") as fh:
        r = client.post(f"/api/projects/{pid}/scans/upload?tools=gitleaks,actionlint,zizmor", headers=admin,
                        files={"file": ("repo.zip", fh, "application/zip")})
    assert r.status_code == 202, r.text
    sid = r.json()["id"]
    return {"admin": admin, "other": other, "pid": pid, "sid": sid}


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert r.headers["X-Content-Type-Options"] == "nosniff"


def test_auth_required(client):
    assert client.get("/api/projects").status_code == 401
    assert client.get("/api/projects", headers={"Authorization": "Bearer junk"}).status_code == 401


def test_weak_password_and_duplicate(client, ctx):
    r = client.post("/api/auth/register", json={"email": "w@weak.example.com", "password": "alllowercase1", "organization_name": "W"})
    assert r.status_code == 422
    r = client.post("/api/auth/register", json={"email": "admin@acme-sec.example.com", "password": "Str0ng!Passw0rd", "organization_name": "Dup"})
    assert r.status_code == 409


def test_login_and_bruteforce_throttle(client, ctx):
    assert client.post("/api/auth/login", json={"email": "admin@acme-sec.example.com", "password": "Str0ng!Passw0rd"}).status_code == 200
    codes = [client.post("/api/auth/login", json={"email": "victim@acme-sec.example.com", "password": "wrong"}).status_code for _ in range(12)]
    assert codes[0] == 401 and codes[-1] == 429


def test_scan_completed_with_results(client, ctx):
    r = client.get(f"/api/scans/{ctx['sid']}", headers=ctx["admin"])
    s = r.json()
    assert s["status"] == "completed", s["error"]
    assert s["posture_score"] is not None and s["posture_score"] < 50
    assert len(s["controls"]) >= 40
    assert s["attack_graph"]["paths"]
    assert all(p["finding_ids"] for p in s["attack_graph"]["paths"])
    tools = {t["tool"]: t["status"] for t in s["tool_runs"]}
    assert tools["gitleaks"] == "ok" and tools["zizmor"] == "ok" and tools["trivy"] == "skipped"
    ai = s["ai_analysis"]
    assert ai["mode"] == "deterministic" and ai["report"]["executive_summary"]
    assert ai["guardrail"]["dropped_count"] == 0
    # repository code removed after assessment
    from app.services.scan_runner import workspace_dir
    assert not workspace_dir(ctx["sid"]).exists()


def test_findings_filter_and_triage(client, ctx):
    fs = client.get(f"/api/scans/{ctx['sid']}/findings?severity=critical", headers=ctx["admin"]).json()
    assert fs and all(f["severity"] == "critical" for f in fs)
    fid = fs[0]["id"]
    r = client.patch(f"/api/findings/{fid}", headers=ctx["admin"], json={"triage_status": "false_positive", "triage_note": "test fixture"})
    assert r.status_code == 200 and r.json()["triage_status"] == "false_positive"
    assert client.patch(f"/api/findings/{fid}", headers=ctx["admin"], json={"triage_status": "bogus"}).status_code == 422


def test_tenant_isolation(client, ctx):
    o = ctx["other"]
    assert client.get(f"/api/scans/{ctx['sid']}", headers=o).status_code == 404
    assert client.get(f"/api/scans/{ctx['sid']}/findings", headers=o).status_code == 404
    assert client.get(f"/api/projects/{ctx['pid']}", headers=o).status_code == 404
    assert client.get(f"/api/scans/{ctx['sid']}/report.html", headers=o).status_code == 404
    assert client.get("/api/projects", headers=o).json() == []
    fid = client.get(f"/api/scans/{ctx['sid']}/findings", headers=ctx["admin"]).json()[0]["id"]
    assert client.patch(f"/api/findings/{fid}", headers=o, json={"triage_status": "fixed"}).status_code == 404
    # spoofed org header does not grant access
    org_id = client.get("/api/org", headers=ctx["admin"]).json()["id"]
    assert client.get("/api/projects", headers={**o, "X-Org-Id": org_id}).status_code == 403


def test_rbac(client, ctx):
    a = ctx["admin"]
    for email, role in (("viewer@acme-sec.example.com", "viewer"), ("analyst@acme-sec.example.com", "analyst")):
        r = client.post("/api/org/members", headers=a, json={"email": email, "password": "Str0ng!Passw0rd", "role": role})
        assert r.status_code == 201
    login = lambda e: {"Authorization": "Bearer " + client.post("/api/auth/login", json={"email": e, "password": "Str0ng!Passw0rd"}).json()["access_token"]}  # noqa: E731
    v, an = login("viewer@acme-sec.example.com"), login("analyst@acme-sec.example.com")
    assert client.get(f"/api/scans/{ctx['sid']}", headers=v).status_code == 200
    assert client.post("/api/projects", headers=v, json={"name": "x", "source_type": "upload"}).status_code == 403
    fid = client.get(f"/api/scans/{ctx['sid']}/findings", headers=v).json()[1]["id"]
    assert client.patch(f"/api/findings/{fid}", headers=v, json={"triage_status": "confirmed"}).status_code == 403
    assert client.patch(f"/api/findings/{fid}", headers=an, json={"triage_status": "confirmed"}).status_code == 200
    assert client.post("/api/credentials", headers=an, json={"name": "t", "secret": "ghp_xxxxxxxxxxxx"}).status_code == 403
    assert client.get("/api/org/audit", headers=an).status_code == 403
    assert client.delete(f"/api/projects/{ctx['pid']}", headers=an).status_code == 403


def test_credentials_never_returned(client, ctx):
    secret = "ghp_SuperSecretValue000000000000000001"
    r = client.post("/api/credentials", headers=ctx["admin"], json={"name": "gh", "secret": secret})
    assert r.status_code == 201 and secret not in r.text and r.json()["hint"] == "...0001"
    assert secret not in client.get("/api/credentials", headers=ctx["admin"]).text
    from app.db import SessionLocal
    from app.models import Credential
    with SessionLocal() as db:
        c = db.execute(select(Credential)).scalars().first()
        assert secret not in c.secret_encrypted


def test_reports(client, ctx):
    a = ctx["admin"]
    h = client.get(f"/api/scans/{ctx['sid']}/report.html", headers=a)
    assert h.status_code == 200 and "CI/CD Security Assessment Report" in h.text and "CICD-SEC-10" in h.text
    assert "default-src 'none'" in h.headers["content-security-policy"]
    assert "AKIAIOSFODNN7EXAMPLE" not in h.text  # secrets redacted
    j = client.get(f"/api/scans/{ctx['sid']}/report.json", headers=a).json()
    assert j["framework"].startswith("OWASP") and j["findings"]
    assert all(f["triage_status"] != "false_positive" for f in j["findings"])
    s = client.get(f"/api/scans/{ctx['sid']}/report.sarif", headers=a).json()
    assert s["version"] == "2.1.0" and s["runs"][0]["results"]
    r0 = s["runs"][0]["results"][0]
    assert r0["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_rescan_carries_triage_and_compare(client, ctx, tmp_path):
    a = ctx["admin"]
    fp = [f for f in client.get(f"/api/scans/{ctx['sid']}/findings", headers=a).json() if f["triage_status"] == "false_positive"][0]["fingerprint"]
    z = zip_dir(SAMPLES / "vulnerable-repo", tmp_path / "r2.zip")
    with open(z, "rb") as fh:
        sid2 = client.post(f"/api/projects/{ctx['pid']}/scans/upload?tools=", headers=a, files={"file": ("r.zip", fh)}).json()["id"]
    f2 = [f for f in client.get(f"/api/scans/{sid2}/findings", headers=a).json() if f["fingerprint"] == fp]
    assert f2 and f2[0]["triage_status"] == "false_positive"
    cmp = client.get(f"/api/scans/{sid2}/compare/{ctx['sid']}", headers=a).json()
    assert cmp["persisting"] > 0 and isinstance(cmp["new"], list)
    trend = client.get(f"/api/projects/{ctx['pid']}/trend", headers=a).json()
    assert len(trend) == 2
    d = client.get("/api/dashboard", headers=a).json()
    assert d["projects"] == 1 and d["assessed_projects"] == 1


def test_upload_rejects_non_zip(client, ctx):
    r = client.post(f"/api/projects/{ctx['pid']}/scans/upload", headers=ctx["admin"], files={"file": ("x.zip", b"hello")})
    assert r.status_code == 422


def test_audit_log(client, ctx):
    rows = client.get("/api/org/audit", headers=ctx["admin"]).json()
    actions = {r["action"] for r in rows}
    assert {"auth.register", "project.create", "scan.upload", "finding.triage", "credential.create", "report.export"} <= actions
    assert all("ghp_SuperSecret" not in json.dumps(r) for r in rows)


def test_rules_catalog(client):
    rules = client.get("/api/rules").json()
    assert len(rules) >= 40 and all(r["references"] for r in rules)
