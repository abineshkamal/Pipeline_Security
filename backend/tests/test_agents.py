"""AI agent pipeline: deterministic mode, fake LLM mode, guardrails; Redis worker via fakeredis."""
from app.agents.llm import FakeProvider, LLMProvider, extract_json
from app.agents.pipeline import run_ai_analysis
from app.scanner.engine import run_assessment
from app.scanner.model import RepoMetadata
from app.scanner.rules import load_rules

from .conftest import SAMPLES, register, zip_dir


def _inputs():
    r = run_assessment(SAMPLES / "vulnerable-repo", RepoMetadata(source="upload"), {"run_tools": False})
    findings = [f.__dict__ | {"id": f"F{i}", "fingerprint": f.fingerprint} for i, f in enumerate(r.findings)]
    fp = {f["fingerprint"]: f["id"] for f in findings}
    for p in r.attack_graph["paths"]:
        p["finding_ids"] = [fp[x] for x in p["findings"]]
    rules = {k: c.describe() for k, c in load_rules().items()}
    return findings, r, rules


def test_deterministic_mode_without_llm():
    findings, r, rules = _inputs()
    a = run_ai_analysis(findings, r.controls, r.inventory, r.attack_graph["paths"], r.summary, rules, LLMProvider())
    assert a["mode"] == "deterministic"
    assert a["triage"] and a["fixes"] and a["narratives"] and a["report"]["executive_summary"]
    assert all(t["mode"] in ("deterministic", "skipped") for t in a["trace"])


def test_fake_llm_mode_and_guardrail_drops_hallucinations():
    findings, r, rules = _inputs()
    a = run_ai_analysis(findings, r.controls, r.inventory, r.attack_graph["paths"], r.summary, rules, FakeProvider())
    assert a["mode"] == "llm"
    assert "HALLUCINATED-ID" not in a["triage"]
    assert "AP-99" not in a["narratives"]
    assert a["guardrail"]["dropped_count"] == 2
    assert set(a["triage"]) <= {f["id"] for f in findings}


def test_extract_json_tolerates_prose():
    assert extract_json('Sure! ```json\n{"a": 1}\n``` done') == {"a": 1}
    assert extract_json('prefix {"b": {"c": 2}} suffix') == {"b": {"c": 2}}
    assert extract_json("no json") is None


def test_redis_worker_with_fakeredis(client, tmp_path, monkeypatch):
    import fakeredis

    from app.config import get_settings
    from app.services import jobs

    hdr = register(client, "redis@acme-sec.example.com", org="Redis Org")
    pid = client.post("/api/projects", headers=hdr, json={"name": "R", "source_type": "upload"}).json()["id"]
    fake = fakeredis.FakeRedis()
    monkeypatch.setattr(get_settings(), "redis_url", "redis://fake")
    monkeypatch.setattr(jobs, "_redis", lambda: fake)
    import app.api.scans as scans_api
    monkeypatch.setattr(scans_api, "enqueue_scan", _real_enqueue(jobs))
    z = zip_dir(SAMPLES / "hardened-repo", tmp_path / "h.zip")
    with open(z, "rb") as fh:
        sid = client.post(f"/api/projects/{pid}/scans/upload?tools=", headers=hdr, files={"file": ("h.zip", fh)}).json()["id"]
    assert client.get(f"/api/scans/{sid}", headers=hdr).json()["status"] == "queued"
    assert fake.llen(jobs.QUEUE_KEY) == 1
    assert jobs.worker_loop(client=fake, once=True, timeout=1) == 1
    s = client.get(f"/api/scans/{sid}", headers=hdr).json()
    assert s["status"] == "completed" and s["posture_score"] == 100.0


def _real_enqueue(jobs):
    def enqueue(scan_id):
        jobs._redis().rpush(jobs.QUEUE_KEY, scan_id)
        return "redis"
    return enqueue
