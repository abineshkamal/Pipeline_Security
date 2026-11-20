"""Executes one scan end-to-end and persists results. Runs in a worker thread or the Redis worker process."""
from __future__ import annotations

import json
import logging
import shutil
import traceback
from types import SimpleNamespace
from pathlib import Path

from sqlalchemy import select

from ..agents.pipeline import run_ai_analysis
from ..config import get_settings
from ..connectors.base import ConnectorError, registry
from ..db import SessionLocal
from ..graph.attack_paths import sync_to_neo4j
from ..models import ActionAdvisory, Credential, Finding, OrgPolicy, Project, Scan, utcnow
from ..scanner.engine import run_assessment
from ..scanner.rules import load_rules
from ..security import decrypt_secret
from .audit import record
from .exceptions import apply_to_findings as apply_exceptions
from .monitoring import after_scan
from .tickets import sync_after_scan as sync_tickets

log = logging.getLogger("pipelinetrust.runner")


def rule_catalog() -> dict[str, dict]:
    return {rid: cls.describe() for rid, cls in load_rules().items()}


def finding_to_dict(f: Finding) -> dict:
    return {c: getattr(f, c) for c in ("id", "rule_id", "category", "title", "severity", "confidence", "risk_score", "evidence_type",
                                        "message", "file_path", "line", "snippet", "workflow", "job", "fingerprint", "extra",
                                        "triage_status", "validation_status", "triage_note", "ai_notes")}


def workspace_dir(scan_id: str) -> Path:
    return get_settings().data_dir / "workspaces" / scan_id


def artifacts_dir(scan_id: str) -> Path:
    return get_settings().data_dir / "artifacts" / scan_id


def org_scan_extensions(db, org_id: str) -> dict:
    """Organization policies and advisories that every scan of this organization evaluates."""
    pols = db.execute(select(OrgPolicy).where(OrgPolicy.organization_id == org_id, OrgPolicy.enabled.is_(True))
                      .order_by(OrgPolicy.policy_id)).scalars().all()
    advs = db.execute(select(ActionAdvisory).where(ActionAdvisory.organization_id == org_id)).scalars().all()
    return {"custom_policies": [p.definition for p in pols], "custom_advisories": [a.as_advisory() for a in advs]}


def save_workflow_sources(scan_id: str, sources: dict[str, str]) -> None:
    """Keep the workflow files (only `.github/workflows/*`, small text) so fixes can be generated after the workspace is deleted."""
    d = artifacts_dir(scan_id)
    d.mkdir(parents=True, exist_ok=True)
    (d / "workflows.json").write_text(json.dumps(sources), "utf-8")


def load_workflow_sources(scan_id: str) -> dict[str, str] | None:
    p = artifacts_dir(scan_id) / "workflows.json"
    try:
        return json.loads(p.read_text("utf-8"))
    except (OSError, ValueError):
        return None


def _set(db, scan: Scan, **kw):
    for k, v in kw.items():
        setattr(scan, k, v)
    db.commit()


def execute_scan(scan_id: str) -> None:
    db = SessionLocal()
    scan = db.get(Scan, scan_id)
    if not scan or scan.status not in ("queued", "running"):
        db.close()
        return
    project = db.get(Project, scan.project_id)
    work = workspace_dir(scan_id)
    client = None
    try:
        _set(db, scan, status="running", started_at=utcnow(), progress="Preparing workspace")

        def progress(msg: str):
            scan.progress = msg[:200]
            db.commit()

        connector = registry().get(project.source_type)
        if not connector:
            raise ConnectorError(f"unknown source type {project.source_type}")
        secret = None
        if project.credential_id:
            cred = db.get(Credential, project.credential_id)
            if cred and cred.organization_id == project.organization_id:
                secret = decrypt_secret(cred.secret_encrypted)
        target = project
        if (scan.options or {}).get("ref"):  # scan a specific branch / tag / commit without changing the project
            target = SimpleNamespace(**{c: getattr(project, c) for c in ("id", "name", "repo_full_name", "source_type", "organization_id")},
                                     ref=scan.options["ref"])
        ws = connector.acquire(project=target, secret=secret, workdir=work,
                               upload_path=Path(scan.upload_path) if scan.upload_path else None, progress=progress)
        client = getattr(ws, "_client", None)
        opts = {**(scan.options or {}), **org_scan_extensions(db, scan.organization_id)}
        result = run_assessment(ws.root, ws.metadata, opts, artifacts_dir(scan_id), progress, ws.sha_resolver)
        save_workflow_sources(scan_id, result.workflow_sources)

        progress("Saving findings")
        db.query(Finding).filter(Finding.scan_id == scan_id).delete()
        prior = _previous_triage(db, scan)
        fp_to_id = {}
        rows = []
        for fr in result.findings:
            row = Finding(organization_id=scan.organization_id, scan_id=scan_id, rule_id=fr.rule_id, category=fr.category,
                          title=fr.title[:300], severity=fr.severity, confidence=fr.confidence, risk_score=fr.risk_score,
                          evidence_type=fr.evidence_type, message=fr.message, file_path=fr.file_path[:500], line=fr.line,
                          snippet=fr.snippet[:4000], workflow=fr.workflow[:300], job=fr.job[:200], fingerprint=fr.fingerprint,
                          extra=fr.extra,
                          validation_status="config_evidence" if fr.evidence_type in ("configuration", "tool") else "needs_validation")
            if fr.fingerprint in prior:  # carry analyst triage decisions across re-scans
                row.triage_status, row.triage_note = prior[fr.fingerprint]
            db.add(row)
            rows.append(row)
        db.flush()
        for r in rows:
            fp_to_id.setdefault(r.fingerprint, r.id)
        graph = result.attack_graph
        for p in graph.get("paths", []):
            p["finding_ids"] = [fp_to_id[fp] for fp in p["findings"] if fp in fp_to_id]
        for e in graph.get("edges", []):
            e["finding_ids"] = [fp_to_id[fp] for fp in e.get("findings", []) if fp in fp_to_id]
        inv = result.inventory
        inv["sbom_available"] = bool(result.sbom_path)
        _set(db, scan, inventory=inv, controls=result.controls, tool_runs=result.tool_runs, summary=result.summary,
             attack_graph=graph, posture_score=result.summary.get("posture_score"), commit_sha=ws.commit_sha)

        neo = sync_to_neo4j(scan_id, graph)
        if neo != "disabled":
            graph["neo4j_sync"] = neo
            scan.attack_graph = dict(graph)
            db.commit()

        if (scan.options or {}).get("ai", True):
            progress("Running AI analysis agents")
            run_ai_for_scan(db, scan)

        apply_exceptions(db, scan.project_id, rows)  # approved, unexpired risk exceptions
        _set(db, scan, status="completed", progress="Completed", finished_at=utcnow())
        record(db, scan.organization_id, None, "scan.completed", f"scan:{scan_id}",
               {"posture_score": scan.posture_score, "findings": len(rows), "trigger": (scan.options or {}).get("trigger", "manual")})
        try:
            alert = after_scan(db, scan)
            if alert:
                record(db, scan.organization_id, None, "alert.drift", f"scan:{scan_id}",
                       {"alert": alert.id, "severity": alert.severity, "items": len(alert.items),
                        "delivered": sum(1 for d in alert.deliveries if d["ok"])})
        except Exception as exc:  # noqa: BLE001 - monitoring must never fail a completed scan
            log.error("drift check for scan %s failed: %s", scan_id, exc)
            db.rollback()
        try:
            t = sync_tickets(db, scan)
            if t["resolved"]:
                record(db, scan.organization_id, None, "tickets.resolved", f"scan:{scan_id}", t)
        except Exception as exc:  # noqa: BLE001
            log.error("ticket sync for scan %s failed: %s", scan_id, exc)
            db.rollback()
    except Exception as exc:  # noqa: BLE001 - surface any failure on the scan record
        log.error("scan %s failed: %s", scan_id, exc)
        traceback.print_exc()
        db.rollback()
        scan = db.get(Scan, scan_id)
        msg = str(exc) if isinstance(exc, ConnectorError) else f"{type(exc).__name__}: {exc}"
        _set(db, scan, status="failed", error=msg[:2000], progress="Failed", finished_at=utcnow())
        record(db, scan.organization_id, None, "scan.failed", f"scan:{scan_id}", {"error": msg[:300]})
    finally:
        if client:
            client.close()
        shutil.rmtree(work, ignore_errors=True)  # repository code is deleted after assessment
        if scan and scan.upload_path:
            Path(scan.upload_path).unlink(missing_ok=True)
        db.close()


def _previous_triage(db, scan: Scan) -> dict[str, tuple[str, str]]:
    prev = db.execute(select(Scan).where(Scan.project_id == scan.project_id, Scan.id != scan.id, Scan.status == "completed", Scan.ref_override == "")
                      .order_by(Scan.created_at.desc()).limit(1)).scalar_one_or_none()
    if not prev:
        return {}
    rows = db.execute(select(Finding.fingerprint, Finding.triage_status, Finding.triage_note, Finding.extra)
                      .where(Finding.scan_id == prev.id, Finding.triage_status.in_(["false_positive", "accepted_risk", "confirmed"]))).all()
    # accepted_risk that came from a risk exception is re-derived from the exception, never carried over
    return {r[0]: (r[1], r[2]) for r in rows if not (r[1] == "accepted_risk" and (r[3] or {}).get("exception"))}


def run_ai_for_scan(db, scan: Scan, provider=None) -> dict:
    findings = db.execute(select(Finding).where(Finding.scan_id == scan.id).order_by(Finding.risk_score.desc())).scalars().all()
    active = [f for f in findings if f.triage_status != "false_positive"]
    paths = (scan.attack_graph or {}).get("paths", [])
    analysis = run_ai_analysis([finding_to_dict(f) for f in active], scan.controls, scan.inventory, paths, scan.summary,
                               rule_catalog(), provider)
    by_id = {f.id: f for f in findings}
    for fid, t in (analysis.get("triage") or {}).items():
        if fid in by_id:
            by_id[fid].ai_notes = {**(by_id[fid].ai_notes or {}), "triage": t}
    for fid, fx in (analysis.get("fixes") or {}).items():
        if fid in by_id:
            by_id[fid].ai_notes = {**(by_id[fid].ai_notes or {}), "fix": fx}
    scan.ai_analysis = analysis
    db.commit()
    return analysis
