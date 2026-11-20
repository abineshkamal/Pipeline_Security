"""Fix campaigns: roll one or more auto-fixable rules out as verified pull requests across many repositories,
then track each pull request until it is merged and the re-scan confirms the findings are gone."""
from __future__ import annotations

import logging
import threading

import httpx
from sqlalchemy import select

from ..connectors.github import GitHubClient
from ..db import SessionLocal
from ..insights import fixes
from ..models import ActionAdvisory, CampaignItem, Credential, Finding, FixCampaign, Project, utcnow
from ..security import decrypt_secret
from .exceptions import latest_scan
from .scan_runner import load_workflow_sources, save_workflow_sources

log = logging.getLogger("pipelinetrust.campaigns")


def _token(db, cred_id: str | None, org_id: str) -> str | None:
    if not cred_id:
        return None
    c = db.get(Credential, cred_id)
    return decrypt_secret(c.secret_encrypted) if c and c.organization_id == org_id else None


def candidates(db, org_id: str, rule_ids: list[str]) -> list[dict]:
    out = []
    for p in db.execute(select(Project).where(Project.organization_id == org_id)).scalars():
        s = latest_scan(db, p.id)
        if not s:
            continue
        fs = db.execute(select(Finding).where(Finding.scan_id == s.id, Finding.rule_id.in_(rule_ids),
                                              Finding.triage_status.in_(["open", "confirmed"]))).scalars().all()
        if fs:
            out.append({"project_id": p.id, "name": p.name, "repo": p.repo_full_name, "source_type": p.source_type,
                        "scan_id": s.id, "findings": len(fs), "files": len({f.file_path for f in fs}),
                        "eligible": p.source_type == "github" and bool(p.repo_full_name)})
    return sorted(out, key=lambda x: (not x["eligible"], -x["findings"]))


def plan_for(db, project: Project, rule_ids: list[str]) -> tuple[dict | None, str, object]:
    s = latest_scan(db, project.id)
    if not s:
        return None, "never scanned", None
    token = _token(db, project.credential_id, project.organization_id)
    src = load_workflow_sources(s.id)
    if src is None and project.repo_full_name:
        try:
            src = fixes.fetch_sources(project.repo_full_name, s.commit_sha, [w["path"] for w in (s.inventory or {}).get("workflows", [])], token)
        except Exception:  # noqa: BLE001
            src = {}
        if src:
            save_workflow_sources(s.id, src)
    if not src:
        return None, "workflow files unavailable - re-scan the project", s
    fs = db.execute(select(Finding).where(Finding.scan_id == s.id, Finding.rule_id.in_(rule_ids),
                                          Finding.triage_status.in_(["open", "confirmed"]))).scalars().all()
    if not fs:
        return None, "no open findings for these rules", s
    advs = [a.as_advisory() for a in db.execute(select(ActionAdvisory).where(ActionAdvisory.organization_id == project.organization_id)).scalars()]
    gh = GitHubClient(token)
    try:
        return fixes.plan_fixes(src, fs, s.inventory or {}, gh.resolve_sha, advs), "", s
    finally:
        gh.close()


def run_campaign(campaign_id: str) -> None:
    db = SessionLocal()
    try:
        c = db.get(FixCampaign, campaign_id)
        write_token = _token(db, c.credential_id, c.organization_id)
        for it in db.execute(select(CampaignItem).where(CampaignItem.campaign_id == c.id, CampaignItem.status == "pending")).scalars().all():
            p = db.get(Project, it.project_id)
            try:
                plan, why, scan = plan_for(db, p, c.rule_ids)
                it.scan_id = scan.id if scan else ""
                if not plan:
                    it.status, it.detail = "no_changes", why
                else:
                    files = {f["path"]: f["patched"] for f in plan["files"] if not f["parse_error"] and f["verified"]}
                    applied = [x for x in plan["fixes"] if x["status"] == "applied" and x["file"] in files]
                    it.findings = len(plan["fixes"])
                    it.fixes_applied, it.files = len(applied), len(files)
                    it.needs_review = sum(1 for x in applied if x["review"])
                    if not files:
                        it.status, it.detail = "no_changes", "no verified fix could be generated (see skipped reasons in the project's Fix tab)"
                    elif c.dry_run:
                        it.status, it.detail = "planned", f"{len(applied)} fix(es) in {len(files)} file(s) ready"
                    elif not write_token:
                        it.status, it.detail = "failed", "campaign has no write credential"
                    else:
                        reviews = "".join(f"\n- `{x['file']}`: {x['review']}" for x in applied if x["review"])
                        body = (f"Part of the PipelineTrust fix campaign **{c.name}** ({', '.join(c.rule_ids)}).\n\n"
                                f"{len(applied)} rule-based fix(es) in {len(files)} workflow file(s), each verified by re-running the workflow rules on the "
                                f"patched file (scan `{scan.id[:8]}`, commit `{(scan.commit_sha or '')[:10]}`).\n"
                                + "".join(f"\n- `{x['file']}`{':' + str(x['line']) if x['line'] else ''}: {x['detail']}" for x in applied[:60])
                                + (f"\n\n**Please review:**{reviews}" if reviews else ""))
                        pr = fixes.open_pull_request(p.repo_full_name, scan.commit_sha, files, write_token, f"{c.name} (PipelineTrust)", body)
                        it.status, it.pr_url, it.pr_number, it.branch, it.detail = "pr_open", pr["url"] or "", pr["number"], pr["branch"], ""
            except (fixes.GitHubWriteError, httpx.HTTPError) as exc:
                it.status, it.detail = "failed", str(exc)[:500]
            except Exception as exc:  # noqa: BLE001 - one repository must not stop the campaign
                log.exception("campaign %s item %s failed", c.id, it.id)
                it.status, it.detail = "failed", f"{type(exc).__name__}: {exc}"[:500]
            it.updated_at = utcnow()
            db.commit()
        c.status, c.finished_at = "done", utcnow()
        db.commit()
    finally:
        db.close()


def start(campaign_id: str) -> None:
    threading.Thread(target=run_campaign, args=(campaign_id,), name=f"pt-campaign-{campaign_id[:6]}", daemon=True).start()


def refresh(db, c: FixCampaign) -> None:
    """Pull request state from GitHub and the remaining findings from each project's latest scan."""
    token = _token(db, c.credential_id, c.organization_id)
    gh = GitHubClient(token)
    try:
        for it in db.execute(select(CampaignItem).where(CampaignItem.campaign_id == c.id)).scalars().all():
            p = db.get(Project, it.project_id)
            if it.pr_number and it.status in ("pr_open", "merged", "closed"):
                r = gh.result(f"/repos/{p.repo_full_name}/pulls/{it.pr_number}")
                if r.status == "ok":
                    it.status = "merged" if r.data.get("merged_at") else "closed" if r.data.get("state") == "closed" else "pr_open"
            s = latest_scan(db, p.id)
            if s:
                it.remaining = len(db.execute(select(Finding.id).where(Finding.scan_id == s.id, Finding.rule_id.in_(c.rule_ids),
                                                                      Finding.triage_status.in_(["open", "confirmed"]))).all())
            it.updated_at = utcnow()
        db.commit()
    finally:
        gh.close()
