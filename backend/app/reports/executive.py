"""Executive report: one printable page on the organization's CI/CD posture over a period (default 30 days)."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from html import escape

from sqlalchemy import select

from ..models import DriftAlert, Finding, Organization, Project, RiskException, Scan
from ..services.exceptions import state as ex_state
from ..services.monitoring import ensure_insights

SEV = ("critical", "high", "medium", "low")


def _aware(d: datetime) -> datetime:
    return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d


def build(db, org_id: str, days: int = 30) -> dict:
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)
    org = db.get(Organization, org_id)
    projects = db.execute(select(Project).where(Project.organization_id == org_id)).scalars().all()
    scans = db.execute(select(Scan).where(Scan.organization_id == org_id, Scan.status == "completed", Scan.ref_override == "").order_by(Scan.created_at)).scalars().all()
    by_proj: dict[str, list[Scan]] = {}
    for s in scans:
        by_proj.setdefault(s.project_id, []).append(s)

    # weekly trend of the average latest score
    trend = []
    weeks = max(1, days // 7)
    for i in range(weeks, -1, -1):
        at = now - timedelta(days=7 * i)
        latest = [next((s for s in reversed(ss) if _aware(s.created_at) <= at), None) for ss in by_proj.values()]
        sc = [s.posture_score for s in latest if s and s.posture_score is not None]
        trend.append({"date": at.date().isoformat(), "average": round(sum(sc) / len(sc), 1) if sc else None, "projects": len(sc)})

    rows, new_total, fixed_total, rule_counts = [], 0, 0, Counter()
    for p in projects:
        ss = by_proj.get(p.id, [])
        if not ss:
            continue
        last = ss[-1]
        base = next((s for s in reversed(ss) if _aware(s.created_at) <= start), ss[0])
        ins = ensure_insights(db, last)
        cur = db.execute(select(Finding.fingerprint, Finding.rule_id, Finding.title, Finding.triage_status).where(Finding.scan_id == last.id)).all()
        if base.id != last.id:
            old = {r[0] for r in db.execute(select(Finding.fingerprint).where(Finding.scan_id == base.id)).all()}
            now_fp = {r[0] for r in cur}
            new_total += len(now_fp - old)
            fixed_total += len(old - now_fp)
        for fp, rid, title, tri in cur:
            if tri in ("open", "confirmed"):
                rule_counts[(rid, title)] += 1
        sm = last.summary or {}
        rows.append({"name": p.name, "repo": p.repo_full_name, "team": p.repo_full_name.split("/")[0] if p.repo_full_name else "Uploaded",
                     "score": last.posture_score, "grade": sm.get("grade"),
                     "delta": round(last.posture_score - base.posture_score, 1) if base.id != last.id and None not in (last.posture_score, base.posture_score) else None,
                     "critical": (sm.get("severity_counts") or {}).get("critical", 0), "high": (sm.get("severity_counts") or {}).get("high", 0),
                     "attack_paths": ins.get("attack_paths", 0), "outsider_secrets": ins.get("outsider_secrets", 0)})
    rows.sort(key=lambda r: (r["score"] is None, r["score"] or 0))
    alerts = db.execute(select(DriftAlert).where(DriftAlert.organization_id == org_id)).scalars().all()
    recent_alerts = [a for a in alerts if _aware(a.created_at) >= start]
    exs = db.execute(select(RiskException).where(RiskException.organization_id == org_id)).scalars().all()
    soon = (now + timedelta(days=30)).date().isoformat()
    names = {p.id: p.name for p in projects}
    teams: dict[str, list] = {}
    for r in rows:
        teams.setdefault(r["team"], []).append(r)
    scored = [r["score"] for r in rows if r["score"] is not None]
    return {
        "organization": org.name if org else "", "generated_at": now.isoformat(timespec="minutes"), "days": days,
        "summary": {"projects": len(projects), "assessed": len(rows), "average": round(sum(scored) / len(scored), 1) if scored else None,
                    "trend_delta": (round(trend[-1]["average"] - trend[0]["average"], 1) if trend[0]["average"] is not None and trend[-1]["average"] is not None else None),
                    "critical": sum(r["critical"] for r in rows), "high": sum(r["high"] for r in rows),
                    "attack_paths": sum(r["attack_paths"] for r in rows), "outsider_secrets": sum(r["outsider_secrets"] for r in rows),
                    "new_findings": new_total, "fixed_findings": fixed_total, "scans": sum(1 for s in scans if _aware(s.created_at) >= start)},
        "trend": trend, "riskiest": rows[:10],
        "teams": sorted(({"team": t, "projects": len(v), "average": round(sum(x["score"] for x in v if x["score"] is not None) / max(1, sum(1 for x in v if x["score"] is not None)), 1),
                          "critical": sum(x["critical"] for x in v), "attack_paths": sum(x["attack_paths"] for x in v)} for t, v in teams.items()), key=lambda t: t["average"]),
        "top_rules": [{"rule_id": k[0], "title": k[1], "open": n} for k, n in rule_counts.most_common(8)],
        "alerts": {"opened": len(recent_alerts), "acknowledged": sum(1 for a in recent_alerts if a.acknowledged_at),
                   "open_total": sum(1 for a in alerts if not a.acknowledged_at),
                   "by_severity": {s: sum(1 for a in recent_alerts if a.severity == s) for s in SEV}},
        "exceptions": {"active": sum(1 for e in exs if ex_state(e) == "active"), "pending": sum(1 for e in exs if e.status == "pending"),
                       "expiring": [{"project": names.get(e.project_id, ""), "title": e.title, "owner": e.owner, "expires_on": e.expires_on}
                                    for e in exs if ex_state(e) == "active" and e.expires_on <= soon]},
    }


def _spark(trend: list[dict]) -> str:
    pts = [(i, t["average"]) for i, t in enumerate(trend) if t["average"] is not None]
    if len(pts) < 2:
        return '<p class="muted">Not enough scans in the period for a trend.</p>'
    w, h, n = 520, 120, max(1, len(trend) - 1)
    xy = " ".join(f"{20 + i * (w - 40) / n:.1f},{h - 15 - v * (h - 30) / 100:.1f}" for i, v in pts)
    labels = "".join(f'<text x="{20 + i * (w - 40) / n:.1f}" y="{h - 2}" font-size="9" text-anchor="middle" fill="#667">{escape(trend[i]["date"][5:])}</text>' for i, _ in pts)
    vals = "".join(f'<text x="{20 + i * (w - 40) / n:.1f}" y="{h - 20 - v * (h - 30) / 100:.1f}" font-size="9" text-anchor="middle">{v}</text>' for i, v in pts)
    return (f'<svg viewBox="0 0 {w} {h}" width="100%" role="img" aria-label="Average posture score by week">'
            f'<line x1="20" x2="{w - 20}" y1="{h - 15}" y2="{h - 15}" stroke="#ccd"/><polyline fill="none" stroke="#2b3a8c" stroke-width="2.5" points="{xy}"/>{vals}{labels}</svg>')


def render(d: dict) -> str:
    s = d["summary"]
    e = escape
    sign = lambda v: "—" if v is None else (f"+{v}" if v > 0 else f"{v}")  # noqa: E731
    cards = [("Average posture", s["average"] if s["average"] is not None else "—", f"{sign(s['trend_delta'])} over {d['days']} days"),
             ("Critical / high", f"{s['critical']} / {s['high']}", "open findings in latest scans"),
             ("Attack paths", s["attack_paths"], "end-to-end, evidence-backed"),
             ("Secrets outsiders can reach", s["outsider_secrets"], "via privileged triggers"),
             ("Fixed vs new", f"{s['fixed_findings']} / {s['new_findings']}", f"findings in {d['days']} days"),
             ("Drift alerts", d["alerts"]["opened"], f"{d['alerts']['open_total']} still open")]
    riskiest = "".join(f"<tr><td>{e(r['name'])}<div class='muted'>{e(r['repo'])}</div></td><td><b>{'—' if r['score'] is None else round(r['score'])}</b> {e(r['grade'] or '')}</td>"
                       f"<td>{sign(r['delta'])}</td><td>{r['critical']}</td><td>{r['high']}</td><td>{r['attack_paths']}</td><td>{r['outsider_secrets']}</td></tr>" for r in d["riskiest"])
    teams = "".join(f"<tr><td>{e(t['team'])}</td><td>{t['projects']}</td><td>{t['average']}</td><td>{t['critical']}</td><td>{t['attack_paths']}</td></tr>" for t in d["teams"])
    rules = "".join(f"<li><b>{e(r['rule_id'])}</b> {e(r['title'])} <span class='muted'>({r['open']} open)</span></li>" for r in d["top_rules"])
    exp = "".join(f"<li>{e(x['project'])}: {e(x['title'])} <span class='muted'>owner {e(x['owner'])}, expires {e(x['expires_on'])}</span></li>" for x in d["exceptions"]["expiring"])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>CI/CD security - executive report</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;color:#1b1f3a;margin:28px;max-width:960px}}h1{{margin:0;font-size:24px}}h2{{font-size:15px;margin:22px 0 8px;color:#2b3a8c}}
.muted{{color:#667;font-size:12px}}.cards{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:14px}}.card{{border:1px solid #dde;border-radius:8px;padding:10px}}
.card b{{font-size:22px;display:block}}table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{border-bottom:1px solid #eef;padding:5px 6px;text-align:left;vertical-align:top}}
th{{background:#f3f4fa}}.cols{{display:grid;grid-template-columns:1fr 1fr;gap:18px}}ul{{padding-left:18px;font-size:13px}}@media print{{body{{margin:12mm}}}}</style></head><body>
<h1>CI/CD security posture - {e(d['organization'])}</h1>
<div class="muted">Last {d['days']} days · generated {e(d['generated_at'])} UTC · {s['assessed']} of {s['projects']} projects assessed · {s['scans']} scans in the period</div>
<div class="cards">{''.join(f"<div class='card'><b>{e(str(v))}</b>{e(lbl)}<div class='muted'>{e(sub)}</div></div>" for lbl, v, sub in cards)}</div>
<h2>Posture trend (average of each project's latest score)</h2>{_spark(d['trend'])}
<h2>Riskiest projects</h2><table><tr><th>Project</th><th>Score</th><th>Change</th><th>Critical</th><th>High</th><th>Attack paths</th><th>Outsider secrets</th></tr>{riskiest or '<tr><td colspan=7>No assessed projects.</td></tr>'}</table>
<div class="cols"><div><h2>By team / owner</h2><table><tr><th>Owner</th><th>Projects</th><th>Avg score</th><th>Critical</th><th>Attack paths</th></tr>{teams}</table></div>
<div><h2>Most common open weaknesses</h2><ul>{rules or '<li>None.</li>'}</ul></div></div>
<div class="cols"><div><h2>Drift alerts</h2><p style="font-size:13px">{d['alerts']['opened']} raised in the period ({', '.join(f"{v} {k}" for k, v in d['alerts']['by_severity'].items() if v) or 'none'}),
{d['alerts']['acknowledged']} acknowledged; {d['alerts']['open_total']} open in total.</p></div>
<div><h2>Risk exceptions</h2><p style="font-size:13px">{d['exceptions']['active']} active, {d['exceptions']['pending']} awaiting approval.</p>
{'<b style="font-size:13px">Expiring within 30 days:</b><ul>' + exp + '</ul>' if exp else ''}</div></div>
<p class="muted" style="margin-top:24px">Scores are computed by deterministic rules against the OWASP Top 10 CI/CD Security Risks. Accepted-risk exceptions do not change scores.</p>
</body></html>"""
