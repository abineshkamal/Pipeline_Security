"use client";
import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import Shell, { canEdit, useMe } from "@/components/Shell";
import { Empty, ErrorBox, Loading, ScoreRing, StatusBadge } from "@/components/ui";
import { api, fmtDate, openHtml, type Portfolio, type PortfolioRow } from "@/lib/api";

interface Cred { id: string; name: string; hint: string }
interface ImportResult { owner: string; found: number; eligible: number; skipped_filtered: number; skipped_existing: number;
  created: { id: string; name: string; repo: string }[]; scans_queued: number; more_available: boolean; warning: string }

function ImportCard({ onDone }: { onDone: () => void }) {
  const [creds, setCreds] = useState<Cred[]>([]);
  const [f, setF] = useState({ owner: "", credential_id: "", include_archived: false, include_forks: false, max_repos: 50, scan_now: true, schedule: "weekly" });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [res, setRes] = useState<ImportResult | null>(null);
  useEffect(() => { api.get<Cred[]>("/api/credentials").then(setCreds).catch(() => setCreds([])); }, []);
  const run = async (e: React.FormEvent) => {
    e.preventDefault(); setBusy(true); setErr(null); setRes(null);
    try {
      const r = await api.post<ImportResult>("/api/portfolio/import", { ...f, credential_id: f.credential_id || null, max_repos: Number(f.max_repos) });
      setRes(r); onDone();
    } catch (x) { setErr((x as Error).message); } finally { setBusy(false); }
  };
  return (
    <div className="card mb-3"><div className="card-body">
      <h2 className="h6">Import a GitHub organization</h2>
      <p className="small text-secondary mb-2">Creates a project for every repository of the organization (or user) that is not tracked yet, optionally scans them now and
        puts them on a schedule. Re-run it later to pick up new repositories.</p>
      <form onSubmit={run} className="row g-2 align-items-end small">
        <div className="col-12 col-md-3"><label className="form-label" htmlFor="own">Organization or user</label>
          <input id="own" className="form-control form-control-sm" required placeholder="e.g. juice-shop" value={f.owner} onChange={(e) => setF({ ...f, owner: e.target.value.trim() })} /></div>
        <div className="col-12 col-md-3"><label className="form-label" htmlFor="cr">Token</label>
          <select id="cr" className="form-select form-select-sm" value={f.credential_id} onChange={(e) => setF({ ...f, credential_id: e.target.value })}>
            <option value="">None (public repositories, 60 API calls/hour)</option>
            {creds.map((c) => <option key={c.id} value={c.id}>{c.name} ({c.hint})</option>)}</select></div>
        <div className="col-6 col-md-1"><label className="form-label" htmlFor="mx">Max new</label>
          <input id="mx" type="number" min={1} max={300} className="form-control form-control-sm" value={f.max_repos} onChange={(e) => setF({ ...f, max_repos: Number(e.target.value) })} /></div>
        <div className="col-6 col-md-2"><label className="form-label" htmlFor="sc">Schedule</label>
          <select id="sc" className="form-select form-select-sm" value={f.schedule} onChange={(e) => setF({ ...f, schedule: e.target.value })}>
            <option value="">Manual</option><option value="daily">Daily</option><option value="weekly">Weekly</option></select></div>
        <div className="col-12 col-md-3 d-flex flex-wrap gap-3">
          {([["scan_now", "Scan now"], ["include_archived", "Archived"], ["include_forks", "Forks"]] as const).map(([k, l]) => (
            <div className="form-check" key={k}><input id={k} type="checkbox" className="form-check-input" checked={f[k]} onChange={(e) => setF({ ...f, [k]: e.target.checked })} />
              <label htmlFor={k} className="form-check-label">{l}</label></div>))}
        </div>
        <div className="col-12"><button className="btn btn-sm btn-primary" disabled={busy}>{busy ? "Discovering…" : "Import repositories"}</button></div>
      </form>
      <ErrorBox error={err} />
      {res && <div className="alert alert-success small mt-2 mb-0">
        <b>{res.owner}</b>: {res.found} repositories found, {res.eligible} eligible ({res.skipped_filtered} archived/forks skipped), {res.skipped_existing} already tracked.
        {" "}<b>{res.created.length} project(s) created</b>{res.scans_queued ? `, ${res.scans_queued} scan(s) queued` : ""}.
        {res.more_available && " More repositories remain: run the import again."}
        {res.warning && <div className="text-danger mt-1">{res.warning}</div>}
      </div>}
    </div></div>
  );
}

const delta = (d: number | null) => d == null || d === 0 ? null : <span className={d > 0 ? "delta-up" : "delta-down"}>{d > 0 ? "▲" : "▼"} {Math.abs(d)}</span>;

function Body() {
  const { role } = useMe();
  const [data, setData] = useState<Portfolio | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [team, setTeam] = useState("");
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<string[]>([]);
  const [msg, setMsg] = useState<string | null>(null);
  const [days, setDays] = useState(30);
  const load = useCallback(() => { api.get<Portfolio>("/api/portfolio").then(setData).catch((e) => setErr(e.message)); }, []);
  useEffect(() => { load(); }, [load]);
  const busy = data?.projects.some((p) => p.last_status === "queued" || p.last_status === "running");
  useEffect(() => { if (!busy) return; const t = setInterval(load, 4000); return () => clearInterval(t); }, [busy, load]);

  const rows = useMemo(() => (data?.projects || []).filter((p) => (!team || p.team === team) &&
    (!q || `${p.name} ${p.repo}`.toLowerCase().includes(q.toLowerCase()))), [data, team, q]);
  const toggle = (id: string) => setSel(sel.includes(id) ? sel.filter((x) => x !== id) : [...sel, id]);
  const bulk = async (what: "scan" | "daily" | "weekly" | "") => {
    setMsg(null); setErr(null);
    try {
      if (what === "scan") {
        const r = await api.post<{ queued: number; skipped: { name: string; reason: string }[] }>("/api/portfolio/scan", { project_ids: sel });
        setMsg(`${r.queued} scan(s) queued` + (r.skipped.length ? `; skipped ${r.skipped.map((s) => `${s.name} (${s.reason})`).join(", ")}` : ""));
      } else {
        const r = await api.put<{ updated: number }>("/api/portfolio/schedule", { project_ids: sel, schedule: what });
        setMsg(`Schedule set to ${what || "manual"} on ${r.updated} GitHub project(s)`);
      }
      setSel([]); load();
    } catch (x) { setErr((x as Error).message); }
  };

  if (!data) return err ? <ErrorBox error={err} /> : <Loading />;
  const t = data.totals;
  const stats: [string, string | number, string?][] = [
    ["Projects", `${t.assessed}/${t.projects}`, "assessed"], ["Critical findings", t.critical], ["Attack paths", t.attack_paths],
    ["Secrets outsiders can reach", t.outsider_secrets], ["Stale secrets", t.stale_secrets, "not rotated in 180+ days"],
    ["Open drift alerts", t.open_alerts], ["On a schedule", t.scheduled],
  ];
  return (
    <>
      <div className="d-flex flex-wrap align-items-center gap-3 mb-3">
        <ScoreRing score={t.average_score} size={72} />
        <div><h1 className="h4 mb-0">Portfolio</h1>
          <div className="small text-secondary">Average posture across {t.assessed} assessed project(s). Riskiest first.
            {t.never_scanned ? ` ${t.never_scanned} never scanned.` : ""}{t.failed_last_scan ? ` ${t.failed_last_scan} failed their last scan.` : ""}</div></div>
        <div className="ms-auto d-flex flex-wrap gap-2 align-items-center">
          <Link className="btn btn-sm btn-outline-secondary" href="/sla">Remediation SLAs</Link>
          <Link className="btn btn-sm btn-outline-secondary" href="/campaigns">Fix campaigns</Link>
          <select className="form-select form-select-sm w-auto" aria-label="Report period" value={days} onChange={(e) => setDays(Number(e.target.value))}>
            {[30, 90, 180, 365].map((n) => <option key={n} value={n}>Last {n} days</option>)}</select>
          <button className="btn btn-sm btn-outline-primary text-nowrap" onClick={() => openHtml(`/api/reports/executive.html?days=${days}`)}>Executive report</button>
        </div>
      </div>
      <div className="row g-2 mb-3">{stats.map(([l, v, h]) => (
        <div className="col-6 col-md-3 col-xl" key={l}><div className="card h-100"><div className="card-body py-2">
          <div className="fs-4 fw-bold">{v}</div><div className="small text-secondary">{l}{h && <div className="fst-italic">{h}</div>}</div></div></div></div>))}
      </div>
      {role === "admin" && <ImportCard onDone={load} />}

      {data.teams.length > 1 && <div className="card mb-3"><div className="card-body">
        <h2 className="h6">By team / owner</h2>
        <div className="table-responsive"><table className="table table-sm small mb-0 align-middle">
          <thead><tr><th>Owner</th><th>Projects</th><th>Avg score</th><th>Worst</th><th>Critical</th><th>High</th><th>Attack paths</th><th>Outsider secrets</th><th>Open alerts</th></tr></thead>
          <tbody>{data.teams.map((x) => <tr key={x.team} className="finding-row" onClick={() => setTeam(team === x.team ? "" : x.team)}>
            <td><b>{x.team}</b>{team === x.team && <span className="badge bg-primary ms-1">filtered</span>}</td><td>{x.assessed}/{x.projects}</td>
            <td>{x.average_score ?? "—"}</td><td>{x.worst_score ?? "—"}</td><td>{x.critical}</td><td>{x.high}</td><td>{x.attack_paths}</td><td>{x.outsider_secrets}</td><td>{x.open_alerts}</td></tr>)}</tbody>
        </table></div>
      </div></div>}

      <div className="card mb-3"><div className="card-body">
        <div className="d-flex flex-wrap align-items-center gap-2 mb-2">
          <h2 className="h6 mb-0 me-auto">Leaderboard ({rows.length})</h2>
          {team && <button className="btn btn-sm btn-outline-secondary" onClick={() => setTeam("")}>Owner: {team} ✕</button>}
          <input className="form-control form-control-sm w-auto" placeholder="Filter projects" aria-label="Filter projects" value={q} onChange={(e) => setQ(e.target.value)} />
          {canEdit(role) && sel.length > 0 && <>
            <button className="btn btn-sm btn-primary" onClick={() => bulk("scan")}>Scan {sel.length}</button>
            <select className="form-select form-select-sm w-auto" aria-label="Set schedule" value="x" onChange={(e) => bulk(e.target.value as "daily")}>
              <option value="x" disabled>Set schedule…</option><option value="daily">Daily</option><option value="weekly">Weekly</option><option value="">Manual</option></select>
          </>}
        </div>
        {msg && <div className="alert alert-info py-1 small">{msg}</div>}
        <ErrorBox error={err} />
        {!rows.length ? <Empty>No projects yet. Import a GitHub organization or create a project.</Empty> : (
          <div className="table-responsive"><table className="table table-sm table-hover mb-0 align-middle small">
            <thead><tr>
              {canEdit(role) && <th><input type="checkbox" className="form-check-input" aria-label="Select all"
                checked={sel.length === rows.length} onChange={(e) => setSel(e.target.checked ? rows.map((r) => r.project_id) : [])} /></th>}
              <th>#</th><th>Project</th><th>Score</th><th>Critical / high</th><th>Attack paths</th><th>Secrets</th><th>Exceptions</th><th>Alerts</th><th>Last scan</th><th>Schedule</th>
            </tr></thead>
            <tbody>{rows.map((r: PortfolioRow) => (
              <tr key={r.project_id}>
                {canEdit(role) && <td><input type="checkbox" className="form-check-input" aria-label={`Select ${r.name}`} checked={sel.includes(r.project_id)} onChange={() => toggle(r.project_id)} /></td>}
                <td className="text-secondary">{r.rank}</td>
                <td><Link href={`/project?id=${r.project_id}`} className="fw-semibold">{r.name}</Link><div className="text-secondary">{r.repo || "ZIP upload"}{r.workflows ? ` · ${r.workflows} pipeline(s)` : ""}</div></td>
                <td className="text-nowrap">{r.posture_score == null ? <span className="text-secondary">—</span> : <><b>{Math.round(r.posture_score)}</b> <span className="text-secondary">{r.grade}</span> {delta(r.score_delta)}</>}</td>
                <td>{r.scan_id ? <><span className="badge sev-critical">{r.severity_counts.critical || 0}</span> <span className="badge sev-high">{r.severity_counts.high || 0}</span></> : "—"}</td>
                <td>{r.scan_id ? <Link href={`/scan?id=${r.scan_id}`}>{r.attack_paths}</Link> : "—"}</td>
                <td>{r.outsider_secrets > 0 && <span className="badge bg-danger me-1" title="reachable by outsiders">{r.outsider_secrets} exposed</span>}
                  {r.stale_secrets > 0 && <span className="badge bg-warning text-dark" title="not rotated in 180+ days">{r.stale_secrets} stale</span>}
                  {!r.outsider_secrets && !r.stale_secrets && <span className="text-secondary">—</span>}</td>
                <td>{r.exceptions_active || r.exceptions_pending ? <Link href="/exceptions">{r.exceptions_active} active{r.exceptions_pending ? `, ${r.exceptions_pending} pending` : ""}</Link> : <span className="text-secondary">—</span>}</td>
                <td>{r.open_alerts ? <Link href="/alerts" className="badge bg-danger">{r.open_alerts}</Link> : <span className="text-secondary">—</span>}</td>
                <td className="text-nowrap">{r.last_status ? <StatusBadge s={r.last_status} /> : null} <span className="text-secondary">{r.scanned_at ? fmtDate(r.scanned_at) : "never"}</span>
                  {r.last_error && <div className="text-danger text-truncate" style={{ maxWidth: 220 }} title={r.last_error}>{r.last_error}</div>}</td>
                <td className="text-nowrap">{r.schedule ? <span title={`next ${fmtDate(r.next_scan_at)}`}>{r.schedule}</span> : <span className="text-secondary">manual</span>}</td>
              </tr>))}</tbody>
          </table></div>)}
      </div></div>
    </>
  );
}

export default function Page() { return <Shell><Body /></Shell>; }
