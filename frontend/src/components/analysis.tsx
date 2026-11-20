"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { canEdit, useMe } from "@/components/Shell";
import { Empty, ErrorBox, Loading, SevBadge } from "@/components/ui";
import { api, fmtDate, pipelineHref, type Finding, type PathStory, type RuntimeEvidence, type Runners, type TicketIntegration, type TicketLink } from "@/lib/api";

const STEP_ICON: Record<string, string> = { actor: "👤", trigger: "⚡", job: "⚙", capability: "🔑", impact: "💥" };

/** Step-by-step attacker walkthrough for one attack path, with the fixes that break it. */
export function PathStoryPanel({ scanId, pathId, goFinding }: { scanId: string; pathId: string; goFinding: (id: string) => void }) {
  const [d, setD] = useState<PathStory | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => { setD(null); setErr(null); api.get<PathStory>(`/api/scans/${scanId}/attack-paths/${pathId}/story`).then(setD).catch((e) => setErr(e.message)); }, [scanId, pathId]);
  if (err) return <ErrorBox error={err} />;
  if (!d) return <Loading label="Building walkthrough…" />;
  return (
    <div className="card mt-2"><div className="card-body">
      <h3 className="h6 mb-1">How an attacker uses {d.path.id} <span className="text-secondary fw-normal small">· risk {d.path.risk} · {d.path.impact}</span></h3>
      <ol className="list-unstyled mb-3">{d.steps.map((s) => (
        <li key={s.step} className="d-flex gap-2 mb-2">
          <span className="story-step" aria-hidden>{STEP_ICON[s.type] || "•"}</span>
          <div className="small"><b>Step {s.step}.</b> {s.action.charAt(0).toUpperCase() + s.action.slice(1)}.
            {s.evidence.length > 0 && <div className="mt-1">Evidence: {s.evidence.map((f) => (
              <button key={f.id} className="btn btn-link btn-sm p-0 me-2 align-baseline" onClick={() => goFinding(f.id)}>
                <SevBadge s={f.severity} /> {f.rule_id} {f.file_path ? `${f.file_path.split("/").pop()}${f.line ? `:${f.line}` : ""}` : ""}</button>))}</div>}
            {s.defence && <div className="text-success mt-1">Defence here: {s.defence}</div>}
          </div>
        </li>))}</ol>
      <h4 className="h6">Break the chain</h4>
      <p className="small text-secondary mb-1">{d.note} Verified with the what-if simulator.</p>
      {d.breakers.length > 0 && <div className="table-responsive"><table className="table table-sm small mb-1 align-middle">
        <thead><tr><th>Fix this finding</th><th>Paths removed</th><th>Score gain</th><th /></tr></thead>
        <tbody>{d.breakers.map((b) => <tr key={b.id}>
          <td><SevBadge s={b.severity} /> <button className="btn btn-link btn-sm p-0" onClick={() => goFinding(b.id)}>{b.rule_id} {b.title}</button>
            <div className="text-secondary">{b.file_path}{b.line ? `:${b.line}` : ""}{b.job ? ` · job ${b.job}` : ""}</div></td>
          <td>{b.paths_removed}</td><td>{b.score_gain != null ? `+${b.score_gain}` : "—"}</td>
          <td>{b.auto_fixable && <span className="badge bg-success">auto-fix available</span>}</td></tr>)}</tbody>
      </table></div>}
      {d.step_fixes.length > 0 && <ul className="small mb-1">{d.step_fixes.map((x) => (
        <li key={x.step}>Fix all {x.findings} finding(s) behind step {x.step} ({x.rule_ids.join(", ")}): removes {x.paths_removed} path(s)
          {x.score_gain != null ? `, +${x.score_gain} points` : ""}{x.auto_fixable && <span className="badge bg-success ms-1">auto-fix available</span>}
          {" "}<button className="btn btn-link btn-sm p-0 align-baseline" onClick={() => goFinding(x.finding_ids[0])}>view</button></li>))}</ul>}
      <div className="small">Fixing all {d.fix_all.finding_ids.length} findings on this path removes {d.fix_all.paths_removed} path(s){d.fix_all.score_gain != null ? ` and gains ${d.fix_all.score_gain} points` : ""}.</div>
    </div></div>
  );
}

const FLAG_TEXT: Record<string, [string, string]> = {
  observed_untrusted_trigger: ["bg-danger", "Ran on untrusted input"],
  dormant_with_secrets: ["bg-warning text-dark", "Dormant, holds secrets"],
  no_runs_in_window: ["bg-secondary", "No runs in window"],
};

/** Run history evidence and self-hosted runner inventory (GitHub projects). */
export function RuntimePanel({ scanId, pipeline }: { scanId: string; pipeline?: string }) {
  const [rt, setRt] = useState<RuntimeEvidence | null>(null);
  const [rn, setRn] = useState<Runners | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const load = (refresh = false) => {
    setErr(null); setRt(null); setRn(null);
    const q = refresh ? "?refresh=true" : "";
    api.get<RuntimeEvidence>(`/api/scans/${scanId}/runtime${q}`).then(setRt).catch((e) => setErr(e.message));
    api.get<Runners>(`/api/scans/${scanId}/runners${q}`).then(setRn).catch((e) => setErr(e.message));
  };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { load(); }, [scanId]);
  if (err) return <ErrorBox error={err} />;
  const wfs = (rt?.workflows || []).filter((w) => !pipeline || w.workflow === pipeline);
  const jobs = (rn?.self_hosted_jobs || []).filter((j) => !pipeline || j.workflow === pipeline);
  return (
    <>
      <div className="d-flex align-items-center gap-2 mb-2">
        <p className="small text-secondary mb-0 me-auto">What actually ran, from the repository&apos;s GitHub Actions run history (latest {rt?.runs_analysed ?? "…"} runs
          {rt?.window?.from ? `, since ${fmtDate(rt.window.from)}` : ""}). Cached for 15 minutes.</p>
        <button className="btn btn-sm btn-outline-secondary" onClick={() => load(true)}>Refresh</button>
      </div>
      {!rt ? <Loading label="Reading run history…" /> : rt.status === "error" ? <div className="alert alert-warning small">Run history unavailable: {rt.detail}</div> : <>
        {rt.observed.filter((o) => !pipeline || o.workflow === pipeline).map((o) => <div key={o.workflow} className="alert alert-danger small py-2"><b>Observed in practice:</b> {o.text}</div>)}
        <div className="card mb-3"><div className="table-responsive"><table className="table table-sm small mb-0 align-middle">
          <thead><tr><th>Pipeline</th><th>Runs</th><th>Events</th><th>From forks</th><th>Privileged runs by outsiders</th><th>Last run</th><th>Failure rate</th><th>Signals</th></tr></thead>
          <tbody>{wfs.map((w) => <tr key={w.workflow}>
            <td>{pipeline ? w.name : <Link href={pipelineHref(scanId, w.workflow)}>{w.name}</Link>}</td><td>{w.runs}</td>
            <td>{Object.entries(w.events).map(([k, v]) => <span key={k} className="badge bg-secondary me-1">{k} {v}</span>)}</td>
            <td>{w.fork_runs || "—"}</td>
            <td>{w.outsider_privileged_runs > 0 ? <b className="text-danger">{w.outsider_privileged_runs}</b> : "—"}
              {w.examples.slice(0, 2).map((x) => <div key={x.url}><a href={x.url} target="_blank" rel="noreferrer">{x.event} by {x.actor}{x.head ? ` from ${x.head}` : ""}</a></div>)}</td>
            <td className="text-nowrap">{w.last_run ? `${w.days_since_last_run} day(s) ago` : "never"}</td>
            <td>{w.failure_rate != null ? `${Math.round(w.failure_rate * 100)}%` : "—"}</td>
            <td>{w.flags.map((f) => <span key={f} className={`badge me-1 ${FLAG_TEXT[f]?.[0] || "bg-secondary"}`}>{FLAG_TEXT[f]?.[1] || f}</span>)}</td>
          </tr>)}</tbody>
        </table></div></div>
      </>}
      <h3 className="h6">Self-hosted runners</h3>
      {!rn ? <Loading /> : <>
        {rn.note && <div className="small text-secondary mb-2">{rn.note}</div>}
        {rn.risks.map((r, i) => <div key={i} className="small mb-1"><SevBadge s={r.severity} /> {r.text}</div>)}
        {!jobs.length && !rn.runners.length ? <Empty>No job targets self-hosted runners{pipeline ? " in this pipeline" : ""}.</Empty> : <div className="row g-3 mt-1">
          {jobs.length > 0 && <div className="col-12 col-xl-6"><div className="card h-100"><div className="card-body">
            <h4 className="h6">Jobs on self-hosted labels</h4>
            <table className="table table-sm small mb-0"><thead><tr><th>Pipeline / job</th><th>Labels</th><th>Fork-reachable</th><th>Matching runners</th></tr></thead>
              <tbody>{jobs.map((j) => <tr key={j.workflow + j.job}><td>{j.workflow_name} / <code>{j.job}</code></td><td>{j.labels.join(", ")}</td>
                <td>{j.fork_reachable ? <span className="badge bg-danger">yes</span> : "no"}</td><td>{j.matching_runners.join(", ") || <span className="text-secondary">unknown</span>}</td></tr>)}</tbody></table>
          </div></div></div>}
          {rn.runners.length > 0 && <div className="col-12 col-xl-6"><div className="card h-100"><div className="card-body">
            <h4 className="h6">Registered runners</h4>
            <table className="table table-sm small mb-0"><thead><tr><th>Runner</th><th>Scope</th><th>Status</th><th>Labels</th><th>Ephemeral</th></tr></thead>
              <tbody>{rn.runners.map((r) => <tr key={r.scope + r.name}><td>{r.name}</td><td>{r.scope}</td><td>{r.status}{r.busy ? " (busy)" : ""}</td>
                <td>{r.labels.join(", ")}</td><td>{r.ephemeral == null ? "—" : r.ephemeral ? "yes" : <span className="text-danger">no</span>}</td></tr>)}</tbody></table>
          </div></div></div>}
        </div>}
      </>}
    </>
  );
}

/** Open a Jira / ServiceNow ticket for a finding, or show the existing one. */
export function TicketButton({ f }: { f: Finding }) {
  const { role } = useMe();
  const [ints, setInts] = useState<TicketIntegration[] | null>(null);
  const [sel, setSel] = useState("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string; url?: string } | null>(null);
  useEffect(() => { setMsg(null); api.get<TicketIntegration[]>("/api/integrations/tickets").then((x) => { setInts(x); setSel(x.find((i) => i.enabled)?.id || ""); }).catch(() => setInts([])); }, [f.id]);
  const t = f.extra?.ticket;
  if (t) return <div className="small mt-2">Ticket: <a href={t.url} target="_blank" rel="noreferrer">{t.key}</a> ({t.system}, {t.status}) - closed automatically when a scan no longer finds this.</div>;
  if (!canEdit(role) || !ints?.length) return null;
  const open = async () => {
    try {
      const r = await api.post<{ created: TicketLink[]; skipped: { key: string; url: string }[]; errors: { detail: string }[] }>("/api/tickets", { integration_id: sel, finding_ids: [f.id] });
      const c = r.created[0] || r.skipped[0];
      setMsg(c ? { ok: true, text: r.created.length ? `Created ${c.key}` : `Already tracked in ${c.key}`, url: c.url } : { ok: false, text: r.errors[0]?.detail || "failed" });
    } catch (x) { setMsg({ ok: false, text: (x as Error).message }); }
  };
  return (
    <div className="d-flex flex-wrap align-items-center gap-2 mt-2 small">
      <select className="form-select form-select-sm w-auto" aria-label="Ticket system" value={sel} onChange={(e) => setSel(e.target.value)}>
        {ints.filter((i) => i.enabled).map((i) => <option key={i.id} value={i.id}>{i.name} ({i.kind === "jira" ? `Jira ${i.target}` : `ServiceNow ${i.target}`})</option>)}</select>
      <button className="btn btn-sm btn-outline-primary" onClick={open} disabled={!sel}>Create ticket</button>
      {msg && <span className={msg.ok ? "text-success" : "text-danger"}>{msg.text}{msg.url && <> · <a href={msg.url} target="_blank" rel="noreferrer">open</a></>}</span>}
    </div>
  );
}
