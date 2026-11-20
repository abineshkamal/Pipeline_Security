"use client";
import Link from "next/link";
import { Fragment, useEffect, useState } from "react";
import Shell, { useMe } from "@/components/Shell";
import { Empty, ErrorBox, Loading, SevBadge } from "@/components/ui";
import { api, fmtDate, pipelineHref } from "@/lib/api";
import { AllowlistPanel, ReputationPanel } from "@/components/enterprise";

interface Advisory { id: string; action: string; title: string; severity: string; bad_refs: string[]; all_tags_affected: boolean; window_start: string; window_end: string;
  references: string[]; guidance: string; source: "builtin" | "organization"; record_id: string | null }
interface Exposure { project_id: string; project: string; repo: string; source_type: string; scan_id: string; scanned_at: string; workflow: string; workflow_name: string;
  job: string; line: number | null; uses: string; advisory: string; advisory_title: string; severity: string; verdict: string; verdict_text: string;
  window_start: string; window_end: string; guidance: string }
interface Runs { window: string; total: number; runs: { id: number; created_at: string; event: string; branch: string; conclusion: string; url: string; actor: string }[]; note: string }

const EMPTY = { advisory_id: "", action: "", title: "", severity: "high", bad_refs: "", all_tags_affected: false, window_start: "", window_end: "", references: "", guidance: "" };

function Body() {
  const { role } = useMe();
  const admin = role === "admin";
  const [ex, setEx] = useState<{ exposures: Exposure[]; projects_checked: number; advisories: number } | null>(null);
  const [advs, setAdvs] = useState<Advisory[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [runs, setRuns] = useState<Record<string, Runs | "loading" | string>>({});
  const [f, setF] = useState(EMPTY);
  const load = () => {
    api.get<typeof ex>("/api/watch/exposures").then(setEx).catch((e) => setErr(e.message));
    api.get<Advisory[]>("/api/advisories").then(setAdvs).catch((e) => setErr(e.message));
  };
  useEffect(() => { load(); }, []);

  const key = (e: Exposure) => `${e.project_id}|${e.workflow}|${e.job}|${e.uses}|${e.advisory}`;
  const checkRuns = async (e: Exposure) => {
    const k = key(e);
    setRuns((r) => ({ ...r, [k]: "loading" }));
    try { const res = await api.post<Runs>("/api/watch/runs", { project_id: e.project_id, workflow: e.workflow, advisory: e.advisory }); setRuns((r) => ({ ...r, [k]: res })); }
    catch (x) { setRuns((r) => ({ ...r, [k]: (x as Error).message })); }
  };
  const add = async (ev: React.FormEvent) => {
    ev.preventDefault(); setErr(null);
    try {
      await api.post("/api/advisories", { ...f, bad_refs: f.bad_refs.split(/[\s,]+/).filter(Boolean), references: f.references.split(/\s+/).filter(Boolean) });
      setF(EMPTY); load();
    } catch (x) { setErr((x as Error).message); }
  };
  const del = async (a: Advisory) => { if (a.record_id && confirm(`Delete advisory ${a.id}?`)) { await api.del(`/api/advisories/${a.record_id}`); load(); } };
  const set = (k: keyof typeof EMPTY) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setF({ ...f, [k]: e.target.type === "checkbox" ? (e.target as HTMLInputElement).checked : e.target.value });

  return (
    <>
      <h1 className="h4 mb-1">Threat watch</h1>
      <p className="text-secondary small mb-3">Compromised GitHub Actions in your pipelines. Every project&apos;s latest inventory is checked against the advisory feed,
        so a new advisory shows its exposure immediately, without re-scanning. For GitHub projects you can list the workflow runs inside the incident window.</p>
      <ErrorBox error={err} />

      <div className="card mb-3"><div className="card-body">
        <h2 className="h6">Exposures {ex && <span className="text-secondary fw-normal small">· {ex.projects_checked} project(s) checked against {ex.advisories} advisories</span>}</h2>
        {!ex ? <Loading /> : !ex.exposures.length ? <Empty>No pipeline uses an action from the advisory feed.</Empty> : (
          <div className="table-responsive"><table className="table table-sm mb-0 align-middle">
            <thead><tr><th>Severity</th><th>Project / pipeline</th><th>Action reference</th><th>Advisory</th><th>Incident window</th><th /></tr></thead>
            <tbody>{ex.exposures.map((e) => {
              const k = key(e), r = runs[k];
              return (
                <Fragment key={k}>
                  <tr>
                    <td><SevBadge s={e.severity} /></td>
                    <td><Link href={`/project?id=${e.project_id}`}>{e.project}</Link> / <Link href={pipelineHref(e.scan_id, e.workflow)}>{e.workflow_name}</Link>
                      {e.job && <> / <code>{e.job}</code></>}{e.line ? <span className="text-secondary small"> line {e.line}</span> : null}</td>
                    <td><code className="text-break-all">{e.uses}</code><div className="small text-secondary">{e.verdict_text}</div></td>
                    <td className="small"><b>{e.advisory}</b><div>{e.advisory_title}</div></td>
                    <td className="small text-nowrap">{e.window_start ? `${e.window_start} → ${e.window_end || e.window_start}` : "—"}</td>
                    <td>{e.source_type === "github" && e.window_start && <button className="btn btn-sm btn-outline-primary text-nowrap" onClick={() => checkRuns(e)} disabled={r === "loading"}>
                      {r === "loading" ? "Checking…" : "Runs in window"}</button>}</td>
                  </tr>
                  {r && r !== "loading" && <tr><td colSpan={6} className="bg-body-tertiary small">
                    {typeof r === "string" ? <span className="text-danger">{r}</span> : <>
                      <b>{r.total}</b> run(s) between {r.window}. {r.note}
                      {r.runs.length > 0 && <ul className="mb-0">{r.runs.map((x) => <li key={x.id}><a href={x.url} target="_blank" rel="noreferrer">{fmtDate(x.created_at)}</a> · {x.event} · {x.branch} · {x.conclusion || "in progress"} · {x.actor}</li>)}</ul>}
                    </>}
                    {e.guidance && <div className="mt-1"><b>Guidance:</b> {e.guidance}</div>}
                  </td></tr>}
                </Fragment>
              );
            })}</tbody>
          </table></div>
        )}
      </div></div>

      <div className="row g-3">
        <div className="col-12 col-xl-7"><div className="card h-100"><div className="card-body">
          <h2 className="h6">Advisory feed</h2>
          {!advs ? <Loading /> : <div className="table-responsive"><table className="table table-sm small mb-0 align-middle">
            <thead><tr><th>Advisory</th><th>Action</th><th>Bad refs</th><th>Window</th><th>Source</th><th /></tr></thead>
            <tbody>{advs.map((a) => (
              <tr key={`${a.source}:${a.id}`}>
                <td><SevBadge s={a.severity} /> <b>{a.id}</b><div>{a.title}</div>{a.references.map((u) => <div key={u}><a href={u} target="_blank" rel="noreferrer" className="text-break-all">{u}</a></div>)}</td>
                <td><code>{a.action}</code></td>
                <td className="text-break-all">{a.all_tags_affected ? <b>all tags</b> : null}{a.bad_refs.map((b) => <div key={b}><code>{b.length > 20 ? `${b.slice(0, 12)}…` : b}</code></div>)}</td>
                <td className="text-nowrap">{a.window_start ? `${a.window_start} → ${a.window_end || a.window_start}` : "—"}</td>
                <td>{a.source === "builtin" ? "Built-in" : "Your organization"}</td>
                <td>{admin && a.source === "organization" && <button className="btn btn-sm btn-link text-danger" onClick={() => del(a)}>Delete</button>}</td>
              </tr>
            ))}</tbody>
          </table></div>}
        </div></div></div>
        <div className="col-12 col-xl-5"><div className="card h-100"><div className="card-body">
          <h2 className="h6">Add an advisory</h2>
          {!admin ? <div className="small text-secondary">Only admins can add advisories.</div> : (
            <form onSubmit={add} className="row g-2 small">
              <div className="col-6"><label className="form-label" htmlFor="aid">Advisory ID</label><input id="aid" className="form-control form-control-sm" required placeholder="GHSA-… / CVE-… / INT-…" value={f.advisory_id} onChange={set("advisory_id")} /></div>
              <div className="col-6"><label className="form-label" htmlFor="act">Action (owner/repo)</label><input id="act" className="form-control form-control-sm" required placeholder="owner/action" value={f.action} onChange={set("action")} /></div>
              <div className="col-12"><label className="form-label" htmlFor="tit">Title</label><input id="tit" className="form-control form-control-sm" required value={f.title} onChange={set("title")} /></div>
              <div className="col-6"><label className="form-label" htmlFor="sev">Severity</label><select id="sev" className="form-select form-select-sm" value={f.severity} onChange={set("severity")}>
                {["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}</select></div>
              <div className="col-6 d-flex align-items-end"><div className="form-check"><input id="all" type="checkbox" className="form-check-input" checked={f.all_tags_affected} onChange={set("all_tags_affected")} />
                <label htmlFor="all" className="form-check-label">All tags affected</label></div></div>
              <div className="col-12"><label className="form-label" htmlFor="br">Malicious refs (tags, branches or SHAs)</label><input id="br" className="form-control form-control-sm" placeholder="v1, 0e58ed86…" value={f.bad_refs} onChange={set("bad_refs")} /></div>
              <div className="col-6"><label className="form-label" htmlFor="ws">Window start</label><input id="ws" type="date" className="form-control form-control-sm" value={f.window_start} onChange={set("window_start")} /></div>
              <div className="col-6"><label className="form-label" htmlFor="we">Window end</label><input id="we" type="date" className="form-control form-control-sm" value={f.window_end} onChange={set("window_end")} /></div>
              <div className="col-12"><label className="form-label" htmlFor="ref">References (URLs)</label><input id="ref" className="form-control form-control-sm" value={f.references} onChange={set("references")} /></div>
              <div className="col-12"><label className="form-label" htmlFor="gd">Guidance</label><input id="gd" className="form-control form-control-sm" value={f.guidance} onChange={set("guidance")} /></div>
              <div className="col-12"><button className="btn btn-sm btn-primary">Add advisory</button></div>
            </form>
          )}
        </div></div></div>
      </div>
    </>
  );
}

const TABS = ["Compromised actions", "Action reputation", "Allowlist"] as const;

function Tabs() {
  const [tab, setTab] = useState<(typeof TABS)[number]>("Compromised actions");
  return (
    <>
      <ul className="nav nav-tabs mb-3">{TABS.map((t) => <li className="nav-item" key={t}><button className={`nav-link ${tab === t ? "active" : ""}`} onClick={() => setTab(t)}>{t}</button></li>)}</ul>
      {tab === "Compromised actions" && <Body />}
      {tab === "Action reputation" && <><h1 className="h4 mb-1">Action reputation</h1>
        <p className="text-secondary small mb-3">Every third-party action used across your projects, scored on publisher verification, maintenance, age, popularity and the advisory feed.</p><ReputationPanel /></>}
      {tab === "Allowlist" && <><h1 className="h4 mb-1">Allowed-actions policy</h1><AllowlistPanel /></>}
    </>
  );
}

export default function Page() { return <Shell><Tabs /></Shell>; }
