"use client";
import Link from "next/link";
import { Fragment, useEffect, useState } from "react";
import { canEdit, useMe } from "@/components/Shell";
import { Empty, ErrorBox, Loading } from "@/components/ui";
import { api, fmtDate, pipelineHref } from "@/lib/api";

/* ------------------------------------------------------------ least-privilege permissions */

interface PermJob { workflow: string; job: string; name: string; explicit: boolean; current_write_scopes: string[] | null; recommended: Record<string, string> | null;
  reasons: string[]; review: string[]; confidence: string; reusable: boolean; excess_write_scopes: string[] | null; yaml: string }

export function LeastPrivilegePanel({ scanId, pipeline }: { scanId: string; pipeline?: string }) {
  const [d, setD] = useState<{ jobs: PermJob[]; counts: Record<string, number> } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => { api.get<typeof d>(`/api/scans/${scanId}/permissions${pipeline ? `?pipeline=${encodeURIComponent(pipeline)}` : ""}`).then(setD).catch((e) => setErr(e.message)); }, [scanId, pipeline]);
  if (err) return <div className="small text-secondary">{err}</div>;
  if (!d) return <Loading />;
  const conf: Record<string, string> = { high: "bg-success", medium: "bg-warning text-dark", low: "bg-secondary" };
  return (
    <div className="card mb-3"><div className="card-body">
      <h2 className="h6 mb-1">Least-privilege GITHUB_TOKEN permissions</h2>
      <p className="small text-secondary">Inferred from what each job&apos;s steps do (known actions and <code>gh</code> / <code>git</code> commands). The automatic fix for
        missing permissions uses these blocks; items under &quot;check&quot; could not be inferred and need a human look.</p>
      <div className="table-responsive"><table className="table table-sm small align-middle mb-0">
        <thead><tr><th>Job</th><th>Today</th><th>Recommended</th><th>Why</th><th>Confidence</th></tr></thead>
        <tbody>{d.jobs.map((j) => (
          <tr key={j.workflow + j.job}>
            <td>{pipeline ? <code>{j.job}</code> : <><Link href={pipelineHref(scanId, j.workflow)}>{j.workflow.split("/").pop()}</Link> / <code>{j.job}</code></>}</td>
            <td>{!j.explicit && j.current_write_scopes == null ? <span className="text-danger">repository default</span> :
              j.current_write_scopes?.length ? <>write: {j.current_write_scopes.join(", ")}</> : "read-only"}
              {j.excess_write_scopes && j.excess_write_scopes.length > 0 && <div className="text-danger">not needed: {j.excess_write_scopes.join(", ")}</div>}</td>
            <td>{j.reusable ? <span className="text-secondary">set in the called workflow</span> : <pre className="snippet mb-0 small">{j.yaml}</pre>}</td>
            <td>{j.reasons.map((r, i) => <div key={i}>{r}</div>)}{j.review.map((r, i) => <div key={i} className="text-warning-emphasis">check: {r}</div>)}
              {!j.reasons.length && !j.review.length && <span className="text-secondary">no token use found</span>}</td>
            <td><span className={`badge ${conf[j.confidence]}`}>{j.confidence}</span></td>
          </tr>))}</tbody>
      </table></div>
    </div></div>
  );
}

/* ------------------------------------------------------------ action reputation + allowlist */

interface RepRow { slug: string; first_party: boolean; projects: string[]; uses: string[]; refs: string[]; pinned: number; unpinned: number; score: number; tier: string;
  reasons: string[]; meta: { stars?: number; archived?: boolean; pushed_at?: string; owner_type?: string; verified_owner?: boolean | null; status?: string } }
const TIER_CLS: Record<string, string> = { trusted: "bg-success", acceptable: "bg-primary", review: "bg-warning text-dark", risky: "bg-danger", blocked: "bg-dark" };

export function ReputationPanel() {
  const [d, setD] = useState<{ actions: RepRow[]; fetched: number; pending: number; counts: Record<string, number> } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const load = (refresh = false) => { setD(null); api.get<typeof d>(`/api/actions/reputation${refresh ? "?refresh=true" : ""}`).then(setD).catch((e) => setErr(e.message)); };
  useEffect(() => { load(); }, []);
  if (err) return <ErrorBox error={err} />;
  if (!d) return <Loading label="Scoring actions…" />;
  const rows = d.actions.filter((a) => !q || a.slug.includes(q.toLowerCase()));
  return (
    <>
      <div className="d-flex flex-wrap align-items-center gap-2 mb-2">
        {Object.entries(d.counts).filter(([, n]) => n).map(([t, n]) => <span key={t} className={`badge ${TIER_CLS[t]}`}>{n} {t}</span>)}
        <span className="small text-secondary me-auto">{d.actions.length} actions across all projects. Repository data is cached for 24 h{d.pending ? `; ${d.pending} still to fetch (API budget) - reload later` : ""}.</span>
        <input className="form-control form-control-sm w-auto" placeholder="Filter" aria-label="Filter actions" value={q} onChange={(e) => setQ(e.target.value)} />
        <button className="btn btn-sm btn-outline-secondary" onClick={() => load(true)}>Refresh</button>
      </div>
      <div className="card"><div className="table-responsive"><table className="table table-sm small align-middle mb-0">
        <thead><tr><th>Action</th><th>Score</th><th>Signals</th><th>Used by</th><th>Pinned</th></tr></thead>
        <tbody>{rows.map((a) => <tr key={a.slug}>
          <td><code>{a.slug}</code><div className="text-secondary">{a.refs.filter(Boolean).slice(0, 3).map((r) => r.length > 12 ? r.slice(0, 10) + "…" : r).join(", ")}</div></td>
          <td className="text-nowrap"><span className={`badge ${TIER_CLS[a.tier]}`}>{a.tier}</span> {a.score}</td>
          <td>{a.reasons.join(" · ") || "—"}</td>
          <td>{a.projects.slice(0, 4).join(", ")}{a.projects.length > 4 ? ` +${a.projects.length - 4}` : ""}</td>
          <td className={a.unpinned ? "text-danger" : ""}>{a.pinned}/{a.pinned + a.unpinned}</td></tr>)}</tbody>
      </table></div></div>
    </>
  );
}

export function AllowlistPanel() {
  const [f, setF] = useState({ min_tier: "acceptable", sha_only: false, verified_allowed: false });
  const [d, setD] = useState<{ policy: { github_owned_allowed: boolean; verified_allowed: boolean; patterns_allowed: string[] }; excluded: { action: string; tier: string; reason: string }[];
    apply: Record<string, string>; note: string; pending_metadata: number } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => { setD(null); api.post<typeof d>("/api/actions/allowlist", f).then(setD).catch((e) => setErr(e.message)); }, [f]);
  const json = d ? JSON.stringify(d.policy, null, 2) : "";
  return (
    <>
      <p className="small text-secondary">GitHub&apos;s &quot;Allow select actions&quot; setting blocks every action that is not listed. This builds that list from the actions you actually use,
        leaving out the ones below your chosen reputation level.</p>
      <div className="d-flex flex-wrap gap-3 align-items-center mb-2 small">
        <label className="d-flex align-items-center gap-1">Minimum level <select className="form-select form-select-sm w-auto" value={f.min_tier} onChange={(e) => setF({ ...f, min_tier: e.target.value })}>
          {["trusted", "acceptable", "review", "risky"].map((t) => <option key={t}>{t}</option>)}</select></label>
        <div className="form-check"><input id="sha" type="checkbox" className="form-check-input" checked={f.sha_only} onChange={(e) => setF({ ...f, sha_only: e.target.checked })} />
          <label htmlFor="sha" className="form-check-label">Only the exact commit SHAs in use</label></div>
        <div className="form-check"><input id="ver" type="checkbox" className="form-check-input" checked={f.verified_allowed} onChange={(e) => setF({ ...f, verified_allowed: e.target.checked })} />
          <label htmlFor="ver" className="form-check-label">Also allow Marketplace verified creators</label></div>
      </div>
      <ErrorBox error={err} />
      {!d ? <Loading /> : <div className="row g-3">
        <div className="col-12 col-xl-6"><div className="card h-100"><div className="card-body">
          <div className="d-flex align-items-center mb-1"><h3 className="h6 mb-0 me-auto">policy.json ({d.policy.patterns_allowed.length} patterns)</h3>
            <button className="btn btn-sm btn-outline-primary" onClick={() => navigator.clipboard?.writeText(json)}>Copy</button></div>
          <pre className="snippet small" style={{ maxHeight: 360 }}>{json}</pre>
          <div className="small"><b>Apply to the organization:</b><pre className="snippet small mb-1">{d.apply.organization}</pre>
            <b>or to one repository:</b><pre className="snippet small mb-0">{d.apply.repository}</pre></div>
        </div></div></div>
        <div className="col-12 col-xl-6"><div className="card h-100"><div className="card-body">
          <h3 className="h6">Left out ({d.excluded.length})</h3>
          <p className="small text-danger">{d.note}</p>
          {!d.excluded.length ? <div className="small text-secondary">Nothing excluded.</div> : <ul className="small mb-0">{d.excluded.map((x) =>
            <li key={x.action}><code>{x.action}</code> <span className={`badge ${TIER_CLS[x.tier]}`}>{x.tier}</span> {x.reason}</li>)}</ul>}
          {d.pending_metadata > 0 && <div className="small text-secondary mt-2">{d.pending_metadata} action(s) have no reputation data yet and count as &quot;review&quot;.</div>}
        </div></div></div>
      </div>}
    </>
  );
}

/* ------------------------------------------------------------ API tokens + SIEM (settings) */

interface Tok { id: string; name: string; role: string; prefix: string; created_by: string; created_at: string; expires_at: string | null; last_used_at: string | null; revoked: boolean }

export function ApiTokens() {
  const { role } = useMe();
  const [list, setList] = useState<Tok[] | null>(null);
  const [f, setF] = useState({ name: "", role: "viewer", expires_in_days: 90 });
  const [created, setCreated] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const load = () => api.get<Tok[]>("/api/tokens").then(setList).catch((e) => setErr(e.message));
  useEffect(() => { if (role === "admin") load(); }, [role]);
  if (role !== "admin") return null;
  const add = async (e: React.FormEvent) => {
    e.preventDefault(); setErr(null);
    try { const r = await api.post<{ token: string }>("/api/tokens", f); setCreated(r.token); setF({ ...f, name: "" }); load(); } catch (x) { setErr((x as Error).message); }
  };
  const revoke = async (t: Tok) => { if (confirm(`Revoke ${t.name}? Anything using it stops working.`)) { await api.del(`/api/tokens/${t.id}`); load(); } };
  return (
    <div className="card mb-3"><div className="card-body">
      <h2 className="h6">API tokens</h2>
      <p className="small text-secondary">For scripts and CI: send <code>Authorization: Bearer pt_…</code>. A token acts for you, never with more rights than you have,
        is bound to this organization, and cannot create other tokens. Only a hash is stored.</p>
      <ErrorBox error={err} />
      {created && <div className="alert alert-success small">New token - copy it now, it is not shown again:<pre className="snippet mb-1 mt-1">{created}</pre>
        <button className="btn btn-sm btn-outline-success" onClick={() => { navigator.clipboard?.writeText(created); }}>Copy</button>
        <button className="btn btn-sm btn-link" onClick={() => setCreated(null)}>Done</button></div>}
      {list && list.length > 0 && <table className="table table-sm small align-middle">
        <thead><tr><th>Name</th><th>Role</th><th>Key</th><th>Created</th><th>Expires</th><th>Last used</th><th /></tr></thead>
        <tbody>{list.map((t) => <tr key={t.id} className={t.revoked ? "text-secondary" : ""}><td>{t.name}</td><td>{t.role}</td><td><code>{t.prefix}…</code></td>
          <td>{fmtDate(t.created_at)} · {t.created_by}</td><td>{t.expires_at ? fmtDate(t.expires_at) : "never"}</td><td>{fmtDate(t.last_used_at)}</td>
          <td>{t.revoked ? "revoked" : <button className="btn btn-sm btn-link text-danger" onClick={() => revoke(t)}>Revoke</button>}</td></tr>)}</tbody></table>}
      <form onSubmit={add} className="row g-2 small align-items-end">
        <div className="col-12 col-md-4"><label className="form-label" htmlFor="tkn">Name</label><input id="tkn" className="form-control form-control-sm" required minLength={2} placeholder="e.g. jenkins-reporting" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></div>
        <div className="col-6 col-md-2"><label className="form-label" htmlFor="tkr">Role</label><select id="tkr" className="form-select form-select-sm" value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })}>
          <option value="viewer">viewer (read)</option><option value="analyst">analyst</option><option value="admin">admin</option></select></div>
        <div className="col-6 col-md-2"><label className="form-label" htmlFor="tke">Expires (days)</label><input id="tke" type="number" min={1} max={730} className="form-control form-control-sm" value={f.expires_in_days} onChange={(e) => setF({ ...f, expires_in_days: Number(e.target.value) })} /></div>
        <div className="col-12 col-md-2"><button className="btn btn-sm btn-primary">Create token</button></div>
      </form>
    </div></div>
  );
}

interface Sink { id: string; name: string; kind: string; url_hint: string; events: string[]; enabled: boolean; delivered: number; failed: number; last_error: string; has_secret: boolean }

export function SiemSinks() {
  const { role } = useMe();
  const empty = { name: "", kind: "splunk", url: "", secret: "", events: [] as string[] };
  const [list, setList] = useState<Sink[] | null>(null);
  const [f, setF] = useState(empty);
  const [err, setErr] = useState<string | null>(null);
  const [res, setRes] = useState<Record<string, string>>({});
  const load = () => api.get<Sink[]>("/api/siem/sinks").then(setList).catch((e) => setErr(e.message));
  useEffect(() => { if (role === "admin") load(); }, [role]);
  if (role !== "admin") return null;
  const add = async (e: React.FormEvent) => {
    e.preventDefault(); setErr(null);
    try { await api.post("/api/siem/sinks", f); setF(empty); load(); } catch (x) { setErr((x as Error).message); }
  };
  const test = async (s: Sink) => { const r = await api.post<{ ok: boolean; detail: string }>(`/api/siem/sinks/${s.id}/test`); setRes((x) => ({ ...x, [s.id]: `${r.ok ? "Delivered" : "Failed"} · ${r.detail}` })); };
  const del = async (s: Sink) => { if (confirm(`Remove ${s.name}?`)) { await api.del(`/api/siem/sinks/${s.id}`); load(); } };
  const ph: Record<string, [string, string]> = { splunk: ["https://splunk.example.com:8088/services/collector/event", "HEC token"],
    datadog: ["https://http-intake.logs.datadoghq.com/api/v2/logs", "Datadog API key"], webhook: ["https://siem.example.com/ingest", "HMAC signing secret (optional)"] };
  return (
    <div className="card mb-3"><div className="card-body">
      <div className="d-flex align-items-center mb-1"><h2 className="h6 mb-0 me-auto">SIEM export</h2>
        <button className="btn btn-sm btn-outline-secondary" onClick={() => api.download("/api/audit/export.jsonl?days=90", "pipelinetrust-audit-90d.jsonl")}>Download audit log (JSONL, 90 days)</button></div>
      <p className="small text-secondary">Stream the audit log and drift alerts to Splunk (HTTP Event Collector), Datadog or any HTTPS endpoint (signed with HMAC-SHA256 in
        <code> X-PipelineTrust-Signature</code>). Events are sent in the background as they happen.</p>
      <ErrorBox error={err} />
      {list && list.length > 0 && <table className="table table-sm small align-middle">
        <thead><tr><th>Name</th><th>Type</th><th>Endpoint</th><th>Events</th><th>Delivered / failed</th><th /></tr></thead>
        <tbody>{list.map((s) => <tr key={s.id}><td><b>{s.name}</b>{res[s.id] && <div className="text-secondary">{res[s.id]}</div>}{s.last_error && <div className="text-danger">{s.last_error}</div>}</td>
          <td>{s.kind}</td><td><code>{s.url_hint}</code></td><td>{s.events.length ? s.events.join(", ") : "all"}</td><td>{s.delivered} / {s.failed}</td>
          <td className="text-nowrap"><button className="btn btn-sm btn-outline-primary me-1" onClick={() => test(s)}>Send test</button>
            <button className="btn btn-sm btn-link text-danger" onClick={() => del(s)}>Remove</button></td></tr>)}</tbody></table>}
      <form onSubmit={add} className="row g-2 small align-items-end">
        <div className="col-6 col-md-2"><label className="form-label" htmlFor="sk">Type</label><select id="sk" className="form-select form-select-sm" value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}>
          <option value="splunk">Splunk HEC</option><option value="datadog">Datadog logs</option><option value="webhook">Generic webhook</option></select></div>
        <div className="col-6 col-md-2"><label className="form-label" htmlFor="sn">Name</label><input id="sn" className="form-control form-control-sm" required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></div>
        <div className="col-12 col-md-4"><label className="form-label" htmlFor="su">URL</label><input id="su" type="url" required className="form-control form-control-sm" placeholder={ph[f.kind][0]} value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} /></div>
        <div className="col-12 col-md-2"><label className="form-label" htmlFor="ss">{ph[f.kind][1]}</label><input id="ss" type="password" autoComplete="new-password" className="form-control form-control-sm" required={f.kind !== "webhook"} value={f.secret} onChange={(e) => setF({ ...f, secret: e.target.value })} /></div>
        <div className="col-6 col-md-1 d-flex flex-column">{["audit", "alert"].map((ev) => <div className="form-check" key={ev}><input id={`ev-${ev}`} type="checkbox" className="form-check-input"
          checked={!f.events.length || f.events.includes(ev)} onChange={(e) => {
            const cur = f.events.length ? f.events : ["audit", "alert"];
            const next = e.target.checked ? [...new Set([...cur, ev])] : cur.filter((x) => x !== ev);
            setF({ ...f, events: next.length === 2 ? [] : next });
          }} /><label htmlFor={`ev-${ev}`} className="form-check-label">{ev}</label></div>)}</div>
        <div className="col-6 col-md-1"><button className="btn btn-sm btn-primary">Add</button></div>
      </form>
    </div></div>
  );
}

/* ------------------------------------------------------------ plain-English policy drafting */

interface Draft { source: string; method: string; provider: string; explanation: string; definition: { id: string; title: string } | null;
  test?: { violations: number; scans: { project: string; status: string; violations: unknown[] }[] } }

export function PolicyDraft({ onUse }: { onUse: (source: string) => void }) {
  const { role } = useMe();
  const [desc, setDesc] = useState("");
  const [d, setD] = useState<Draft | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  if (!canEdit(role)) return null;
  const go = async (e: React.FormEvent) => {
    e.preventDefault(); setBusy(true); setErr(null); setD(null);
    try { setD(await api.post<Draft>("/api/policies/draft", { description: desc })); } catch (x) { setErr((x as Error).message); } finally { setBusy(false); }
  };
  return (
    <div className="card mb-3"><div className="card-body">
      <h2 className="h6">Describe a rule in plain English</h2>
      <form onSubmit={go} className="d-flex flex-wrap gap-2">
        <input className="form-control form-control-sm flex-grow-1" style={{ minWidth: 280 }} minLength={8} required aria-label="Describe the policy"
          placeholder="e.g. Jobs that deploy must use a protected environment" value={desc} onChange={(e) => setDesc(e.target.value)} />
        <button className="btn btn-sm btn-primary" disabled={busy}>{busy ? "Drafting…" : "Draft policy"}</button>
      </form>
      <div className="small text-secondary mt-1">Try: &quot;ban tj-actions/changed-files&quot;, &quot;no self-hosted runners for fork pull requests&quot;, &quot;no packages write&quot;, &quot;pin every action to a SHA&quot;.
        With an AI provider configured any wording works; the draft is always validated and tested on every project before you save it.</div>
      <ErrorBox error={err} />
      {d && (d.source ? <div className="mt-2">
        <div className="small mb-1"><span className="badge bg-info text-dark me-1">{d.method === "llm" ? `AI (${d.provider})` : "built-in template"}</span>{d.explanation}</div>
        <pre className="snippet small mb-1">{d.source}</pre>
        {d.test && <div className="small mb-2">Dry run: <b>{d.test.violations}</b> violation(s) across {d.test.scans.length} project(s)
          {d.test.scans.filter((s) => s.violations.length).slice(0, 5).map((s) => ` · ${s.project}: ${s.violations.length}`).join("")}</div>}
        <button className="btn btn-sm btn-outline-primary" onClick={() => onUse(d.source)}>Open in editor</button>
      </div> : <div className="alert alert-warning small mt-2 mb-0">{d.explanation}</div>)}
    </div></div>
  );
}

/* ------------------------------------------------------------ golden templates */

interface TplRow { project_id: string; project: string; scan_id: string; workflow: string; workflow_name: string; status: string; detail: string; similarity?: number;
  missing_steps?: string[]; extra_steps?: string[]; ref?: string }
interface TplRes { id: string; name: string; workflow_path: string; source_project: string; error?: string; callable?: boolean; reusable_ref?: string | null;
  steps?: number; rows?: TplRow[]; counts?: Record<string, number> }
const TPL_CLS: Record<string, [string, string]> = { adopted: ["bg-success", "Calls template"], unapproved_ref: ["bg-warning text-dark", "Unapproved version"],
  copy: ["bg-info text-dark", "Copy"], drifted_copy: ["bg-danger", "Drifted copy"], not_adopted: ["bg-secondary", "Not adopted"] };

export function TemplatesPanel() {
  const { role } = useMe();
  const admin = role === "admin";
  const [res, setRes] = useState<TplRes[] | null>(null);
  const [projects, setProjects] = useState<{ id: string; name: string }[]>([]);
  const [f, setF] = useState({ name: "", source_project_id: "", workflow_path: ".github/workflows/", applies_to: "", approved_refs: "" });
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const load = () => api.get<TplRes[]>("/api/templates/compliance").then(setRes).catch((e) => setErr(e.message));
  useEffect(() => { load(); api.get<{ id: string; name: string }[]>("/api/projects").then(setProjects).catch(() => setProjects([])); }, []);
  const add = async (e: React.FormEvent) => {
    e.preventDefault(); setErr(null);
    try { await api.post("/api/templates", { ...f, approved_refs: f.approved_refs.split(/[\s,]+/).filter(Boolean) }); setF({ ...f, name: "" }); load(); }
    catch (x) { setErr((x as Error).message); }
  };
  const del = async (t: TplRes) => { if (confirm(`Remove template ${t.name}?`)) { await api.del(`/api/templates/${t.id}`); load(); } };
  return (
    <div className="card mb-3"><div className="card-body">
      <h2 className="h6">Golden pipeline templates</h2>
      <p className="small text-secondary">Mark an approved workflow (ideally a reusable <code>workflow_call</code> workflow) and see which repositories call it, which copied it - copies
        stop receiving its fixes - and which drifted from it. Compared on each project&apos;s latest scan.</p>
      <ErrorBox error={err} />
      {!res ? <Loading /> : !res.length ? <div className="small text-secondary mb-2">No templates yet.</div> : res.map((t) => (
        <div key={t.id} className="border rounded p-2 mb-2">
          <div className="d-flex flex-wrap align-items-center gap-2">
            <b>{t.name}</b><span className="small text-secondary">{t.source_project} · <code>{t.workflow_path}</code>{t.reusable_ref && <> · callable as <code>{t.reusable_ref}@…</code></>}</span>
            <span className="ms-auto" />{t.counts && Object.entries(t.counts).filter(([, n]) => n).map(([k, n]) => <span key={k} className={`badge ${TPL_CLS[k][0]}`}>{n} {TPL_CLS[k][1].toLowerCase()}</span>)}
            {admin && <button className="btn btn-sm btn-link text-danger" onClick={() => del(t)}>Remove</button>}
          </div>
          {t.error ? <div className="small text-danger">{t.error}</div> : t.callable === false && <div className="small text-warning-emphasis">This workflow has no <code>workflow_call</code> trigger, so repositories can only copy it.</div>}
          {t.rows && t.rows.length > 0 && <table className="table table-sm small mb-0 mt-1"><tbody>{t.rows.map((r) => (
            <Fragment key={r.project_id + r.workflow}>
              <tr className="finding-row" onClick={() => setOpen(open === r.project_id + r.workflow ? null : r.project_id + r.workflow)}>
                <td><span className={`badge ${TPL_CLS[r.status][0]}`}>{TPL_CLS[r.status][1]}</span></td>
                <td><Link href={pipelineHref(r.scan_id, r.workflow)} onClick={(e) => e.stopPropagation()}>{r.project} / {r.workflow_name}</Link></td><td>{r.detail}</td></tr>
              {open === r.project_id + r.workflow && (r.missing_steps?.length || r.extra_steps?.length) ? <tr><td colSpan={3} className="bg-body-tertiary">
                {r.missing_steps?.length ? <div><b>Missing from template:</b> {r.missing_steps.map((s, i) => <code key={i} className="me-2">{s}</code>)}</div> : null}
                {r.extra_steps?.length ? <div><b>Added locally:</b> {r.extra_steps.map((s, i) => <code key={i} className="me-2">{s}</code>)}</div> : null}
              </td></tr> : null}
            </Fragment>))}</tbody></table>}
        </div>))}
      {admin && <form onSubmit={add} className="row g-2 small align-items-end mt-1">
        <div className="col-6 col-md-2"><label className="form-label" htmlFor="tn2">Name</label><input id="tn2" className="form-control form-control-sm" required minLength={2} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></div>
        <div className="col-6 col-md-2"><label className="form-label" htmlFor="tp">Source project</label><select id="tp" className="form-select form-select-sm" required value={f.source_project_id} onChange={(e) => setF({ ...f, source_project_id: e.target.value })}>
          <option value="">Choose…</option>{projects.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}</select></div>
        <div className="col-12 col-md-3"><label className="form-label" htmlFor="tw2">Workflow file</label><input id="tw2" className="form-control form-control-sm" required value={f.workflow_path} onChange={(e) => setF({ ...f, workflow_path: e.target.value })} /></div>
        <div className="col-6 col-md-2"><label className="form-label" htmlFor="ta">Applies to (regex)</label><input id="ta" className="form-control form-control-sm" placeholder="ci|build" value={f.applies_to} onChange={(e) => setF({ ...f, applies_to: e.target.value })} /></div>
        <div className="col-6 col-md-2"><label className="form-label" htmlFor="tr">Approved versions</label><input id="tr" className="form-control form-control-sm" placeholder="v2, v3" value={f.approved_refs} onChange={(e) => setF({ ...f, approved_refs: e.target.value })} /></div>
        <div className="col-12 col-md-1"><button className="btn btn-sm btn-primary">Add</button></div>
      </form>}
    </div></div>
  );
}
