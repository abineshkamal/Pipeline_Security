"use client";
import dynamic from "next/dynamic";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { PolarAngleAxis, PolarGrid, PolarRadiusAxis, Radar, RadarChart, ResponsiveContainer, Tooltip } from "recharts";
import Shell, { canEdit, useMe } from "@/components/Shell";
import { ErrorBox, Loading, ScoreRing, SevBadge, StatusBadge } from "@/components/ui";
import { api, CATEGORIES, fmtDate, type AttackPath, type Finding, type Scan } from "@/lib/api";

const AttackGraph = dynamic(() => import("@/components/AttackGraph"), { ssr: false, loading: () => <Loading label="Loading graph…" /> });
const TABS = ["Overview", "Controls", "Findings", "Attack paths", "AI analysis", "Inventory", "Tools"] as const;
type Tab = (typeof TABS)[number];

function Overview({ scan }: { scan: Scan }) {
  const s = scan.summary!;
  const radar = s.categories.map((c) => ({ cat: c.category.replace("CICD-SEC-", "SEC-"), score: c.score ?? 0, assessed: c.score != null }));
  return (
    <div className="row g-3">
      <div className="col-12 col-lg-4"><div className="card h-100"><div className="card-body text-center">
        <ScoreRing score={s.posture_score} size={140} />
        <div className="mt-2 fw-semibold">Grade {s.grade}</div>
        <div className="small text-secondary">{s.total_findings} findings · automated coverage {s.coverage.percent}% of applicable controls</div>
        <div className="d-flex justify-content-center gap-2 mt-3 flex-wrap">
          {(["critical", "high", "medium", "low"] as const).map((k) => <span key={k} className={`badge sev-${k}`}>{s.severity_counts[k]} {k}</span>)}
        </div>
        <div className="small text-secondary mt-3">Controls: {s.coverage.controls} · not assessed {s.coverage.not_assessed} · manual {s.coverage.manual} · N/A {s.coverage.not_applicable}</div>
      </div></div></div>
      <div className="col-12 col-lg-8"><div className="card h-100"><div className="card-body">
        <h2 className="h6">OWASP CI/CD category scores</h2>
        <ResponsiveContainer width="100%" height={300}>
          <RadarChart data={radar} outerRadius="75%">
            <PolarGrid /><PolarAngleAxis dataKey="cat" fontSize={11} /><PolarRadiusAxis domain={[0, 100]} fontSize={9} />
            <Radar dataKey="score" stroke="#2d3a8c" fill="#2d3a8c" fillOpacity={0.35} /><Tooltip />
          </RadarChart>
        </ResponsiveContainer>
      </div></div></div>
      <div className="col-12"><div className="card"><div className="table-responsive"><table className="table table-sm mb-0">
        <thead><tr><th>Category</th><th>Status</th><th>Score</th><th>Pass</th><th>Fail</th><th>Not assessed</th><th>Manual</th><th>N/A</th><th>Findings</th></tr></thead>
        <tbody>{s.categories.map((c) => (
          <tr key={c.category}><td><b>{c.category}</b> <span className="small text-secondary">{c.name}</span></td><td><StatusBadge s={c.status} /></td>
            <td>{c.score ?? "N/A"}</td><td>{c.pass}</td><td>{c.fail}</td><td>{c.not_assessed}</td><td>{c.manual}</td><td>{c.not_applicable}</td><td>{c.findings}</td></tr>
        ))}</tbody>
      </table></div></div></div>
      {s.coverage_notes?.length > 0 && <div className="col-12"><div className="alert alert-warning mb-0">
        <b>Coverage and limitations</b><ul className="mb-0 small">{s.coverage_notes.map((n, i) => <li key={i}>{n}</li>)}</ul></div></div>}
    </div>
  );
}

function Controls({ scan }: { scan: Scan }) {
  const [cat, setCat] = useState("");
  const rows = (scan.controls || []).filter((c) => !cat || c.category === cat);
  return (
    <div className="card"><div className="card-body">
      <select className="form-select form-select-sm mb-2" style={{ maxWidth: 320 }} value={cat} onChange={(e) => setCat(e.target.value)} aria-label="Filter category">
        <option value="">All categories</option>{Object.entries(CATEGORIES).map(([k, v]) => <option key={k} value={k}>{k} · {v}</option>)}
      </select>
      <div className="table-responsive"><table className="table table-sm mb-0">
        <thead><tr><th>Rule</th><th>Category</th><th>Control</th><th>Status</th><th>Notes / evidence</th></tr></thead>
        <tbody>{rows.map((c) => (
          <tr key={c.rule_id}><td className="font-monospace small">{c.rule_id}</td><td className="small">{c.category}</td><td>{c.title}</td>
            <td><StatusBadge s={c.status} />{c.finding_count > 0 && <span className="small text-secondary"> ({c.finding_count})</span>}</td>
            <td className="small text-secondary">{c.note}{c.evidence.slice(0, 3).map((e, i) => <div key={i}>{e}</div>)}</td></tr>
        ))}</tbody>
      </table></div>
    </div></div>
  );
}

function FindingDetail({ f, onSaved }: { f: Finding; onSaved: (f: Finding) => void }) {
  const { role } = useMe();
  const [triage, setTriage] = useState(f.triage_status);
  const [val, setVal] = useState(f.validation_status);
  const [note, setNote] = useState(f.triage_note);
  const [msg, setMsg] = useState<string | null>(null);
  // reset the form only when a different finding is selected (not when the saved copy comes back)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { setTriage(f.triage_status); setVal(f.validation_status); setNote(f.triage_note); setMsg(null); }, [f.id]);
  const save = async () => {
    try { onSaved(await api.patch<Finding>(`/api/findings/${f.id}`, { triage_status: triage, validation_status: val, triage_note: note })); setMsg("Saved"); }
    catch (x) { setMsg((x as Error).message); }
  };
  const t = f.ai_notes?.triage, fix = f.ai_notes?.fix;
  return (
    <div className={`card border-sev-${f.severity}`}><div className="card-body">
      <div className="d-flex gap-2 align-items-center flex-wrap mb-1"><SevBadge s={f.severity} /><span className="fw-semibold">{f.title}</span></div>
      <div className="small text-secondary mb-2">{f.rule_id} · {f.category} · risk {f.risk_score} · confidence {f.confidence} · evidence: {f.evidence_type}</div>
      <p className="mb-2">{f.message}</p>
      <div className="small mb-1">Location: <code className="text-break-all">{f.file_path}{f.line ? `:${f.line}` : ""}</code>{f.job && <> · job <code>{f.job}</code></>}</div>
      {f.snippet && <pre className="snippet mb-2">{f.snippet}</pre>}
      {f.extra?.corroborated_by && <div className="small text-success mb-2">✔ Corroborated by: {f.extra.corroborated_by.join("; ")}</div>}
      {f.extra?.suggested_pin && <div className="small mb-2">Suggested pin: <code className="text-break-all">{f.extra.suggested_pin}</code></div>}
      {fix?.patch && <><div className="small text-secondary">Suggested change ({fix.source}):</div><pre className="snippet mb-2">{fix.patch}</pre></>}
      {fix?.explanation && <p className="small">{fix.explanation}</p>}
      {t && <div className="alert alert-secondary small py-2">AI triage ({t.source}): exploitability <b>{t.exploitability}</b>, priority <b>{t.priority}</b>, false-positive likelihood {t.false_positive_likelihood}. {t.rationale}</div>}
      <hr />
      <div className="row g-2">
        <div className="col-6"><label className="form-label small" htmlFor="tri">Triage</label>
          <select id="tri" className="form-select form-select-sm" value={triage} disabled={!canEdit(role)} onChange={(e) => setTriage(e.target.value)}>
            {["open", "confirmed", "false_positive", "accepted_risk", "fixed"].map((x) => <option key={x}>{x}</option>)}</select></div>
        <div className="col-6"><label className="form-label small" htmlFor="val">Validation</label>
          <select id="val" className="form-select form-select-sm" value={val} disabled={!canEdit(role)} onChange={(e) => setVal(e.target.value)}>
            {["unvalidated", "config_evidence", "needs_validation", "validated", "not_reproducible"].map((x) => <option key={x}>{x}</option>)}</select></div>
        <div className="col-12"><label className="form-label small" htmlFor="note">Analyst note</label>
          <textarea id="note" className="form-control form-control-sm" rows={2} value={note} disabled={!canEdit(role)} onChange={(e) => setNote(e.target.value)} /></div>
      </div>
      {canEdit(role) && <button className="btn btn-sm btn-primary mt-2" onClick={save}>Save triage</button>}
      {msg && <span className="small ms-2">{msg}</span>}
    </div></div>
  );
}

function Findings({ scanId, focus }: { scanId: string; focus: string | null }) {
  const [all, setAll] = useState<Finding[] | null>(null);
  const [sev, setSev] = useState("");
  const [cat, setCat] = useState("");
  const [tri, setTri] = useState("");
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<Finding | null>(null);
  useEffect(() => { api.get<Finding[]>(`/api/scans/${scanId}/findings`).then((fs) => { setAll(fs); setSel(fs.find((f) => f.id === focus) || null); }); }, [scanId, focus]);
  const rows = useMemo(() => (all || []).filter((f) => (!sev || f.severity === sev) && (!cat || f.category === cat) && (!tri || f.triage_status === tri)
    && (!q || `${f.title} ${f.message} ${f.file_path} ${f.rule_id}`.toLowerCase().includes(q.toLowerCase()))), [all, sev, cat, tri, q]);
  if (!all) return <Loading />;
  return (
    <div className="row g-3">
      <div className="col-12 col-xl-7">
        <div className="d-flex flex-wrap gap-2 mb-2">
          <input className="form-control form-control-sm" style={{ maxWidth: 220 }} placeholder="Search…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search findings" />
          <select className="form-select form-select-sm" style={{ maxWidth: 140 }} value={sev} onChange={(e) => setSev(e.target.value)} aria-label="Severity">
            <option value="">All severities</option>{["critical", "high", "medium", "low", "info"].map((s) => <option key={s}>{s}</option>)}</select>
          <select className="form-select form-select-sm" style={{ maxWidth: 220 }} value={cat} onChange={(e) => setCat(e.target.value)} aria-label="Category">
            <option value="">All categories</option>{Object.entries(CATEGORIES).map(([k, v]) => <option key={k} value={k}>{k} · {v}</option>)}</select>
          <select className="form-select form-select-sm" style={{ maxWidth: 160 }} value={tri} onChange={(e) => setTri(e.target.value)} aria-label="Triage">
            <option value="">Any triage</option>{["open", "confirmed", "false_positive", "accepted_risk", "fixed"].map((s) => <option key={s}>{s}</option>)}</select>
        </div>
        <div className="small text-secondary mb-1">{rows.length} of {all.length} findings</div>
        <div className="card"><div className="table-responsive" style={{ maxHeight: 640 }}><table className="table table-sm mb-0">
          <thead className="sticky-top"><tr><th>Sev</th><th>Finding</th><th>Location</th><th>Risk</th><th>Triage</th></tr></thead>
          <tbody>{rows.map((f) => (
            <tr key={f.id} className={`finding-row ${sel?.id === f.id ? "table-active" : ""}`} onClick={() => setSel(f)}>
              <td><SevBadge s={f.severity} /></td>
              <td><div className="fw-semibold small">{f.title}</div><div className="small text-secondary">{f.rule_id} · {f.category}</div></td>
              <td className="small text-break-all">{f.file_path}{f.line ? `:${f.line}` : ""}</td><td>{f.risk_score}</td>
              <td className="small">{f.triage_status}</td>
            </tr>
          ))}</tbody>
        </table></div></div>
      </div>
      <div className="col-12 col-xl-5">
        {sel ? <FindingDetail f={sel} onSaved={(nf) => { setAll((a) => a!.map((x) => (x.id === nf.id ? nf : x))); setSel(nf); }} />
          : <div className="text-secondary small p-3 border rounded">Select a finding to see evidence, remediation and triage.</div>}
      </div>
    </div>
  );
}

function AttackPaths({ scan, goFinding }: { scan: Scan; goFinding: (id: string) => void }) {
  const g = scan.attack_graph!;
  const [hl, setHl] = useState<AttackPath | null>(g.paths[0] || null);
  const [full, setFull] = useState(false);
  const narratives = scan.ai_analysis?.narratives || {};
  if (!g.nodes.length) return <div className="text-secondary p-4 border rounded">No evidence-backed attack paths were identified.</div>;
  return (
    <div className="row g-3">
      <div className="col-12 col-lg-4">
        <div className="small text-secondary mb-2">{g.paths.length} path(s). Every attacker-entry edge is backed by a deterministic finding.</div>
        <div className="list-group" style={{ maxHeight: 560, overflowY: "auto" }}>
          {g.paths.map((p) => (
            <button key={p.id} className={`list-group-item list-group-item-action ${hl?.id === p.id ? "active" : ""}`} onClick={() => setHl(p)}>
              <div className="d-flex justify-content-between"><b>{p.id}</b><span>risk {p.risk}</span></div>
              <div className="small">{p.impact}</div><div className="small opacity-75">{p.actor}</div>
            </button>
          ))}
        </div>
      </div>
      <div className="col-12 col-lg-8">
        <div className="d-flex justify-content-end mb-2">
          <div className="btn-group btn-group-sm" role="group" aria-label="Graph view">
            <button className={`btn ${!full ? "btn-primary" : "btn-outline-primary"}`} onClick={() => setFull(false)} disabled={!hl}>Selected path</button>
            <button className={`btn ${full ? "btn-primary" : "btn-outline-primary"}`} onClick={() => setFull(true)}>Full graph ({g.nodes.length} nodes)</button>
          </div>
        </div>
        <AttackGraph nodes={g.nodes} edges={g.edges} highlight={hl} pathOnly={!full && !!hl} />
        {hl && <div className="card mt-2"><div className="card-body">
          <ol className="small mb-2">{hl.labels.map((l, i) => <li key={i}>{l}</li>)}</ol>
          {hl.gated_by.length > 0 && <div className="small text-secondary">Partially gated by environment(s): {hl.gated_by.join(", ")}</div>}
          {narratives[hl.id] && <div className="alert alert-secondary small py-2 mt-2">{narratives[hl.id].narrative}{narratives[hl.id].break_point && <><br /><b>Break the chain:</b> {narratives[hl.id].break_point}</>}</div>}
          <div className="small">Evidence: {hl.finding_ids.map((id) => <button key={id} className="btn btn-link btn-sm p-0 me-2" onClick={() => goFinding(id)}>{id.slice(0, 8)}</button>)}</div>
        </div></div>}
      </div>
    </div>
  );
}

function AIPanel({ scan, reload }: { scan: Scan; reload: () => void }) {
  const { role } = useMe();
  const a = scan.ai_analysis;
  const [busy, setBusy] = useState(false);
  const rerun = async () => { setBusy(true); try { await api.post(`/api/scans/${scan.id}/ai`); reload(); } finally { setBusy(false); } };
  if (!a?.report) return <div className="text-secondary">AI analysis was not run. {canEdit(role) && <button className="btn btn-sm btn-primary ms-2" onClick={rerun} disabled={busy}>Run now</button>}</div>;
  return (
    <div className="row g-3">
      <div className="col-12"><div className="alert alert-info small mb-0">{a.disclaimer} Mode: <b>{a.mode}</b> · provider {a.provider}{a.model ? ` / ${a.model}` : ""} · {a.seconds}s
        {canEdit(role) && <button className="btn btn-sm btn-outline-primary ms-3" onClick={rerun} disabled={busy}>{busy ? "Running…" : "Re-run agents"}</button>}</div></div>
      <div className="col-12 col-lg-7"><div className="card h-100"><div className="card-body">
        <h2 className="h6">Executive summary</h2><p>{a.report.executive_summary}</p>
        {a.report.top_risks.length > 0 && <><h3 className="h6">Top risks</h3><ul className="small">{a.report.top_risks.map((r, i) => <li key={i}>{r}</li>)}</ul></>}
        {a.report.recommended_actions.length > 0 && <><h3 className="h6">Recommended actions</h3><ol className="small">{a.report.recommended_actions.map((r, i) => <li key={i}>{r}</li>)}</ol></>}
      </div></div></div>
      <div className="col-12 col-lg-5"><div className="card h-100"><div className="card-body">
        <h2 className="h6">Pipeline context</h2><p className="small">{a.context?.summary}</p>
        {a.context?.trust_boundaries?.length ? <div className="small"><b>Trust boundaries:</b> {a.context.trust_boundaries.join(", ")}</div> : null}
        {a.context?.crown_jewels?.length ? <div className="small"><b>Sensitive assets:</b> {a.context.crown_jewels.join(", ")}</div> : null}
        <h3 className="h6 mt-3">Agent trace</h3>
        <table className="table table-sm small mb-0"><tbody>{a.trace?.map((t, i) => <tr key={i}><td>{t.agent}</td><td>{t.mode}</td><td>{t.seconds}s</td><td className="text-danger">{t.error}</td></tr>)}</tbody></table>
        {a.guardrail && <div className="small mt-2">Guardrail: {a.guardrail.dropped_count} unknown reference(s) discarded.</div>}
      </div></div></div>
    </div>
  );
}

function InventoryPanel({ scan }: { scan: Scan }) {
  const inv = scan.inventory!;
  return (
    <div className="row g-3">
      <div className="col-12"><div className="card"><div className="card-body">
        <h2 className="h6">Workflows ({inv.workflows.length})</h2>
        <div className="table-responsive"><table className="table table-sm small mb-0"><thead><tr><th>Workflow</th><th>Triggers</th><th>Jobs</th></tr></thead><tbody>
          {inv.workflows.map((w) => <tr key={w.path}><td><code>{w.path}</code>{w.error && <div className="text-danger">{w.error}</div>}</td>
            <td>{w.triggers.map((t) => <span key={t} className={`badge me-1 ${w.privileged_triggers.includes(t) ? "bg-danger" : w.external_triggers.includes(t) ? "bg-warning text-dark" : "bg-secondary"}`}>{t}</span>)}</td>
            <td>{w.jobs.map((j) => <div key={j.id}><b>{j.id}</b> [{j.runs_on.join(", ")}]{j.self_hosted && <span className="badge bg-danger ms-1">self-hosted</span>}
              {j.environment && <span className="badge bg-info text-dark ms-1">env {j.environment}</span>}
              {j.write_scopes?.length ? <span className="text-secondary"> write: {j.write_scopes.join(",")}</span> : j.permissions_source === "default" ? <span className="text-secondary"> (default token perms)</span> : null}
              {j.secrets.length > 0 && <span className="text-secondary"> secrets: {j.secrets.join(",")}</span>}</div>)}</td></tr>)}
        </tbody></table></div>
      </div></div></div>
      <div className="col-12 col-lg-7"><div className="card h-100"><div className="card-body">
        <h2 className="h6">Actions and images ({inv.actions.length})</h2>
        <div className="table-responsive" style={{ maxHeight: 420 }}><table className="table table-sm small mb-0"><thead><tr><th>Reference</th><th>Pinned</th><th>Publisher</th><th>Uses</th></tr></thead><tbody>
          {inv.actions.map((a) => <tr key={a.uses}><td className="text-break-all"><code>{a.uses}</code></td><td>{a.sha_pinned ? "✔ SHA" : "✖"}</td><td>{a.first_party ? "GitHub" : a.owner}</td><td>{a.count}</td></tr>)}
        </tbody></table></div>
      </div></div></div>
      <div className="col-12 col-lg-5"><div className="card h-100"><div className="card-body small">
        <h2 className="h6">Secrets referenced</h2>{Object.keys(inv.secrets).length ? Object.entries(inv.secrets).map(([k, v]) => <div key={k}><code>{k}</code> <span className="text-secondary">{v.length} job(s)</span></div>) : "None"}
        <h2 className="h6 mt-3">Self-hosted runners</h2>{Object.keys(inv.self_hosted_runners).length ? Object.entries(inv.self_hosted_runners).map(([k, v]) => <div key={k}>{k} <span className="text-secondary">{v.join(", ")}</span></div>) : "None"}
        <h2 className="h6 mt-3">Environments</h2>{Object.keys(inv.environments).length ? Object.keys(inv.environments).join(", ") : "None"}
        {inv.other_ci_systems.length > 0 && <><h2 className="h6 mt-3">Other CI systems (not assessed)</h2>{inv.other_ci_systems.map((c) => <div key={c.file}>{c.system} <code>{c.file}</code></div>)}</>}
      </div></div></div>
    </div>
  );
}

function Tools({ scan }: { scan: Scan }) {
  return (
    <div className="card"><div className="table-responsive"><table className="table table-sm mb-0">
      <thead><tr><th>Tool</th><th>Status</th><th>Results</th><th>Seconds</th><th>Detail</th></tr></thead>
      <tbody>{scan.tool_runs?.map((t) => <tr key={t.tool}><td>{t.tool}</td><td><span className={`badge ${t.status === "ok" ? "bg-success" : t.status === "skipped" ? "bg-secondary" : "bg-danger"}`}>{t.status}</span></td>
        <td>{t.count}</td><td>{t.seconds}</td><td className="small text-secondary">{t.detail}</td></tr>)}</tbody>
    </table></div></div>
  );
}

function Body() {
  const id = useSearchParams().get("id") || "";
  const [scan, setScan] = useState<Scan | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("Overview");
  const [focus, setFocus] = useState<string | null>(null);
  const load = useCallback(() => { api.get<Scan>(`/api/scans/${id}`).then(setScan).catch((e) => setErr(e.message)); }, [id]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (scan && (scan.status === "running" || scan.status === "queued")) { const t = setTimeout(load, 2500); return () => clearTimeout(t); }
  }, [scan, load]);
  if (err) return <ErrorBox error={err} />;
  if (!scan) return <Loading />;
  const dl = (fmt: string) => api.download(`/api/scans/${id}/report.${fmt}`, `pipelinetrust-${id.slice(0, 8)}.${fmt}`).catch((e) => setErr(e.message));
  return (
    <>
      <div className="d-flex flex-wrap justify-content-between align-items-start gap-2 mb-3">
        <div>
          <div className="small"><Link href={`/project?id=${scan.project_id}`}>← {scan.project?.name}</Link></div>
          <h1 className="h4 mb-0">Assessment results <StatusBadge s={scan.status} /></h1>
          <div className="small text-secondary">{scan.project?.repo_full_name || "ZIP upload"} · {fmtDate(scan.created_at)}{scan.commit_sha && <> · commit <code>{scan.commit_sha.slice(0, 12)}</code></>}</div>
        </div>
        {scan.status === "completed" && (
          <div className="btn-group btn-group-sm flex-wrap">
            <button className="btn btn-outline-primary" onClick={() => dl("html")}>HTML report</button>
            <button className="btn btn-outline-primary" onClick={() => dl("json")}>JSON</button>
            <button className="btn btn-outline-primary" onClick={() => dl("sarif")}>SARIF</button>
            {scan.inventory?.sbom_available && <button className="btn btn-outline-secondary" onClick={() => api.download(`/api/scans/${id}/sbom`, `sbom-${id.slice(0, 8)}.cdx.json`)}>SBOM</button>}
          </div>
        )}
      </div>
      {scan.status !== "completed" ? (
        scan.status === "failed" ? <div className="alert alert-danger">{scan.error}</div> : <Loading label={scan.progress || "Scan in progress…"} />
      ) : (
        <>
          <ul className="nav nav-tabs mb-3 flex-nowrap overflow-auto">
            {TABS.map((t) => <li className="nav-item" key={t}><button className={`nav-link text-nowrap ${tab === t ? "active" : ""}`} onClick={() => setTab(t)}>{t}</button></li>)}
          </ul>
          {tab === "Overview" && <Overview scan={scan} />}
          {tab === "Controls" && <Controls scan={scan} />}
          {tab === "Findings" && <Findings scanId={id} focus={focus} />}
          {tab === "Attack paths" && <AttackPaths scan={scan} goFinding={(fid) => { setFocus(fid); setTab("Findings"); }} />}
          {tab === "AI analysis" && <AIPanel scan={scan} reload={load} />}
          {tab === "Inventory" && <InventoryPanel scan={scan} />}
          {tab === "Tools" && <Tools scan={scan} />}
        </>
      )}
    </>
  );
}

export default function Page() { return <Shell><Suspense fallback={<Loading />}><Body /></Suspense></Shell>; }
