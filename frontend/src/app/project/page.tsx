"use client";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useState } from "react";
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import Shell, { canEdit, useMe } from "@/components/Shell";
import { Empty, ErrorBox, Loading, StatusBadge } from "@/components/ui";
import { api, fmtDate, pipelineHref, type Project, type ProjectPipelines, type Scan } from "@/lib/api";

interface Tool { name: string; available: boolean; default: boolean }
interface TrendPt { scan_id: string; at: string; posture_score: number | null; coverage: number | null; critical: number; high: number }

function ScanLauncher({ project, onStarted }: { project: Project; onStarted: () => void }) {
  const [tools, setTools] = useState<Tool[]>([]);
  const [sel, setSel] = useState<string[]>([]);
  const [ai, setAi] = useState(true);
  const [ref, setRef] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    api.get<Tool[]>("/api/tools").then((t) => { setTools(t); setSel(t.filter((x) => x.default && x.available).map((x) => x.name)); });
  }, []);
  const toggle = (n: string) => setSel(sel.includes(n) ? sel.filter((x) => x !== n) : [...sel, n]);
  const start = async () => {
    setBusy(true); setErr(null);
    try {
      if (project.source_type === "upload") {
        if (!file) throw new Error("choose a .zip of the repository first");
        await api.upload(`/api/projects/${project.id}/scans/upload?tools=${sel.join(",")}&ai=${ai}`, file);
      } else {
        await api.post(`/api/projects/${project.id}/scans`, { tools: sel, run_tools: sel.length > 0, ai, ref: ref.trim() });
      }
      onStarted();
    } catch (x) { setErr((x as Error).message); } finally { setBusy(false); }
  };
  return (
    <div className="card mb-3"><div className="card-body">
      <h2 className="h6">Run assessment</h2>
      {project.source_type === "upload" && (
        <div className="mb-2"><label className="form-label small" htmlFor="zip">Repository archive (.zip). It is extracted in an isolated workspace, never executed, and deleted after the scan.</label>
          <input id="zip" type="file" accept=".zip,application/zip" className="form-control" onChange={(e) => setFile(e.target.files?.[0] || null)} /></div>
      )}
      {project.source_type === "github" && (
        <div className="mb-2" style={{ maxWidth: 420 }}><label className="form-label small" htmlFor="ref">Branch, tag or commit (optional - e.g. a release tag to compare releases)</label>
          <input id="ref" className="form-control form-control-sm" placeholder={project.ref || "default branch"} value={ref} onChange={(e) => setRef(e.target.value)} /></div>
      )}
      <div className="small mb-1 text-secondary">External scanners (missing tools mark dependent controls NOT ASSESSED):</div>
      <div className="d-flex flex-wrap gap-3 mb-2">
        {tools.map((t) => (
          <div className="form-check" key={t.name}>
            <input className="form-check-input" type="checkbox" id={`t-${t.name}`} checked={sel.includes(t.name)} disabled={!t.available} onChange={() => toggle(t.name)} />
            <label className="form-check-label small" htmlFor={`t-${t.name}`}>{t.name}{!t.available && " (not installed)"}</label>
          </div>
        ))}
      </div>
      <div className="form-check mb-2">
        <input className="form-check-input" type="checkbox" id="ai" checked={ai} onChange={(e) => setAi(e.target.checked)} />
        <label className="form-check-label small" htmlFor="ai">Run AI analysis agents (advisory; deterministic fallback without an LLM key)</label>
      </div>
      <ErrorBox error={err} />
      <button className="btn btn-primary" onClick={start} disabled={busy}>{busy ? "Starting…" : "Start scan"}</button>
    </div></div>
  );
}

function Monitoring({ project, editable, onChange }: { project: Project; editable: boolean; onChange: () => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [alerts, setAlerts] = useState<number | null>(null);
  useEffect(() => { api.get<unknown[]>(`/api/alerts?project_id=${project.id}`).then((a) => setAlerts(a.length)).catch(() => setAlerts(null)); }, [project.id]);
  const set = async (schedule: string) => {
    setBusy(true); setErr(null);
    try { await api.put(`/api/projects/${project.id}/schedule`, { schedule }); onChange(); } catch (x) { setErr((x as Error).message); } finally { setBusy(false); }
  };
  return (
    <div className="card mb-3"><div className="card-body d-flex flex-wrap align-items-center gap-3">
      <h2 className="h6 mb-0">Continuous monitoring</h2>
      {project.source_type !== "github" ? <span className="small text-secondary">Scheduled scans need a GitHub project; ZIP projects are scanned on upload.</span> : <>
        <div className="d-flex align-items-center gap-2">
          <label htmlFor="sched" className="small text-secondary">Re-scan</label>
          <select id="sched" className="form-select form-select-sm w-auto" value={project.schedule} disabled={!editable || busy} onChange={(e) => set(e.target.value)}>
            <option value="">Manually</option><option value="daily">Daily</option><option value="weekly">Weekly</option>
          </select>
        </div>
        <span className="small text-secondary">{project.schedule ? `Next run ${fmtDate(project.next_scan_at)}` : "Not scheduled"}</span>
      </>}
      <span className="small text-secondary">Every completed scan is compared with the previous one; regressions raise a drift alert.</span>
      <Link href="/alerts" className={`badge ms-auto ${alerts ? "bg-danger" : "bg-secondary"}`}>{alerts ?? "—"} open alert(s)</Link>
      <ErrorBox error={err} />
    </div></div>
  );
}

function TriggerBadges({ triggers, external, privileged }: { triggers: string[]; external: string[]; privileged: string[] }) {
  return <>{triggers.map((t) => (
    <span key={t} className={`badge me-1 ${privileged.includes(t) ? "bg-danger" : external.includes(t) ? "bg-warning text-dark" : "bg-secondary"}`}
      title={privileged.includes(t) ? "Privileged trigger reachable by outsiders" : external.includes(t) ? "Can be triggered from outside the repository" : undefined}>{t}</span>
  ))}</>;
}

function Pipelines({ data }: { data: ProjectPipelines }) {
  const [q, setQ] = useState("");
  if (!data.scan) return (
    <div className="card mb-3"><div className="card-body"><h2 className="h6">Pipelines</h2>
      <Empty>Run a scan to discover this repository&apos;s pipelines.</Empty></div></div>
  );
  const rows = data.pipelines.filter((p) => !q || `${p.name} ${p.path}`.toLowerCase().includes(q.toLowerCase()));
  return (
    <div className="card mb-3"><div className="card-body">
      <div className="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-2">
        <div><h2 className="h6 mb-0">Pipelines ({data.pipelines.length})</h2>
          <div className="small text-secondary">From the latest scan · {fmtDate(data.scan.created_at)} · commit <code>{data.scan.commit_sha.slice(0, 10) || "—"}</code>
            {data.repo_setting_findings > 0 && <> · {data.repo_setting_findings} repository-setting finding(s) apply to every pipeline</>}</div></div>
        <input className="form-control form-control-sm" style={{ maxWidth: 240 }} placeholder="Filter pipelines…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter pipelines" />
      </div>
      {!data.pipelines.length ? <Empty>No GitHub Actions workflows were found in this repository.</Empty> : (
        <div className="table-responsive"><table className="table table-sm table-hover mb-0 align-middle">
          <thead><tr><th>Pipeline</th><th>Triggers</th><th>Jobs</th><th>Findings</th><th>Max risk</th><th>Attack paths</th><th>Exposure</th><th /></tr></thead>
          <tbody>{rows.map((p) => (
            <tr key={p.path}>
              <td><Link href={pipelineHref(data.scan!.id, p.path)} className="fw-semibold">{p.name}</Link>
                <div className="small text-secondary font-monospace text-break-all">{p.path}</div>{p.error && <div className="small text-danger">{p.error}</div>}</td>
              <td><TriggerBadges triggers={p.triggers} external={p.external_triggers} privileged={p.privileged_triggers} /></td>
              <td>{p.jobs}</td>
              <td className="text-nowrap">{p.findings === 0 ? <span className="text-success small">None</span> : (["critical", "high", "medium", "low"] as const)
                .filter((k) => p.severity_counts[k] > 0).map((k) => <span key={k} className={`badge sev-${k} me-1`}>{p.severity_counts[k]} {k}</span>)}</td>
              <td>{p.max_risk || "—"}</td>
              <td>{p.attack_paths || "—"}</td>
              <td className="small">
                {p.self_hosted && <span className="badge bg-danger me-1">self-hosted</span>}
                {p.write_access && <span className="badge bg-warning text-dark me-1">write token</span>}
                {p.deploys && <span className="badge bg-info text-dark me-1">deploys</span>}
                {p.secrets.length > 0 && <span className="badge bg-light text-dark border me-1">{p.secrets.length} secret(s)</span>}
              </td>
              <td><Link href={pipelineHref(data.scan!.id, p.path)}>Analyse</Link></td>
            </tr>
          ))}</tbody>
        </table></div>
      )}
      {data.other_ci_systems.length > 0 && <div className="small text-secondary mt-2">Other CI systems detected but not assessed: {data.other_ci_systems.map((c) => `${c.system} (${c.file})`).join(", ")}</div>}
    </div></div>
  );
}

function Body() {
  const id = useSearchParams().get("id") || "";
  const router = useRouter();
  const { role } = useMe();
  const [p, setP] = useState<Project | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [trend, setTrend] = useState<TrendPt[]>([]);
  const [pipes, setPipes] = useState<ProjectPipelines | null>(null);
  const [cmp, setCmp] = useState<string[]>([]);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(() => {
    if (!id) return;
    Promise.all([api.get<Project>(`/api/projects/${id}`), api.get<Scan[]>(`/api/projects/${id}/scans`), api.get<TrendPt[]>(`/api/projects/${id}/trend`),
      api.get<ProjectPipelines>(`/api/projects/${id}/pipelines`)])
      .then(([a, b, c, d]) => { setP(a); setScans(b); setTrend(c); setPipes(d); }).catch((e) => setErr(e.message));
  }, [id]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (!scans.some((s) => s.status === "queued" || s.status === "running")) return;
    const t = setInterval(load, 2500);
    return () => clearInterval(t);
  }, [scans, load]);

  const remove = async () => {
    if (!p || !confirm(`Delete project "${p.name}" and all its scans? This cannot be undone.`)) return;
    await api.del(`/api/projects/${p.id}`);
    router.replace("/projects");
  };

  if (err) return <ErrorBox error={err} />;
  if (!p) return <Loading />;
  const data = trend.map((t) => ({ ...t, label: new Date(t.at).toLocaleDateString() }));
  return (
    <>
      <div className="d-flex flex-wrap justify-content-between align-items-start gap-2 mb-3">
        <div><h1 className="h4 mb-0">{p.name}</h1>
          <div className="text-secondary small">{p.source_type === "github" ? `GitHub · ${p.repo_full_name}${p.ref ? "@" + p.ref : ""}` : "Offline ZIP assessment"}</div></div>
        {role === "admin" && <button className="btn btn-outline-danger btn-sm" onClick={remove}>Delete project</button>}
      </div>
      {canEdit(role) && <ScanLauncher project={p} onStarted={load} />}
      <Monitoring project={p} editable={canEdit(role)} onChange={load} />
      {pipes ? <Pipelines data={pipes} /> : <Loading />}
      {data.length > 1 && (
        <div className="card mb-3"><div className="card-body">
          <h2 className="h6">Posture over time</h2>
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={data} margin={{ left: -20 }}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} /><XAxis dataKey="label" fontSize={11} /><YAxis fontSize={11} domain={[0, 100]} />
              <Tooltip /><Legend />
              <Line type="monotone" dataKey="posture_score" name="Posture" stroke="#2d3a8c" strokeWidth={2} />
              <Line type="monotone" dataKey="coverage" name="Coverage %" stroke="#805ad5" strokeDasharray="4 3" />
              <Line type="monotone" dataKey="critical" name="Critical" stroke="#b3261e" />
            </LineChart>
          </ResponsiveContainer>
        </div></div>
      )}
      <div className="card"><div className="card-body">
        <div className="d-flex flex-wrap align-items-center gap-2 mb-2">
          <h2 className="h6 mb-0 me-auto">Scans</h2>
          <span className="small text-secondary">Tick two completed scans to see what changed in the pipelines between them.</span>
          <button className="btn btn-sm btn-outline-primary" disabled={cmp.length !== 2} onClick={() => {
            const [a, b] = [...cmp].sort((x, y) => (scans.find((s) => s.id === x)!.created_at < scans.find((s) => s.id === y)!.created_at ? -1 : 1));
            router.push(`/diff?base=${a}&scan=${b}`);
          }}>Compare {cmp.length}/2</button>
        </div>
        {!scans.length ? <Empty>No scans yet.</Empty> : (
          <div className="table-responsive"><table className="table table-sm mb-0">
            <thead><tr><th /><th>Started</th><th>Status</th><th>Score</th><th>Critical / High</th><th>Ref / commit</th><th /></tr></thead>
            <tbody>{scans.map((s) => (
              <tr key={s.id}>
                <td>{s.status === "completed" && <input type="checkbox" className="form-check-input" aria-label="Select for comparison" checked={cmp.includes(s.id)}
                  onChange={(e) => setCmp(e.target.checked ? [...cmp.slice(-1), s.id] : cmp.filter((x) => x !== s.id))} />}</td>
                <td className="small">{fmtDate(s.created_at)}{s.trigger && s.trigger !== "manual" && <span className="badge bg-light text-dark border ms-1">{s.trigger}</span>}</td>
                <td><StatusBadge s={s.status} /> {(s.status === "running" || s.status === "queued") && <span className="small text-secondary">{s.progress}</span>}
                  {s.status === "failed" && <div className="small text-danger">{s.error}</div>}</td>
                <td>{s.posture_score ?? "—"} {s.grade && <span className="text-secondary small">({s.grade})</span>}</td>
                <td>{s.severity_counts ? `${s.severity_counts.critical} / ${s.severity_counts.high}` : "—"}</td>
                <td className="small font-monospace">{s.ref && <span className="badge bg-info text-dark me-1">{s.ref}</span>}{s.commit_sha?.slice(0, 10) || "—"}</td>
                <td>{s.status === "completed" && <Link href={`/scan?id=${s.id}`}>View results</Link>}</td>
              </tr>
            ))}</tbody>
          </table></div>
        )}
      </div></div>
    </>
  );
}

export default function Page() { return <Shell><Suspense fallback={<Loading />}><Body /></Suspense></Shell>; }
