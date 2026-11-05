"use client";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useState } from "react";
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import Shell, { canEdit, useMe } from "@/components/Shell";
import { Empty, ErrorBox, Loading, StatusBadge } from "@/components/ui";
import { api, fmtDate, type Project, type Scan } from "@/lib/api";

interface Tool { name: string; available: boolean; default: boolean }
interface TrendPt { scan_id: string; at: string; posture_score: number | null; coverage: number | null; critical: number; high: number }

function ScanLauncher({ project, onStarted }: { project: Project; onStarted: () => void }) {
  const [tools, setTools] = useState<Tool[]>([]);
  const [sel, setSel] = useState<string[]>([]);
  const [ai, setAi] = useState(true);
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
        await api.post(`/api/projects/${project.id}/scans`, { tools: sel, run_tools: sel.length > 0, ai });
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

function Body() {
  const id = useSearchParams().get("id") || "";
  const router = useRouter();
  const { role } = useMe();
  const [p, setP] = useState<Project | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [trend, setTrend] = useState<TrendPt[]>([]);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(() => {
    if (!id) return;
    Promise.all([api.get<Project>(`/api/projects/${id}`), api.get<Scan[]>(`/api/projects/${id}/scans`), api.get<TrendPt[]>(`/api/projects/${id}/trend`)])
      .then(([a, b, c]) => { setP(a); setScans(b); setTrend(c); }).catch((e) => setErr(e.message));
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
        <h2 className="h6">Scans</h2>
        {!scans.length ? <Empty>No scans yet.</Empty> : (
          <div className="table-responsive"><table className="table table-sm mb-0">
            <thead><tr><th>Started</th><th>Status</th><th>Score</th><th>Critical / High</th><th>Commit</th><th /></tr></thead>
            <tbody>{scans.map((s) => (
              <tr key={s.id}>
                <td className="small">{fmtDate(s.created_at)}</td>
                <td><StatusBadge s={s.status} /> {(s.status === "running" || s.status === "queued") && <span className="small text-secondary">{s.progress}</span>}
                  {s.status === "failed" && <div className="small text-danger">{s.error}</div>}</td>
                <td>{s.posture_score ?? "—"} {s.grade && <span className="text-secondary small">({s.grade})</span>}</td>
                <td>{s.severity_counts ? `${s.severity_counts.critical} / ${s.severity_counts.high}` : "—"}</td>
                <td className="small font-monospace">{s.commit_sha?.slice(0, 10) || "—"}</td>
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
