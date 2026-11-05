"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import Shell from "@/components/Shell";
import { Empty, ErrorBox, Loading, ScoreRing, StatusBadge } from "@/components/ui";
import { api, CATEGORIES, fmtDate, type SevCounts } from "@/lib/api";

interface Dash {
  projects: number; assessed_projects: number; average_posture: number | null; severity_counts: SevCounts; open_findings: number;
  category_scores: Record<string, number>;
  projects_at_risk: { project_id: string; name: string; posture_score: number | null; scan_id: string; critical: number }[];
  recent_scans: { id: string; project: string; project_id: string; status: string; posture_score: number | null; created_at: string }[];
}

const scoreColor = (v: number) => (v >= 90 ? "var(--pt-pass)" : v >= 65 ? "var(--pt-medium)" : "var(--pt-critical)");

function Body() {
  const [d, setD] = useState<Dash | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => { api.get<Dash>("/api/dashboard").then(setD).catch((e) => setErr(e.message)); }, []);
  if (err) return <ErrorBox error={err} />;
  if (!d) return <Loading />;
  if (!d.projects) return (
    <Empty>
      <h2 className="h5">No projects yet</h2>
      <p>Create a project from a GitHub repository or upload a repository ZIP to run your first OWASP CI/CD assessment.</p>
      <Link className="btn btn-primary" href="/projects">Create a project</Link>
    </Empty>
  );
  const cats = Object.entries(d.category_scores).map(([k, v]) => ({ cat: k.replace("CICD-SEC-", "SEC-"), name: CATEGORIES[k], score: v }));
  return (
    <>
      <h1 className="h4 mb-3">Security posture overview</h1>
      <div className="row g-3 mb-3">
        <div className="col-12 col-md-3"><div className="card h-100"><div className="card-body d-flex align-items-center gap-3">
          <ScoreRing score={d.average_posture} /><div className="kpi"><div className="l">Average posture</div><div className="small text-secondary">{d.assessed_projects} of {d.projects} projects assessed</div></div>
        </div></div></div>
        {(["critical", "high", "medium", "low"] as const).map((s) => (
          <div className="col-6 col-md" key={s}><div className="card h-100"><div className="card-body kpi">
            <div className="l">{s}</div><div className="v" style={{ color: `var(--pt-${s})` }}>{d.severity_counts[s]}</div>
          </div></div></div>
        ))}
        <div className="col-6 col-md"><div className="card h-100"><div className="card-body kpi"><div className="l">Open findings</div><div className="v">{d.open_findings}</div></div></div></div>
      </div>
      <div className="row g-3">
        <div className="col-12 col-lg-7"><div className="card h-100"><div className="card-body">
          <h2 className="h6">Average score by OWASP CI/CD category</h2>
          {cats.length ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={cats} margin={{ left: -20 }}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="cat" fontSize={11} interval={0} />
                <YAxis domain={[0, 100]} fontSize={11} />
                <Tooltip formatter={(v: number) => [v, "score"]} labelFormatter={(l, p) => (p?.[0]?.payload?.name ? `${l} · ${p[0].payload.name}` : l)} />
                <Bar dataKey="score" radius={[4, 4, 0, 0]}>{cats.map((c) => <Cell key={c.cat} fill={scoreColor(c.score)} />)}</Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : <p className="text-secondary small">No completed scans yet.</p>}
        </div></div></div>
        <div className="col-12 col-lg-5"><div className="card h-100"><div className="card-body">
          <h2 className="h6">Projects at risk</h2>
          <table className="table table-sm mb-0"><thead><tr><th>Project</th><th>Score</th><th>Critical</th></tr></thead><tbody>
            {d.projects_at_risk.map((p) => (
              <tr key={p.project_id}><td><Link href={`/scan?id=${p.scan_id}`}>{p.name}</Link></td><td>{p.posture_score ?? "N/A"}</td><td>{p.critical}</td></tr>
            ))}
          </tbody></table>
        </div></div></div>
        <div className="col-12"><div className="card"><div className="card-body">
          <h2 className="h6">Recent scans</h2>
          <div className="table-responsive"><table className="table table-sm mb-0"><thead><tr><th>Project</th><th>Status</th><th>Score</th><th>Started</th><th /></tr></thead><tbody>
            {d.recent_scans.map((s) => (
              <tr key={s.id}><td><Link href={`/project?id=${s.project_id}`}>{s.project}</Link></td><td><StatusBadge s={s.status} /></td>
                <td>{s.posture_score ?? "—"}</td><td className="small">{fmtDate(s.created_at)}</td><td><Link href={`/scan?id=${s.id}`}>Open</Link></td></tr>
            ))}
          </tbody></table></div>
        </div></div></div>
      </div>
    </>
  );
}

export default function Page() { return <Shell><Body /></Shell>; }
