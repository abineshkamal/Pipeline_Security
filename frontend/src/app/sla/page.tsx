"use client";
import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import Shell, { useMe } from "@/components/Shell";
import { Empty, ErrorBox, Loading, SevBadge } from "@/components/ui";
import { api } from "@/lib/api";

const SEVS = ["critical", "high", "medium", "low"] as const;
interface Row { finding_id: string; scan_id: string; project_id: string; project: string; team: string; severity: string; rule_id: string; title: string; file_path: string;
  age_days: number; target_days: number; overdue: boolean; due_in: number }
interface Sla {
  targets: Record<string, number>; window_days: number;
  by_severity: Record<string, { target_days: number; open: number; overdue: number; oldest_days: number | null; fixed: number; mttr_days: number | null; within_target_pct: number | null }>;
  teams: { team: string; open: number; overdue: number; overdue_critical: number; fixed: number; mttr_days: number | null }[];
  totals: { open: number; overdue: number; fixed: number; within_target_pct: number | null }; overdue: Row[]; due_soon: Row[]; note: string;
}

function Body() {
  const { role } = useMe();
  const [win, setWin] = useState(90);
  const [d, setD] = useState<Sla | null>(null);
  const [t, setT] = useState<Record<string, number> | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const load = useCallback(() => { api.get<Sla>(`/api/sla?window_days=${win}`).then((x) => { setD(x); setT(x.targets); }).catch((e) => setErr(e.message)); }, [win]);
  useEffect(() => { load(); }, [load]);
  const save = async () => { try { await api.put("/api/sla/targets", t); load(); } catch (x) { setErr((x as Error).message); } };
  if (!d || !t) return err ? <ErrorBox error={err} /> : <Loading />;
  const rowTable = (rows: Row[], label: string) => !rows.length ? <Empty>{label}</Empty> : (
    <div className="table-responsive"><table className="table table-sm small align-middle mb-0">
      <thead><tr><th>Severity</th><th>Finding</th><th>Project</th><th>Age</th><th>Target</th></tr></thead>
      <tbody>{rows.map((r) => <tr key={r.finding_id}><td><SevBadge s={r.severity} /></td>
        <td><Link href={`/scan?id=${r.scan_id}&finding=${r.finding_id}`}>{r.rule_id} {r.title}</Link><div className="text-secondary">{r.file_path}</div></td>
        <td>{r.project}</td><td className={r.overdue ? "text-danger fw-semibold" : ""}>{r.age_days} d</td>
        <td>{r.target_days} d{r.overdue ? <span className="text-danger"> (+{-r.due_in})</span> : <span className="text-secondary"> ({r.due_in} left)</span>}</td></tr>)}</tbody>
    </table></div>);
  return (
    <>
      <div className="d-flex flex-wrap align-items-center gap-2 mb-1">
        <h1 className="h4 mb-0 me-auto">Remediation SLAs</h1>
        <select className="form-select form-select-sm w-auto" aria-label="Window" value={win} onChange={(e) => setWin(Number(e.target.value))}>
          {[30, 90, 180, 365].map((n) => <option key={n} value={n}>Fixed in the last {n} days</option>)}</select>
      </div>
      <p className="text-secondary small mb-3">How long findings stay open against your targets. {d.note} Accepted risks and false positives are not counted as overdue.</p>
      <ErrorBox error={err} />
      <div className="row g-2 mb-3">{[["Open findings", d.totals.open, ""], ["Overdue", d.totals.overdue, d.totals.overdue ? "text-danger" : ""],
        [`Fixed (${d.window_days} d)`, d.totals.fixed, ""], ["Fixed within target", d.totals.within_target_pct == null ? "—" : `${d.totals.within_target_pct}%`, ""]].map(([l, v, c]) => (
        <div className="col-6 col-md-3" key={l as string}><div className="card h-100"><div className="card-body py-2"><div className={`fs-4 fw-bold ${c}`}>{v}</div><div className="small text-secondary">{l}</div></div></div></div>))}</div>
      <div className="card mb-3"><div className="card-body">
        <h2 className="h6">By severity</h2>
        <table className="table table-sm small align-middle mb-0">
          <thead><tr><th>Severity</th><th>Target (days)</th><th>Open</th><th>Overdue</th><th>Oldest</th><th>Fixed</th><th>Mean time to fix</th><th>Within target</th></tr></thead>
          <tbody>{SEVS.map((s) => { const b = d.by_severity[s]; return <tr key={s}><td><SevBadge s={s} /></td>
            <td>{role === "admin" ? <input type="number" min={1} max={730} className="form-control form-control-sm" style={{ width: 80 }} aria-label={`${s} target`} value={t[s]}
              onChange={(e) => setT({ ...t, [s]: Number(e.target.value) })} /> : b.target_days}</td>
            <td>{b.open}</td><td className={b.overdue ? "text-danger fw-semibold" : ""}>{b.overdue}</td><td>{b.oldest_days != null ? `${b.oldest_days} d` : "—"}</td>
            <td>{b.fixed}</td><td>{b.mttr_days != null ? `${b.mttr_days} d` : "—"}</td><td>{b.within_target_pct != null ? `${b.within_target_pct}%` : "—"}</td></tr>; })}</tbody>
        </table>
        {role === "admin" && <button className="btn btn-sm btn-primary mt-2" onClick={save}>Save targets</button>}
      </div></div>
      <div className="row g-3">
        <div className="col-12 col-xl-4"><div className="card h-100"><div className="card-body">
          <h2 className="h6">By team / owner</h2>
          {!d.teams.length ? <Empty>No data.</Empty> : <table className="table table-sm small mb-0"><thead><tr><th>Owner</th><th>Open</th><th>Overdue</th><th>Critical overdue</th><th>MTTR</th></tr></thead>
            <tbody>{d.teams.map((x) => <tr key={x.team}><td>{x.team}</td><td>{x.open}</td><td className={x.overdue ? "text-danger" : ""}>{x.overdue}</td><td>{x.overdue_critical}</td>
              <td>{x.mttr_days != null ? `${x.mttr_days} d` : "—"}</td></tr>)}</tbody></table>}
        </div></div></div>
        <div className="col-12 col-xl-8"><div className="card mb-3"><div className="card-body">
          <h2 className="h6">Overdue ({d.overdue.length})</h2>{rowTable(d.overdue.slice(0, 100), "Nothing is overdue.")}
        </div></div>
        <div className="card"><div className="card-body"><h2 className="h6">Due within 7 days ({d.due_soon.length})</h2>{rowTable(d.due_soon.slice(0, 50), "Nothing due this week.")}</div></div></div>
      </div>
    </>
  );
}

export default function Page() { return <Shell><Body /></Shell>; }
