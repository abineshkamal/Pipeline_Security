"use client";
import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import Shell, { canEdit, useMe } from "@/components/Shell";
import { Empty, ErrorBox, Loading, SevBadge } from "@/components/ui";
import { api, fmtDate, type Channel, type DriftAlert } from "@/lib/api";

const KIND_LABEL: Record<string, string> = { score_drop: "Score drop", new_finding: "New finding", more_findings: "New findings",
  new_attack_path: "New attack path", secret_exposed: "Secret exposed", test: "Test" };

function Channels({ admin }: { admin: boolean }) {
  const [list, setList] = useState<Channel[] | null>(null);
  const [f, setF] = useState({ name: "", kind: "slack", url: "", min_severity: "high" });
  const [err, setErr] = useState<string | null>(null);
  const [res, setRes] = useState<Record<string, string>>({});
  const load = () => api.get<Channel[]>("/api/notifications/channels").then(setList).catch((e) => setErr(e.message));
  useEffect(() => { load(); }, []);
  const add = async (e: React.FormEvent) => {
    e.preventDefault(); setErr(null);
    try { await api.post("/api/notifications/channels", f); setF({ ...f, name: "", url: "" }); load(); } catch (x) { setErr((x as Error).message); }
  };
  const test = async (c: Channel) => {
    setRes((r) => ({ ...r, [c.id]: "Sending…" }));
    try { const r = await api.post<{ ok: boolean; detail: string }>(`/api/notifications/channels/${c.id}/test`); setRes((x) => ({ ...x, [c.id]: `${r.ok ? "Delivered" : "Failed"} · ${r.detail}` })); }
    catch (x) { setRes((r) => ({ ...r, [c.id]: (x as Error).message })); }
  };
  const patch = async (c: Channel, body: Partial<Channel>) => { await api.patch(`/api/notifications/channels/${c.id}`, body); load(); };
  const del = async (c: Channel) => { if (confirm(`Delete channel ${c.name}?`)) { await api.del(`/api/notifications/channels/${c.id}`); load(); } };
  return (
    <div className="card mb-3"><div className="card-body">
      <h2 className="h6">Notification channels</h2>
      <p className="small text-secondary mb-2">Drift alerts at or above the channel&apos;s minimum severity are posted here. Webhook URLs are stored encrypted and never shown again.</p>
      <ErrorBox error={err} />
      {!list ? <Loading /> : !list.length ? <div className="small text-secondary mb-2">No channels: alerts are only shown on this page.</div> : (
        <div className="table-responsive"><table className="table table-sm small align-middle">
          <thead><tr><th>Name</th><th>Type</th><th>URL</th><th>Minimum</th><th>Enabled</th><th /></tr></thead>
          <tbody>{list.map((c) => <tr key={c.id}>
            <td><b>{c.name}</b>{res[c.id] && <div className="text-secondary">{res[c.id]}</div>}</td><td>{c.kind}</td><td><code>{c.url_hint}</code></td>
            <td>{admin ? <select className="form-select form-select-sm w-auto" aria-label="Minimum severity" value={c.min_severity} onChange={(e) => patch(c, { min_severity: e.target.value })}>
              {["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}</select> : c.min_severity}</td>
            <td><input type="checkbox" className="form-check-input" aria-label="Enabled" checked={c.enabled} disabled={!admin} onChange={(e) => patch(c, { enabled: e.target.checked })} /></td>
            <td className="text-nowrap">{admin && <><button className="btn btn-sm btn-outline-primary me-1" onClick={() => test(c)}>Send test</button>
              <button className="btn btn-sm btn-link text-danger" onClick={() => del(c)}>Delete</button></>}</td>
          </tr>)}</tbody>
        </table></div>)}
      {admin && <form onSubmit={add} className="row g-2 align-items-end small">
        <div className="col-12 col-md-2"><label className="form-label" htmlFor="cn">Name</label><input id="cn" className="form-control form-control-sm" required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></div>
        <div className="col-6 col-md-2"><label className="form-label" htmlFor="ck">Type</label><select id="ck" className="form-select form-select-sm" value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}>
          <option value="slack">Slack incoming webhook</option><option value="teams">Teams workflow webhook</option><option value="webhook">Generic JSON webhook</option></select></div>
        <div className="col-12 col-md-5"><label className="form-label" htmlFor="cu">Webhook URL (https)</label><input id="cu" className="form-control form-control-sm" required type="url" placeholder="https://hooks.slack.com/services/…" value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} /></div>
        <div className="col-6 col-md-2"><label className="form-label" htmlFor="cm">Minimum severity</label><select id="cm" className="form-select form-select-sm" value={f.min_severity} onChange={(e) => setF({ ...f, min_severity: e.target.value })}>
          {["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}</select></div>
        <div className="col-12 col-md-1"><button className="btn btn-sm btn-primary w-100">Add</button></div>
      </form>}
    </div></div>
  );
}

function Body() {
  const { role } = useMe();
  const [status, setStatus] = useState<"open" | "all">("open");
  const [list, setList] = useState<DriftAlert[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const load = useCallback(() => { api.get<DriftAlert[]>(`/api/alerts?status=${status}`).then(setList).catch((e) => setErr(e.message)); }, [status]);
  useEffect(() => { load(); }, [load]);
  const ack = async (a: DriftAlert) => { await api.post(`/api/alerts/${a.id}/ack`); load(); };
  return (
    <>
      <h1 className="h4 mb-1">Drift alerts</h1>
      <p className="text-secondary small mb-3">Raised when a completed scan is worse than the previous scan of the same project: a new attack path, a new critical or high
        finding, a secret newly reachable by outsiders, or a score drop. Improvements never alert. Put projects on a schedule (project page or Portfolio) to watch them continuously.</p>
      <Channels admin={role === "admin"} />
      <div className="d-flex align-items-center gap-2 mb-2">
        <h2 className="h6 mb-0 me-auto">Alerts</h2>
        <div className="btn-group btn-group-sm">{(["open", "all"] as const).map((s) =>
          <button key={s} className={`btn ${status === s ? "btn-primary" : "btn-outline-primary"}`} onClick={() => setStatus(s)}>{s === "open" ? "Open" : "All"}</button>)}</div>
      </div>
      <ErrorBox error={err} />
      {!list ? <Loading /> : !list.length ? <Empty>{status === "open" ? "No open alerts. Posture has not regressed since the last scans." : "No alerts yet."}</Empty> :
        list.map((a) => (
          <div className="card mb-2" key={a.id}><div className="card-body">
            <div className="d-flex flex-wrap align-items-start gap-2">
              <SevBadge s={a.severity} />
              <div className="me-auto"><b>{a.title}</b>
                <div className="small text-secondary">{fmtDate(a.created_at)} · <Link href={`/project?id=${a.project_id}`}>{a.project}</Link> ·{" "}
                  <Link href={`/scan?id=${a.scan_id}`}>this scan</Link> vs <Link href={`/scan?id=${a.previous_scan_id}`}>previous</Link>
                  {a.deliveries.length > 0 && <> · sent to {a.deliveries.map((d) => `${d.channel} (${d.ok ? "ok" : d.detail})`).join(", ")}</>}</div></div>
              {a.acknowledged_at ? <span className="small text-secondary">Acknowledged by {a.acknowledged_by}</span> :
                canEdit(role) && <button className="btn btn-sm btn-outline-secondary" onClick={() => ack(a)}>Acknowledge</button>}
            </div>
            <ul className="small mb-0 mt-2">{a.items.map((i, n) => (
              <li key={n}><span className={`badge sev-${i.severity} me-1`}>{KIND_LABEL[i.kind] || i.kind}</span>
                {i.kind === "new_finding" && i.ref ? <Link href={`/scan?id=${a.scan_id}&finding=${i.ref}`}>{i.text}</Link> : i.text}</li>))}</ul>
          </div></div>))}
    </>
  );
}

export default function Page() { return <Shell><Body /></Shell>; }
