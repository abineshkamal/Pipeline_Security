"use client";
import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import Shell, { canEdit, useMe } from "@/components/Shell";
import { Empty, ErrorBox, Loading } from "@/components/ui";
import { api, fmtDate } from "@/lib/api";

interface Rule { rule_id: string; label: string }
interface Cand { project_id: string; name: string; repo: string; source_type: string; scan_id: string; findings: number; files: number; eligible: boolean }
interface Item { id: string; project_id: string; project: string; scan_id: string; status: string; findings: number; fixes_applied: number; files: number; needs_review: number;
  pr_url: string; pr_number: number | null; detail: string; remaining: number | null; updated_at: string }
interface Camp { id: string; name: string; rule_ids: string[]; dry_run: boolean; status: string; created_by: string; created_at: string; projects: number;
  by_status: Record<string, number>; fixes_applied: number; remaining: number; items?: Item[] }
interface Cred { id: string; name: string; hint: string }

const ST: Record<string, [string, string]> = { pending: ["bg-secondary", "Pending"], planned: ["bg-info text-dark", "Ready (dry run)"], no_changes: ["bg-light text-dark border", "Nothing to fix"],
  pr_open: ["bg-primary", "PR open"], merged: ["bg-success", "Merged"], closed: ["bg-dark", "Closed"], failed: ["bg-danger", "Failed"] };

function NewCampaign({ onCreated }: { onCreated: (id: string) => void }) {
  const [rules, setRules] = useState<Rule[]>([]);
  const [sel, setSel] = useState<string[]>(["PT-3P-001"]);
  const [cands, setCands] = useState<Cand[] | null>(null);
  const [picked, setPicked] = useState<string[]>([]);
  const [creds, setCreds] = useState<Cred[]>([]);
  const [f, setF] = useState({ name: "Pin third-party actions", credential_id: "", dry_run: true });
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => { api.get<Rule[]>("/api/campaigns/rules").then(setRules); api.get<Cred[]>("/api/credentials").then(setCreds).catch(() => setCreds([])); }, []);
  useEffect(() => {
    if (!sel.length) { setCands([]); return; }
    setCands(null);
    api.get<Cand[]>(`/api/campaigns/candidates?rule_ids=${sel.join(",")}`).then((c) => { setCands(c); setPicked(c.filter((x) => x.eligible).map((x) => x.project_id)); }).catch((e) => setErr(e.message));
  }, [sel]);
  const go = async () => {
    setErr(null);
    try {
      const c = await api.post<Camp>("/api/campaigns", { name: f.name, rule_ids: sel, project_ids: picked, credential_id: f.credential_id || null, dry_run: f.dry_run });
      onCreated(c.id);
    } catch (x) { setErr((x as Error).message); }
  };
  return (
    <div className="card mb-3"><div className="card-body">
      <h2 className="h6">New campaign</h2>
      <div className="d-flex flex-wrap gap-3 mb-2 small">{rules.map((r) => <div className="form-check" key={r.rule_id}>
        <input id={r.rule_id} type="checkbox" className="form-check-input" checked={sel.includes(r.rule_id)} onChange={(e) => setSel(e.target.checked ? [...sel, r.rule_id] : sel.filter((x) => x !== r.rule_id))} />
        <label htmlFor={r.rule_id} className="form-check-label"><b>{r.rule_id}</b> {r.label}</label></div>)}</div>
      {!cands ? <Loading /> : !cands.length ? <div className="small text-secondary mb-2">No project has open findings for these rules.</div> : (
        <div className="table-responsive mb-2" style={{ maxHeight: 260 }}><table className="table table-sm small mb-0">
          <thead><tr><th><input type="checkbox" className="form-check-input" aria-label="Select all" checked={picked.length === cands.filter((c) => c.eligible).length}
            onChange={(e) => setPicked(e.target.checked ? cands.filter((c) => c.eligible).map((c) => c.project_id) : [])} /></th><th>Project</th><th>Findings</th><th>Files</th></tr></thead>
          <tbody>{cands.map((c) => <tr key={c.project_id} className={c.eligible ? "" : "text-secondary"}>
            <td><input type="checkbox" className="form-check-input" aria-label={`Include ${c.name}`} disabled={!c.eligible && !f.dry_run} checked={picked.includes(c.project_id)}
              onChange={(e) => setPicked(e.target.checked ? [...picked, c.project_id] : picked.filter((x) => x !== c.project_id))} /></td>
            <td>{c.name} <span className="text-secondary">{c.repo || "(ZIP - dry run only)"}</span></td><td>{c.findings}</td><td>{c.files}</td></tr>)}</tbody>
        </table></div>)}
      <div className="row g-2 small align-items-end">
        <div className="col-12 col-md-4"><label className="form-label" htmlFor="cn">Name (also the PR title)</label><input id="cn" className="form-control form-control-sm" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></div>
        <div className="col-12 col-md-4"><label className="form-label" htmlFor="cc">Write token (Contents + Pull requests: write)</label>
          <select id="cc" className="form-select form-select-sm" value={f.credential_id} disabled={f.dry_run} onChange={(e) => setF({ ...f, credential_id: e.target.value })}>
            <option value="">Choose…</option>{creds.map((c) => <option key={c.id} value={c.id}>{c.name} ({c.hint})</option>)}</select></div>
        <div className="col-6 col-md-2"><div className="form-check"><input id="dr" type="checkbox" className="form-check-input" checked={f.dry_run} onChange={(e) => setF({ ...f, dry_run: e.target.checked })} />
          <label htmlFor="dr" className="form-check-label">Dry run (no PRs)</label></div></div>
        <div className="col-6 col-md-2"><button className="btn btn-sm btn-primary w-100" disabled={!picked.length || !sel.length || (!f.dry_run && !f.credential_id)} onClick={go}>
          {f.dry_run ? "Plan" : `Open ${picked.length} PR(s)`}</button></div>
      </div>
      <ErrorBox error={err} />
    </div></div>
  );
}

function Detail({ id, onBack }: { id: string; onBack: () => void }) {
  const { role } = useMe();
  const [c, setC] = useState<Camp | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const load = useCallback(() => { api.get<Camp>(`/api/campaigns/${id}`).then(setC).catch((e) => setErr(e.message)); }, [id]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => { if (c?.status !== "running") return; const t = setInterval(load, 2500); return () => clearInterval(t); }, [c, load]);
  const refresh = async () => { setC(await api.post<Camp>(`/api/campaigns/${id}/refresh`)); };
  if (err) return <ErrorBox error={err} />;
  if (!c) return <Loading />;
  const done = (c.by_status.merged || 0), total = c.items?.filter((i) => i.status !== "no_changes").length || 0;
  return (
    <div className="card mb-3"><div className="card-body">
      <div className="d-flex flex-wrap align-items-center gap-2 mb-2">
        <button className="btn btn-sm btn-link px-0" onClick={onBack}>← All campaigns</button>
        <h2 className="h6 mb-0 me-auto">{c.name} <span className="text-secondary fw-normal small">· {c.rule_ids.join(", ")}{c.dry_run ? " · dry run" : ""} · {c.status}</span></h2>
        {canEdit(role) && !c.dry_run && <button className="btn btn-sm btn-outline-primary" onClick={refresh}>Refresh PR status</button>}
      </div>
      {!c.dry_run && total > 0 && <div className="progress mb-2" role="progressbar" aria-label="Merged pull requests" aria-valuenow={done} aria-valuemax={total}>
        <div className="progress-bar bg-success" style={{ width: `${(100 * done) / total}%` }}>{done}/{total} merged</div></div>}
      <div className="table-responsive"><table className="table table-sm small align-middle mb-0">
        <thead><tr><th>Project</th><th>Status</th><th>Fixes</th><th>Needs review</th><th>Pull request</th><th>Still open after re-scan</th><th>Detail</th></tr></thead>
        <tbody>{c.items?.map((i) => <tr key={i.id}>
          <td><Link href={`/project?id=${i.project_id}`}>{i.project}</Link></td><td><span className={`badge ${ST[i.status]?.[0]}`}>{ST[i.status]?.[1] || i.status}</span></td>
          <td>{i.fixes_applied ? `${i.fixes_applied} in ${i.files} file(s)` : "—"}</td><td>{i.needs_review || "—"}</td>
          <td>{i.pr_url ? <a href={i.pr_url} target="_blank" rel="noreferrer">#{i.pr_number}</a> : "—"}</td>
          <td>{i.remaining ?? "—"}</td><td className="text-secondary">{i.detail}</td></tr>)}</tbody>
      </table></div>
    </div></div>
  );
}

function Body() {
  const { role } = useMe();
  const [list, setList] = useState<Camp[] | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const load = () => api.get<Camp[]>("/api/campaigns").then(setList);
  useEffect(() => { load(); }, []);
  return (
    <>
      <h1 className="h4 mb-1">Fix campaigns</h1>
      <p className="text-secondary small mb-3">Roll one automatic fix out to every affected repository as verified pull requests, then follow them to merge. Each PR contains
        only fixes that passed re-verification; re-scans confirm the findings are gone. Start with a dry run to see what each repository would get.</p>
      {open ? <Detail id={open} onBack={() => { setOpen(null); load(); }} /> : <>
        {role === "admin" && <NewCampaign onCreated={(id) => { setOpen(id); load(); }} />}
        <div className="card"><div className="card-body">
          <h2 className="h6">Campaigns</h2>
          {!list ? <Loading /> : !list.length ? <Empty>No campaigns yet.</Empty> : <table className="table table-sm small align-middle mb-0">
            <thead><tr><th>Name</th><th>Rules</th><th>Projects</th><th>Progress</th><th>Created</th></tr></thead>
            <tbody>{list.map((c) => <tr key={c.id} className="finding-row" onClick={() => setOpen(c.id)}>
              <td><b>{c.name}</b>{c.dry_run && <span className="badge bg-info text-dark ms-1">dry run</span>}</td><td>{c.rule_ids.join(", ")}</td><td>{c.projects}</td>
              <td>{Object.entries(c.by_status).filter(([, n]) => n).map(([k, n]) => <span key={k} className={`badge me-1 ${ST[k][0]}`}>{n} {ST[k][1].toLowerCase()}</span>)}</td>
              <td>{fmtDate(c.created_at)} · {c.created_by}</td></tr>)}</tbody></table>}
        </div></div>
      </>}
    </>
  );
}

export default function Page() { return <Shell><Body /></Shell>; }
