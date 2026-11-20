"use client";
import { useEffect, useState } from "react";
import Shell, { canEdit, useMe } from "@/components/Shell";
import { ErrorBox, Loading } from "@/components/ui";
import { api, fmtDate, type TicketIntegration, type TicketLink } from "@/lib/api";
import { ApiTokens, SiemSinks } from "@/components/enterprise";

interface Member { user_id: string; email: string; full_name: string; role: string }
interface Cred { id: string; name: string; provider: string; hint: string; created_at: string }
interface Audit { id: number; at: string; user: string; action: string; target: string; details: Record<string, unknown>; ip: string }
interface Repo { full_name: string; private: boolean; default_branch: string; archived: boolean }

function Members() {
  const { role, me } = useMe();
  const [ms, setMs] = useState<Member[] | null>(null);
  const [f, setF] = useState({ email: "", full_name: "", password: "", role: "analyst" });
  const [err, setErr] = useState<string | null>(null);
  const load = () => api.get<Member[]>("/api/org/members").then(setMs);
  useEffect(() => { load(); }, []);
  const add = async (e: React.FormEvent) => {
    e.preventDefault(); setErr(null);
    try { await api.post("/api/org/members", f); setF({ email: "", full_name: "", password: "", role: "analyst" }); load(); } catch (x) { setErr((x as Error).message); }
  };
  const change = async (id: string, r: string) => { try { await api.patch(`/api/org/members/${id}`, { role: r }); load(); } catch (x) { setErr((x as Error).message); } };
  const remove = async (m: Member) => { if (confirm(`Remove ${m.email} from the organization?`)) { await api.del(`/api/org/members/${m.user_id}`); load(); } };
  if (!ms) return <Loading />;
  return (
    <div className="card mb-3"><div className="card-body">
      <h2 className="h6">Members</h2>
      <ErrorBox error={err} />
      <div className="table-responsive"><table className="table table-sm"><thead><tr><th>Email</th><th>Name</th><th>Role</th><th /></tr></thead><tbody>
        {ms.map((m) => <tr key={m.user_id}><td>{m.email}</td><td>{m.full_name}</td>
          <td>{role === "admin" && m.user_id !== me?.id ? (
            <select className="form-select form-select-sm" style={{ maxWidth: 140 }} value={m.role} onChange={(e) => change(m.user_id, e.target.value)} aria-label={`Role for ${m.email}`}>
              {["admin", "analyst", "viewer"].map((r) => <option key={r}>{r}</option>)}</select>) : m.role}</td>
          <td>{role === "admin" && m.user_id !== me?.id && <button className="btn btn-sm btn-outline-danger" onClick={() => remove(m)}>Remove</button>}</td></tr>)}
      </tbody></table></div>
      {role === "admin" && (
        <form className="row g-2" onSubmit={add}>
          <div className="col-12 col-md-3"><input className="form-control form-control-sm" type="email" placeholder="email" required value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} aria-label="Email" /></div>
          <div className="col-12 col-md-3"><input className="form-control form-control-sm" placeholder="full name" value={f.full_name} onChange={(e) => setF({ ...f, full_name: e.target.value })} aria-label="Full name" /></div>
          <div className="col-12 col-md-3"><input className="form-control form-control-sm" type="password" placeholder="initial password" required minLength={10} value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} aria-label="Initial password" /></div>
          <div className="col-6 col-md-2"><select className="form-select form-select-sm" value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })} aria-label="Role">
            {["admin", "analyst", "viewer"].map((r) => <option key={r}>{r}</option>)}</select></div>
          <div className="col-6 col-md-1"><button className="btn btn-sm btn-primary w-100">Add</button></div>
        </form>
      )}
    </div></div>
  );
}

function Credentials() {
  const { role } = useMe();
  const [cs, setCs] = useState<Cred[] | null>(null);
  const [f, setF] = useState({ name: "", secret: "" });
  const [err, setErr] = useState<string | null>(null);
  const [info, setInfo] = useState<Record<string, string>>({});
  const [repos, setRepos] = useState<{ cred: string; list: Repo[] } | null>(null);
  const load = () => api.get<Cred[]>("/api/credentials").then(setCs).catch(() => setCs([]));
  useEffect(() => { load(); }, []);
  const add = async (e: React.FormEvent) => {
    e.preventDefault(); setErr(null);
    try { await api.post("/api/credentials", { ...f, provider: "github" }); setF({ name: "", secret: "" }); load(); } catch (x) { setErr((x as Error).message); }
  };
  const test = async (c: Cred) => {
    try {
      const r = await api.post<{ valid: boolean; login?: string; token_type?: string; advice?: string }>(`/api/credentials/${c.id}/test`);
      setInfo({ ...info, [c.id]: r.valid ? `valid · ${r.login} · ${r.token_type} · ${r.advice}` : "invalid token" });
    } catch (x) { setInfo({ ...info, [c.id]: (x as Error).message }); }
  };
  const discover = async (c: Cred) => {
    try { setRepos({ cred: c.name, list: await api.get<Repo[]>(`/api/credentials/${c.id}/repos`) }); } catch (x) { setErr((x as Error).message); }
  };
  if (!canEdit(role)) return null;
  if (!cs) return <Loading />;
  return (
    <div className="card mb-3"><div className="card-body">
      <h2 className="h6">GitHub credentials</h2>
      <p className="small text-secondary">Tokens are encrypted at rest and never shown again. Use a fine-grained, <b>read-only</b> token (Contents, Metadata, Actions, Administration: read, Environments: read).</p>
      <ErrorBox error={err} />
      <table className="table table-sm"><tbody>{cs.map((c) => <tr key={c.id}><td>{c.name}</td><td className="font-monospace small">{c.hint}</td><td className="small">{fmtDate(c.created_at)}</td>
        <td className="text-end"><button className="btn btn-sm btn-outline-secondary me-1" onClick={() => test(c)}>Test</button>
          <button className="btn btn-sm btn-outline-secondary me-1" onClick={() => discover(c)}>Discover repos</button>
          {role === "admin" && <button className="btn btn-sm btn-outline-danger" onClick={async () => { if (confirm("Delete credential?")) { await api.del(`/api/credentials/${c.id}`); load(); } }}>Delete</button>}
          {info[c.id] && <div className="small text-secondary mt-1">{info[c.id]}</div>}</td></tr>)}</tbody></table>
      {role === "admin" && <form className="row g-2" onSubmit={add}>
        <div className="col-12 col-md-4"><input className="form-control form-control-sm" placeholder="name" required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} aria-label="Credential name" /></div>
        <div className="col-12 col-md-6"><input className="form-control form-control-sm" type="password" placeholder="github_pat_…" required minLength={8} autoComplete="off" value={f.secret} onChange={(e) => setF({ ...f, secret: e.target.value })} aria-label="Token" /></div>
        <div className="col-12 col-md-2"><button className="btn btn-sm btn-primary w-100">Save</button></div>
      </form>}
      {repos && <div className="mt-3"><h3 className="h6">Repositories visible to {repos.cred} ({repos.list.length})</h3>
        <div style={{ maxHeight: 260, overflowY: "auto" }}><table className="table table-sm small"><tbody>{repos.list.map((r) => <tr key={r.full_name}><td>{r.full_name}</td><td>{r.private ? "private" : "public"}</td><td>{r.default_branch}</td><td>{r.archived && "archived"}</td></tr>)}</tbody></table></div></div>}
    </div></div>
  );
}

function AuditLog() {
  const { role } = useMe();
  const [rows, setRows] = useState<Audit[] | null>(null);
  useEffect(() => { if (role === "admin") api.get<Audit[]>("/api/org/audit").then(setRows); }, [role]);
  if (role !== "admin") return null;
  if (!rows) return <Loading />;
  return (
    <div className="card"><div className="card-body">
      <h2 className="h6">Audit log</h2>
      <div className="table-responsive" style={{ maxHeight: 420 }}><table className="table table-sm small mb-0"><thead><tr><th>When</th><th>User</th><th>Action</th><th>Target</th><th>Details</th><th>IP</th></tr></thead><tbody>
        {rows.map((r) => <tr key={r.id}><td className="text-nowrap">{fmtDate(r.at)}</td><td>{r.user}</td><td><code>{r.action}</code></td><td className="text-break-all">{r.target}</td>
          <td className="text-secondary text-break-all">{JSON.stringify(r.details)}</td><td>{r.ip}</td></tr>)}
      </tbody></table></div>
    </div></div>
  );
}

function Ticketing() {
  const { role } = useMe();
  const admin = role === "admin";
  const empty = { name: "", kind: "jira", base_url: "", target: "", issue_type: "Bug", username: "", secret: "", close_action: "" };
  const [list, setList] = useState<TicketIntegration[] | null>(null);
  const [links, setLinks] = useState<TicketLink[]>([]);
  const [f, setF] = useState(empty);
  const [err, setErr] = useState<string | null>(null);
  const [res, setRes] = useState<Record<string, string>>({});
  const load = () => {
    api.get<TicketIntegration[]>("/api/integrations/tickets").then(setList).catch((e) => setErr(e.message));
    api.get<TicketLink[]>("/api/tickets").then(setLinks).catch(() => setLinks([]));
  };
  useEffect(() => { load(); }, []);
  const add = async (e: React.FormEvent) => {
    e.preventDefault(); setErr(null);
    try { await api.post("/api/integrations/tickets", f); setF(empty); load(); } catch (x) { setErr((x as Error).message); }
  };
  const test = async (i: TicketIntegration) => {
    setRes((r) => ({ ...r, [i.id]: "Testing…" }));
    try { const r = await api.post<{ ok: boolean; detail: string }>(`/api/integrations/tickets/${i.id}/test`); setRes((x) => ({ ...x, [i.id]: `${r.ok ? "OK" : "Failed"} · ${r.detail}` })); }
    catch (x) { setRes((r) => ({ ...r, [i.id]: (x as Error).message })); }
  };
  const del = async (i: TicketIntegration) => { if (confirm(`Remove ${i.name}? Tickets already created stay in ${i.kind}.`)) { await api.del(`/api/integrations/tickets/${i.id}`); load(); } };
  const jira = f.kind === "jira";
  return (
    <div className="card mb-3"><div className="card-body">
      <h2 className="h6">Ticketing (Jira / ServiceNow)</h2>
      <p className="small text-secondary">Open tickets from any finding. Tickets follow the finding across scans and are commented on and closed automatically when a scan no longer finds it;
        they reopen here if the finding comes back. Credentials are stored encrypted.</p>
      <ErrorBox error={err} />
      {list && list.length > 0 && <table className="table table-sm small align-middle">
        <thead><tr><th>Name</th><th>System</th><th>Target</th><th>Closes with</th><th /></tr></thead>
        <tbody>{list.map((i) => <tr key={i.id}><td><b>{i.name}</b>{res[i.id] && <div className="text-secondary">{res[i.id]}</div>}</td>
          <td>{i.kind === "jira" ? "Jira" : "ServiceNow"} <span className="text-secondary">{i.base_url}</span></td><td><code>{i.target}</code>{i.kind === "jira" && ` · ${i.issue_type}`}</td>
          <td>{i.close_action || <span className="text-secondary">comment only</span>}</td>
          <td className="text-nowrap">{admin && <><button className="btn btn-sm btn-outline-primary me-1" onClick={() => test(i)}>Test</button>
            <button className="btn btn-sm btn-link text-danger" onClick={() => del(i)}>Remove</button></>}</td></tr>)}</tbody></table>}
      {admin && <form onSubmit={add} className="row g-2 small align-items-end">
        <div className="col-6 col-md-2"><label className="form-label" htmlFor="tk">System</label><select id="tk" className="form-select form-select-sm" value={f.kind}
          onChange={(e) => setF({ ...f, kind: e.target.value, target: e.target.value === "jira" ? "" : "incident" })}><option value="jira">Jira</option><option value="servicenow">ServiceNow</option></select></div>
        <div className="col-6 col-md-2"><label className="form-label" htmlFor="tn">Name</label><input id="tn" className="form-control form-control-sm" required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></div>
        <div className="col-12 col-md-4"><label className="form-label" htmlFor="tu">Base URL</label><input id="tu" type="url" className="form-control form-control-sm" required
          placeholder={jira ? "https://your-site.atlassian.net" : "https://your-instance.service-now.com"} value={f.base_url} onChange={(e) => setF({ ...f, base_url: e.target.value })} /></div>
        <div className="col-6 col-md-2"><label className="form-label" htmlFor="tt">{jira ? "Project key" : "Table"}</label><input id="tt" className="form-control form-control-sm" required
          placeholder={jira ? "SEC" : "incident"} value={f.target} onChange={(e) => setF({ ...f, target: e.target.value })} /></div>
        {jira && <div className="col-6 col-md-2"><label className="form-label" htmlFor="ti">Issue type</label><input id="ti" className="form-control form-control-sm" value={f.issue_type} onChange={(e) => setF({ ...f, issue_type: e.target.value })} /></div>}
        <div className="col-6 col-md-3"><label className="form-label" htmlFor="tw">{jira ? "Account email" : "User"}</label><input id="tw" className="form-control form-control-sm" required value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} /></div>
        <div className="col-6 col-md-3"><label className="form-label" htmlFor="ts">{jira ? "API token" : "Password"}</label><input id="ts" type="password" autoComplete="new-password" className="form-control form-control-sm" required value={f.secret} onChange={(e) => setF({ ...f, secret: e.target.value })} /></div>
        <div className="col-6 col-md-3"><label className="form-label" htmlFor="tc">{jira ? "Close with transition (optional)" : "Close with state value (optional)"}</label>
          <input id="tc" className="form-control form-control-sm" placeholder={jira ? "Done" : "6"} value={f.close_action} onChange={(e) => setF({ ...f, close_action: e.target.value })} /></div>
        <div className="col-6 col-md-3"><button className="btn btn-sm btn-primary">Add integration</button></div>
      </form>}
      {links.length > 0 && <><h3 className="h6 mt-3">Tickets ({links.filter((l) => l.status === "open").length} open)</h3>
        <div className="table-responsive" style={{ maxHeight: 300 }}><table className="table table-sm small mb-0">
          <thead><tr><th>Ticket</th><th>Project</th><th>Finding</th><th>Status</th><th>Last sync</th></tr></thead>
          <tbody>{links.map((l) => <tr key={l.id}><td><a href={l.url} target="_blank" rel="noreferrer">{l.key}</a></td><td>{l.project}</td><td>{l.rule_id} {l.title}</td>
            <td><span className={`badge ${l.status === "open" ? "bg-warning text-dark" : "bg-success"}`}>{l.status}</span></td><td className="text-secondary">{l.sync_detail || fmtDate(l.created_at)}</td></tr>)}</tbody>
        </table></div></>}
    </div></div>
  );
}

export default function Page() {
  return <Shell><h1 className="h4 mb-3">Settings</h1><Members /><Credentials /><ApiTokens /><Ticketing /><SiemSinks /><AuditLog /></Shell>;
}

