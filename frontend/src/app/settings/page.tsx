"use client";
import { useEffect, useState } from "react";
import Shell, { canEdit, useMe } from "@/components/Shell";
import { ErrorBox, Loading } from "@/components/ui";
import { api, fmtDate } from "@/lib/api";

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

export default function Page() {
  return <Shell><h1 className="h4 mb-3">Settings</h1><Members /><Credentials /><AuditLog /></Shell>;
}
