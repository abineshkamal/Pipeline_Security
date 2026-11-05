"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import Shell, { canEdit, useMe } from "@/components/Shell";
import { Empty, ErrorBox, Loading, StatusBadge } from "@/components/ui";
import { api, fmtDate, type Project } from "@/lib/api";

interface Cred { id: string; name: string; hint: string }

function NewProject({ onCreated }: { onCreated: () => void }) {
  const [f, setF] = useState({ name: "", description: "", source_type: "github", repo_full_name: "", ref: "", credential_id: "" });
  const [creds, setCreds] = useState<Cred[]>([]);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => { api.get<Cred[]>("/api/credentials").then(setCreds).catch(() => setCreds([])); }, []);
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setF({ ...f, [k]: e.target.value });
  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setErr(null);
    try {
      await api.post("/api/projects", { ...f, credential_id: f.credential_id || null });
      setF({ ...f, name: "", repo_full_name: "", description: "" });
      onCreated();
    } catch (x) { setErr((x as Error).message); }
  };
  return (
    <form className="card mb-4" onSubmit={submit}><div className="card-body">
      <h2 className="h6">New project</h2>
      <div className="row g-2">
        <div className="col-12 col-md-3"><label className="form-label small" htmlFor="pn">Name</label><input id="pn" className="form-control" required value={f.name} onChange={set("name")} /></div>
        <div className="col-12 col-md-2"><label className="form-label small" htmlFor="ps">Source</label>
          <select id="ps" className="form-select" value={f.source_type} onChange={set("source_type")}>
            <option value="github">GitHub Actions</option><option value="upload">ZIP upload (offline)</option>
          </select></div>
        {f.source_type === "github" && <>
          <div className="col-12 col-md-3"><label className="form-label small" htmlFor="pr">Repository (owner/repo)</label><input id="pr" className="form-control" required pattern="[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+" value={f.repo_full_name} onChange={set("repo_full_name")} /></div>
          <div className="col-6 col-md-2"><label className="form-label small" htmlFor="pref">Branch / ref</label><input id="pref" className="form-control" placeholder="default" value={f.ref} onChange={set("ref")} /></div>
          <div className="col-6 col-md-2"><label className="form-label small" htmlFor="pc">Credential</label>
            <select id="pc" className="form-select" value={f.credential_id} onChange={set("credential_id")}>
              <option value="">None (public)</option>{creds.map((c) => <option key={c.id} value={c.id}>{c.name} ({c.hint})</option>)}
            </select></div>
        </>}
      </div>
      {f.source_type === "github" && !f.credential_id && <div className="form-text">Without a token only public repositories can be scanned and repository settings (branch protection, token defaults) are mostly NOT ASSESSED.</div>}
      <ErrorBox error={err} />
      <button className="btn btn-primary mt-3">Create project</button>
    </div></form>
  );
}

function Body() {
  const { role } = useMe();
  const [ps, setPs] = useState<Project[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const load = () => api.get<Project[]>("/api/projects").then(setPs).catch((e) => setErr(e.message));
  useEffect(() => { load(); }, []);
  return (
    <>
      <h1 className="h4 mb-3">Projects</h1>
      {canEdit(role) && <NewProject onCreated={load} />}
      <ErrorBox error={err} />
      {!ps ? <Loading /> : !ps.length ? <Empty>No projects yet.</Empty> : (
        <div className="card"><div className="table-responsive"><table className="table mb-0">
          <thead><tr><th>Name</th><th>Source</th><th>Scans</th><th>Last scan</th><th>Score</th><th /></tr></thead>
          <tbody>{ps.map((p) => (
            <tr key={p.id}>
              <td><Link href={`/project?id=${p.id}`} className="fw-semibold">{p.name}</Link><div className="small text-secondary">{p.repo_full_name}</div></td>
              <td>{p.source_type === "github" ? "GitHub" : "ZIP upload"}</td><td>{p.scan_count}</td>
              <td>{p.last_scan ? <><StatusBadge s={p.last_scan.status} /> <span className="small text-secondary">{fmtDate(p.last_scan.created_at)}</span></> : "—"}</td>
              <td>{p.last_scan?.posture_score ?? "—"}</td>
              <td><Link href={`/project?id=${p.id}`}>Open</Link></td>
            </tr>
          ))}</tbody>
        </table></div></div>
      )}
    </>
  );
}

export default function Page() { return <Shell><Body /></Shell>; }
