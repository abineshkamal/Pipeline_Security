"use client";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { api, setOrg, setToken } from "@/lib/api";

export default function Register() {
  const router = useRouter();
  const [f, setF] = useState({ email: "", password: "", full_name: "", organization_name: "" });
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value });

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setErr(null);
    try {
      const r = await api.post<{ access_token: string }>("/api/auth/register", f);
      setToken(r.access_token); setOrg(null);
      router.replace("/dashboard");
    } catch (x) { setErr((x as Error).message); } finally { setBusy(false); }
  };

  return (
    <div className="auth-wrap">
      <div className="card auth-card shadow-sm">
        <div className="card-body p-4">
          <h1 className="h4 fw-bold mb-1">Create organization</h1>
          <p className="text-secondary small mb-4">You become the organization admin.</p>
          <form onSubmit={submit}>
            <label className="form-label small" htmlFor="org">Organization name</label>
            <input id="org" className="form-control mb-3" required minLength={2} value={f.organization_name} onChange={set("organization_name")} />
            <label className="form-label small" htmlFor="name">Your name</label>
            <input id="name" className="form-control mb-3" value={f.full_name} onChange={set("full_name")} />
            <label className="form-label small" htmlFor="email">Email</label>
            <input id="email" className="form-control mb-3" type="email" autoComplete="username" required value={f.email} onChange={set("email")} />
            <label className="form-label small" htmlFor="pw">Password</label>
            <input id="pw" className="form-control mb-1" type="password" autoComplete="new-password" required minLength={10} value={f.password} onChange={set("password")} />
            <div className="form-text mb-3">At least 10 characters with 3 of: lowercase, uppercase, digit, symbol.</div>
            {err && <div className="alert alert-danger py-2 small">{err}</div>}
            <button className="btn btn-primary w-100" disabled={busy}>{busy ? "Creating…" : "Create account"}</button>
          </form>
          <p className="small mt-3 mb-0 text-center">Have an account? <Link href="/login">Sign in</Link></p>
        </div>
      </div>
    </div>
  );
}
