"use client";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { api, setOrg, setToken } from "@/lib/api";

export default function Login() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setErr(null);
    try {
      const r = await api.post<{ access_token: string }>("/api/auth/login", { email, password });
      setToken(r.access_token); setOrg(null);
      router.replace("/dashboard");
    } catch (x) { setErr((x as Error).message); } finally { setBusy(false); }
  };

  return (
    <div className="auth-wrap">
      <div className="card auth-card shadow-sm">
        <div className="card-body p-4">
          <h1 className="h4 fw-bold mb-1">◆ PipelineTrust</h1>
          <p className="text-secondary small mb-4">AI-Powered CI/CD Security Assurance</p>
          <form onSubmit={submit}>
            <label className="form-label small" htmlFor="email">Email</label>
            <input id="email" className="form-control mb-3" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} />
            <label className="form-label small" htmlFor="pw">Password</label>
            <input id="pw" className="form-control mb-3" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
            {err && <div className="alert alert-danger py-2 small">{err}</div>}
            <button className="btn btn-primary w-100" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
          </form>
          <p className="small mt-3 mb-0 text-center">New here? <Link href="/register">Create an organization</Link></p>
        </div>
      </div>
    </div>
  );
}
