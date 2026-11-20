"use client";
import { PolicyDraft, TemplatesPanel } from "@/components/enterprise";
import { useEffect, useState } from "react";
import Shell, { canEdit, useMe } from "@/components/Shell";
import { Empty, ErrorBox, Loading, SevBadge } from "@/components/ui";
import { api, CATEGORIES } from "@/lib/api";

interface PolicyRow { id: string; policy_id: string; title: string; enabled: boolean; source: string; severity: string; category: string; target: string; updated_at: string }
interface PolicyList { policies: PolicyRow[]; examples: string[]; operators: string[]; fields: Record<string, Record<string, string>> }
interface TestResult { violations: number; scans: { scan_id: string; project: string; status: string; note: string; violations: { message: string; file: string; line: number | null; job: string }[] }[] }

const BLANK = `id: ORG-EXAMPLE-001
title: Describe what must (not) happen
severity: medium
category: CICD-SEC-5
target: job          # workflow | job | action
when:
  - {field: write_scopes, contains: contents}
message: "Job {id} in {workflow} can write repository contents"
remediation: Explain how to fix it.
`;

function Body() {
  const { role } = useMe();
  const admin = role === "admin";
  const [d, setD] = useState<PolicyList | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [editing, setEditing] = useState<PolicyRow | null>(null);
  const [source, setSource] = useState(BLANK);
  const [enabled, setEnabled] = useState(true);
  const [test, setTest] = useState<TestResult | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const load = () => api.get<PolicyList>("/api/policies").then(setD).catch((e) => setErr(e.message));
  useEffect(() => { load(); }, []);

  const edit = (p: PolicyRow | null, src?: string) => { setEditing(p); setSource(p ? p.source : src || BLANK); setEnabled(p ? p.enabled : true); setTest(null); setMsg(null); setErr(null); };
  const runTest = async () => {
    setBusy(true); setErr(null); setTest(null);
    try { setTest(await api.post<TestResult>("/api/policies/test", { source })); } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };
  const save = async () => {
    setBusy(true); setErr(null); setMsg(null);
    try {
      const r = editing
        ? await api.put<PolicyRow>(`/api/policies/${editing.id}`, { source, enabled })
        : await api.post<PolicyRow>("/api/policies", { source, enabled });
      setMsg(`Saved ${r.policy_id}. It is evaluated on every new scan.`);
      setEditing(r); load();
    } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };
  const toggle = async (p: PolicyRow) => { try { await api.put(`/api/policies/${p.id}`, { source: p.source, enabled: !p.enabled }); load(); } catch (e) { setErr((e as Error).message); } };
  const remove = async (p: PolicyRow) => {
    if (!confirm(`Delete policy ${p.policy_id}?`)) return;
    try { await api.del(`/api/policies/${p.id}`); if (editing?.id === p.id) edit(null); load(); } catch (e) { setErr((e as Error).message); }
  };

  if (!d) return err ? <ErrorBox error={err} /> : <Loading />;
  return (
    <>
      <h1 className="h4 mb-1">Policies</h1>
      <p className="text-secondary small mb-3">Your organization&apos;s own rules, written as short YAML. They run on every scan next to the 47 built-in controls,
        produce normal findings, count towards the posture score and appear in reports and compliance packs.</p>
      <PolicyDraft onUse={(src) => { edit(null); setSource(src); setTest(null); setTimeout(() => document.getElementById("policy-editor")?.scrollIntoView({ behavior: "smooth" }), 50); }} />
      <div className="card mb-3"><div className="card-body">
        <div className="d-flex justify-content-between align-items-center mb-2"><h2 className="h6 mb-0">Organization policies ({d.policies.length})</h2>
          {admin && <button className="btn btn-sm btn-primary" onClick={() => edit(null)}>New policy</button>}</div>
        {!d.policies.length ? <Empty>No policies yet. {admin ? "Start from an example below." : "Ask an admin to add one."}</Empty> : (
          <div className="table-responsive"><table className="table table-sm mb-0 align-middle">
            <thead><tr><th>ID</th><th>Title</th><th>Target</th><th>Severity</th><th>Category</th><th>Enabled</th><th /></tr></thead>
            <tbody>{d.policies.map((p) => (
              <tr key={p.id}>
                <td className="font-monospace small">{p.policy_id}</td><td>{p.title}</td><td>{p.target}</td><td><SevBadge s={p.severity} /></td>
                <td className="small">{p.category} · {CATEGORIES[p.category]}</td>
                <td><div className="form-check form-switch"><input className="form-check-input" type="checkbox" checked={p.enabled} disabled={!admin}
                  onChange={() => toggle(p)} aria-label={`Enable ${p.policy_id}`} /></div></td>
                <td className="text-nowrap"><button className="btn btn-sm btn-link" onClick={() => edit(p)}>{admin ? "Edit" : "View"}</button>
                  {admin && <button className="btn btn-sm btn-link text-danger" onClick={() => remove(p)}>Delete</button>}</td>
              </tr>
            ))}</tbody>
          </table></div>
        )}
      </div></div>

      <div className="row g-3">
        <div className="col-12 col-xl-7"><div className="card h-100"><div className="card-body">
          <div className="d-flex flex-wrap justify-content-between gap-2 align-items-center mb-2">
            <h2 className="h6 mb-0">{editing ? `Edit ${editing.policy_id}` : "New policy"}</h2>
            <div className="d-flex flex-wrap gap-1"><span className="small text-secondary me-1 align-self-center">Examples:</span>
              {d.examples.map((ex) => { const id = /id:\s*(\S+)/.exec(ex)?.[1] || "example"; return <button key={id} className="btn btn-sm btn-outline-secondary" onClick={() => edit(null, ex)}>{id}</button>; })}
            </div>
          </div>
          <textarea id="policy-editor" className="form-control code" rows={18} value={source} onChange={(e) => setSource(e.target.value)} readOnly={!admin && !!editing} spellCheck={false} aria-label="Policy YAML" />
          <div className="d-flex flex-wrap gap-2 align-items-center mt-2">
            {canEdit(role) && <button className="btn btn-sm btn-outline-primary" onClick={runTest} disabled={busy}>{busy ? "Working…" : "Validate & test on all projects"}</button>}
            {admin && <>
              <div className="form-check ms-2"><input id="en" className="form-check-input" type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
                <label className="form-check-label small" htmlFor="en">Enabled</label></div>
              <button className="btn btn-sm btn-primary" onClick={save} disabled={busy}>Save policy</button>
            </>}
          </div>
          <ErrorBox error={err} />
          {msg && <div className="alert alert-success py-2 mt-2 small">{msg}</div>}
          {test && <div className="mt-3">
            <div className="small mb-1"><b>{test.violations}</b> violation(s) across {test.scans.length} project(s) (latest scans; nothing is stored).</div>
            {test.scans.map((s) => (
              <details key={s.scan_id} className="mb-1" open={s.violations.length > 0 && test.scans.length <= 3}>
                <summary className="small">{s.project}: <b className={s.status === "FAIL" ? "text-danger" : s.status === "PASS" ? "text-success" : ""}>{s.status}</b> · {s.violations.length} violation(s)</summary>
                <ul className="small mb-0">{s.violations.map((v, i) => <li key={i}>{v.message} <span className="text-secondary">{v.file}{v.line ? `:${v.line}` : ""}</span></li>)}</ul>
              </details>
            ))}
          </div>}
        </div></div></div>
        <div className="col-12 col-xl-5"><div className="card h-100"><div className="card-body small">
          <h2 className="h6">Reference</h2>
          <p>A policy flags every <b>target</b> item where all <code>when</code> conditions hold and the <code>unless</code> conditions (optional) do not.
            Use <code>{"{field}"}</code> in <code>message</code> to insert values.</p>
          <p className="mb-1"><b>Operators:</b> {d.operators.map((o) => <code key={o} className="me-1">{o}</code>)}</p>
          <p className="text-secondary">Text comparisons ignore case. <code>contains</code> checks list membership for list fields and substrings for text.</p>
          {Object.entries(d.fields).map(([t, fs]) => (
            <div key={t} className="mb-2"><b>{t}</b>: {Object.entries(fs).map(([f, ty]) => <span key={f} className="me-2 d-inline-block"><code>{f}</code> <span className="text-secondary">{ty}</span></span>)}</div>
          ))}
        </div></div></div>
      </div>
      <TemplatesPanel />
    </>
  );
}

export default function Page() { return <Shell><Body /></Shell>; }
