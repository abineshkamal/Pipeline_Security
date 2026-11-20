"use client";
import { useEffect, useState } from "react";
import { canEdit, useMe } from "@/components/Shell";
import { TicketButton } from "@/components/analysis";
import { SevBadge } from "@/components/ui";
import { api, type Finding, type RiskException } from "@/lib/api";

const inDays = (n: number) => new Date(Date.now() + n * 864e5).toISOString().slice(0, 10);

function ExceptionRequest({ f }: { f: Finding }) {
  const [open, setOpen] = useState(false);
  const [b, setB] = useState({ scope: "finding", reason: "", compensating_controls: "", owner: "", expires_on: inDays(90) });
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  useEffect(() => { setOpen(false); setMsg(null); }, [f.id]);
  const ex = f.extra?.exception;
  if (ex) return (
    <div className="alert alert-warning small py-2 mb-2">Accepted under risk exception until <b>{ex.expires_on}</b> · owner {ex.owner} · approved by {ex.approved_by}.
      {" "}<a href="/exceptions">Manage exceptions</a>. The finding reopens automatically when the exception expires.</div>);
  const send = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const r = await api.post<RiskException>("/api/exceptions", { finding_id: f.id, ...b });
      setMsg({ ok: true, text: `Requested (${r.matched_findings} finding(s) covered). An admin other than you must approve it on the Exceptions page.` }); setOpen(false);
    } catch (x) { setMsg({ ok: false, text: (x as Error).message }); }
  };
  return (
    <div className="mt-2">
      {!open ? <button className="btn btn-sm btn-outline-warning" onClick={() => setOpen(true)}>Request risk exception…</button> : (
        <form onSubmit={send} className="border rounded p-2 row g-2 small">
          <div className="col-12 fw-semibold">Risk exception (time-boxed, needs a second person to approve)</div>
          <div className="col-12 col-md-6"><label className="form-label" htmlFor="xs">Covers</label>
            <select id="xs" className="form-select form-select-sm" value={b.scope} onChange={(e) => setB({ ...b, scope: e.target.value })}>
              <option value="finding">This finding only</option>
              {f.file_path && <option value="rule_in_workflow">All {f.rule_id} findings in {f.file_path}</option>}
              <option value="rule">All {f.rule_id} findings in this project</option></select></div>
          <div className="col-6 col-md-3"><label className="form-label" htmlFor="xo">Risk owner</label>
            <input id="xo" className="form-control form-control-sm" required minLength={2} placeholder="team or person" value={b.owner} onChange={(e) => setB({ ...b, owner: e.target.value })} /></div>
          <div className="col-6 col-md-3"><label className="form-label" htmlFor="xe">Expires on</label>
            <input id="xe" type="date" className="form-control form-control-sm" required min={inDays(1)} max={inDays(365)} value={b.expires_on} onChange={(e) => setB({ ...b, expires_on: e.target.value })} /></div>
          <div className="col-12"><label className="form-label" htmlFor="xr">Business justification</label>
            <textarea id="xr" className="form-control form-control-sm" rows={2} required minLength={10} value={b.reason} onChange={(e) => setB({ ...b, reason: e.target.value })} /></div>
          <div className="col-12"><label className="form-label" htmlFor="xc">Compensating controls (optional)</label>
            <input id="xc" className="form-control form-control-sm" value={b.compensating_controls} onChange={(e) => setB({ ...b, compensating_controls: e.target.value })} /></div>
          <div className="col-12 d-flex gap-2"><button className="btn btn-sm btn-warning">Submit request</button>
            <button type="button" className="btn btn-sm btn-link" onClick={() => setOpen(false)}>Cancel</button></div>
        </form>)}
      {msg && <div className={`small mt-1 ${msg.ok ? "text-success" : "text-danger"}`}>{msg.text}</div>}
    </div>
  );
}

/** Evidence, remediation, AI notes and triage form for one finding. Shared by the scan results and pipeline pages. */
export default function FindingDetail({ f, onSaved }: { f: Finding; onSaved: (f: Finding) => void }) {
  const { role } = useMe();
  const [triage, setTriage] = useState(f.triage_status);
  const [val, setVal] = useState(f.validation_status);
  const [note, setNote] = useState(f.triage_note);
  const [msg, setMsg] = useState<string | null>(null);
  // reset the form only when a different finding is selected (not when the saved copy comes back)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { setTriage(f.triage_status); setVal(f.validation_status); setNote(f.triage_note); setMsg(null); }, [f.id]);
  const save = async () => {
    try { onSaved(await api.patch<Finding>(`/api/findings/${f.id}`, { triage_status: triage, validation_status: val, triage_note: note })); setMsg("Saved"); }
    catch (x) { setMsg((x as Error).message); }
  };
  const t = f.ai_notes?.triage, fix = f.ai_notes?.fix;
  return (
    <div className={`card border-sev-${f.severity}`}><div className="card-body">
      <div className="d-flex gap-2 align-items-center flex-wrap mb-1"><SevBadge s={f.severity} /><span className="fw-semibold">{f.title}</span></div>
      <div className="small text-secondary mb-2">{f.rule_id} · {f.category} · risk {f.risk_score} · confidence {f.confidence} · evidence: {f.evidence_type}</div>
      <p className="mb-2">{f.message}</p>
      <div className="small mb-1">Location: <code className="text-break-all">{f.file_path}{f.line ? `:${f.line}` : ""}</code>{f.job && <> · job <code>{f.job}</code></>}</div>
      {f.snippet && <pre className="snippet mb-2">{f.snippet}</pre>}
      {f.extra?.exception && <ExceptionRequest f={f} />}
      {f.extra?.corroborated_by && <div className="small text-success mb-2">✔ Corroborated by: {f.extra.corroborated_by.join("; ")}</div>}
      {f.extra?.suggested_pin && <div className="small mb-2">Suggested pin: <code className="text-break-all">{f.extra.suggested_pin}</code></div>}
      {fix?.patch && <><div className="small text-secondary">Suggested change ({fix.source}):</div><pre className="snippet mb-2">{fix.patch}</pre></>}
      {fix?.explanation && <p className="small">{fix.explanation}</p>}
      {t && <div className="alert alert-secondary small py-2">AI triage ({t.source}): exploitability <b>{t.exploitability}</b>, priority <b>{t.priority}</b>, false-positive likelihood {t.false_positive_likelihood}. {t.rationale}</div>}
      <hr />
      <div className="row g-2">
        <div className="col-6"><label className="form-label small" htmlFor="tri">Triage</label>
          <select id="tri" className="form-select form-select-sm" value={triage} disabled={!canEdit(role)} onChange={(e) => setTriage(e.target.value)}>
            {["open", "confirmed", "false_positive", "accepted_risk", "fixed"].map((x) => <option key={x}>{x}</option>)}</select></div>
        <div className="col-6"><label className="form-label small" htmlFor="val">Validation</label>
          <select id="val" className="form-select form-select-sm" value={val} disabled={!canEdit(role)} onChange={(e) => setVal(e.target.value)}>
            {["unvalidated", "config_evidence", "needs_validation", "validated", "not_reproducible"].map((x) => <option key={x}>{x}</option>)}</select></div>
        <div className="col-12"><label className="form-label small" htmlFor="note">Analyst note</label>
          <textarea id="note" className="form-control form-control-sm" rows={2} value={note} disabled={!canEdit(role)} onChange={(e) => setNote(e.target.value)} /></div>
      </div>
      {canEdit(role) && <button className="btn btn-sm btn-primary mt-2" onClick={save}>Save triage</button>}
      {msg && <span className="small ms-2">{msg}</span>}
      {canEdit(role) && !f.extra?.exception && !["false_positive", "fixed"].includes(f.triage_status) && <ExceptionRequest f={f} />}
      <TicketButton f={f} />
    </div></div>
  );
}
