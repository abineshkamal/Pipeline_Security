"use client";
import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import Shell, { canEdit, useMe } from "@/components/Shell";
import { Empty, ErrorBox, Loading } from "@/components/ui";
import { api, fmtDate, type RiskException } from "@/lib/api";

const STATES = ["pending", "active", "expired", "rejected", "revoked", "all"] as const;
const STATE_CLS: Record<string, string> = { pending: "bg-info text-dark", active: "bg-warning text-dark", expired: "bg-secondary", rejected: "bg-danger", revoked: "bg-secondary" };

function Body() {
  const { role, me } = useMe();
  const [st, setSt] = useState<(typeof STATES)[number]>("pending");
  const [list, setList] = useState<RiskException[] | null>(null);
  const [all, setAll] = useState<RiskException[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [notes, setNotes] = useState<Record<string, string>>({});
  const load = useCallback(() => {
    api.get<RiskException[]>("/api/exceptions").then((x) => { setAll(x); setList(st === "all" ? x : x.filter((e) => e.state === st)); }).catch((e) => setErr(e.message));
  }, [st]);
  useEffect(() => { load(); }, [load]);
  const act = async (e: RiskException, what: "approve" | "reject" | "revoke") => {
    setErr(null);
    try {
      if (what === "revoke") { if (!confirm("Revoke this exception? Covered findings reopen.")) return; await api.post(`/api/exceptions/${e.id}/revoke`); }
      else await api.post(`/api/exceptions/${e.id}/decision`, { decision: what, note: notes[e.id] || "" });
      load();
    } catch (x) { setErr((x as Error).message); }
  };
  const count = (s: string) => s === "all" ? all.length : all.filter((e) => e.state === s).length;
  const soon = all.filter((e) => e.expiring_soon);
  return (
    <>
      <h1 className="h4 mb-1">Risk exceptions</h1>
      <p className="text-secondary small mb-3">Accepting a risk needs a justification, a risk owner, an expiry date (at most a year) and approval by an admin other than the requester.
        While active, covered findings are marked <i>accepted risk</i> on every new scan; when the exception expires or is revoked they reopen. Exceptions do not change the
        posture score: the weakness is still there. Request one from any finding&apos;s detail panel.</p>
      {soon.length > 0 && <div className="alert alert-warning small py-2">{soon.length} active exception(s) expire within 14 days: {soon.map((e) => `${e.rule_id} in ${e.project} (${e.expires_on})`).join(", ")}.</div>}
      <ul className="nav nav-tabs mb-3">{STATES.map((s) => (
        <li className="nav-item" key={s}><button className={`nav-link ${st === s ? "active" : ""}`} onClick={() => setSt(s)}>
          {s[0].toUpperCase() + s.slice(1)} <span className="badge bg-secondary">{count(s)}</span></button></li>))}</ul>
      <ErrorBox error={err} />
      {!list ? <Loading /> : !list.length ? <Empty>No {st === "all" ? "" : st} exceptions.</Empty> : list.map((e) => {
        const own = me?.email === e.requested_by;
        return (
          <div className="card mb-2" key={e.id}><div className="card-body">
            <div className="d-flex flex-wrap gap-2 align-items-start">
              <span className={`badge ${STATE_CLS[e.state]}`}>{e.state}</span>
              <div className="me-auto"><b>{e.title}</b>
                <div className="small text-secondary"><Link href={`/project?id=${e.project_id}`}>{e.project}</Link> · {e.matched_findings} finding(s) in the latest scan ·
                  owner <b>{e.owner}</b> · expires {e.expires_on}{e.days_left != null && ` (${e.days_left} day(s))`}</div></div>
              {e.expiring_soon && <span className="badge bg-warning text-dark">expires soon</span>}
            </div>
            <div className="small mt-2"><b>Justification:</b> {e.reason}</div>
            {e.compensating_controls && <div className="small"><b>Compensating controls:</b> {e.compensating_controls}</div>}
            <div className="small text-secondary mt-1">Requested by {e.requested_by} on {fmtDate(e.requested_at)}
              {e.decided_by && <> · {e.status === "rejected" ? "rejected" : "approved"} by {e.decided_by} on {fmtDate(e.decided_at)}{e.decision_note && `: “${e.decision_note}”`}</>}</div>
            {e.state === "pending" && role === "admin" && (own ? <div className="small text-secondary mt-2">You requested this one; another admin must decide (four-eyes rule).</div> : (
              <div className="d-flex flex-wrap gap-2 mt-2">
                <input className="form-control form-control-sm w-auto flex-grow-1" placeholder="Decision note (optional)" aria-label="Decision note"
                  value={notes[e.id] || ""} onChange={(x) => setNotes({ ...notes, [e.id]: x.target.value })} />
                <button className="btn btn-sm btn-success" onClick={() => act(e, "approve")}>Approve</button>
                <button className="btn btn-sm btn-outline-danger" onClick={() => act(e, "reject")}>Reject</button>
              </div>))}
            {(e.state === "pending" || e.state === "active") && canEdit(role) && (role === "admin" || own) &&
              <button className="btn btn-sm btn-link text-danger px-0 mt-1" onClick={() => act(e, "revoke")}>Revoke</button>}
          </div></div>
        );
      })}
    </>
  );
}

export default function Page() { return <Shell><Body /></Shell>; }
