"use client";
import Link from "next/link";
import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { canEdit, useMe } from "@/components/Shell";
import { Empty, ErrorBox, Loading, SevBadge, StatusBadge } from "@/components/ui";
import {
  api, pipelineHref, type AskAnswer, type CompliancePack, type FixPlan, type Recommendations, type SecretsMap, type WhatIf,
} from "@/lib/api";

const LEVEL_TEXT: Record<string, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
const REACH_TEXT: Record<string, string> = { outsiders: "Outsiders", contributors: "Contributors", maintainers: "Maintainers / schedule" };

function Delta({ v, invert = false }: { v: number | null | undefined; invert?: boolean }) {
  if (v == null || v === 0) return <span className="text-secondary">±0</span>;
  const good = invert ? v < 0 : v > 0;
  return <span className={good ? "delta-up" : "delta-down"}>{v > 0 ? "+" : ""}{v}</span>;
}

// ------------------------------------------------------------------ secrets

const ROT_CLS: Record<string, string> = { stale: "bg-danger", aging: "bg-warning text-dark", ok: "bg-success", missing: "bg-secondary", unknown: "bg-light text-dark border", automatic: "bg-light text-dark border" };
const ROT_TEXT: Record<string, string> = { stale: "Stale", aging: "Aging", ok: "Recent", missing: "Not defined", unknown: "Unknown", automatic: "Automatic" };
function RotationBadge({ r }: { r: SecretsMap["secrets"][number]["rotation"] }) {
  return <span className={`badge ${ROT_CLS[r.status]}`} title={r.detail}>{ROT_TEXT[r.status]}{r.age_days != null ? ` · ${r.age_days}d` : ""}</span>;
}

export function SecretsPanel({ scanId, pipeline }: { scanId: string; pipeline?: string }) {
  const [d, setD] = useState<SecretsMap | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  useEffect(() => {
    setD(null);
    api.get<SecretsMap>(`/api/scans/${scanId}/secrets${pipeline ? `?pipeline=${encodeURIComponent(pipeline)}` : ""}`).then(setD).catch((e) => setErr(e.message));
  }, [scanId, pipeline]);
  if (err) return <ErrorBox error={err} />;
  if (!d) return <Loading />;
  if (!d.secrets.length) return <Empty>{pipeline ? "This pipeline references no secrets." : "No workflow references any secrets."}</Empty>;
  return (
    <>
      <div className="d-flex flex-wrap gap-2 align-items-center mb-2 small">
        <span className="text-secondary">{d.secrets.length} secret(s){pipeline ? " used by this pipeline" : ""}:</span>
        {(["critical", "high", "medium", "low"] as const).filter((k) => d.secrets.some((s) => s.level === k)).map((k) =>
          <span key={k} className={`badge lvl-${k}`}>{d.secrets.filter((s) => s.level === k).length} {k}</span>)}
        {d.secrets.some((s) => s.reach === "outsiders") && <span className="text-danger fw-semibold ms-2">{d.secrets.filter((s) => s.reach === "outsiders").length} reachable by outsiders</span>}
      </div>
      {d.rotation?.rotate_first.length > 0 && <div className="alert alert-danger small py-2"><b>Rotate first:</b> {d.rotation.rotate_first.map((n) => <code key={n} className="me-2">{n}</code>)}
        - highly exposed and not rotated in {d.rotation.aging_days}+ days.</div>}
      {d.rotation && d.rotation.status !== "ok" && <div className="small text-secondary mb-2">Rotation dates: {d.rotation.detail || d.rotation.status}.
        {d.rotation.status !== "skipped" && " Give the project a token with the Secrets: read permission (names and dates only; values are never readable) and re-scan."}</div>}
      <div className="alert alert-secondary small py-2">Fork pull requests (<code>pull_request</code>) get no secrets. Privileged triggers such as <code>pull_request_target</code>, <code>issue_comment</code>, <code>issues</code> and <code>workflow_run</code> run with secrets on input from anyone, so those secrets are reachable by outsiders. A protected environment lowers the exposure.</div>
      <div className="card"><div className="table-responsive"><table className="table table-sm mb-0 align-middle">
        <thead><tr><th>Secret</th><th>Exposure</th><th>Who can reach it</th><th>Last rotated</th><th>Pipelines</th><th>Jobs</th><th>Attack paths</th><th /></tr></thead>
        <tbody>{d.secrets.map((s) => (
          <Fragment key={s.name}>
            <tr className="finding-row" onClick={() => setOpen(open === s.name ? null : s.name)}>
              <td><code>{s.name}</code></td>
              <td><span className={`badge lvl-${s.level}`}>{LEVEL_TEXT[s.level]}</span></td>
              <td className={s.reach === "outsiders" ? "text-danger fw-semibold" : ""}>{REACH_TEXT[s.reach]}</td>
              <td>{s.rotation && <RotationBadge r={s.rotation} />}{s.rotate_first && <span className="badge bg-danger ms-1">rotate first</span>}</td>
              <td>{s.pipelines}</td><td>{s.jobs}</td><td>{s.attack_paths || "—"}</td>
              <td className="small text-secondary">{open === s.name ? "▲" : "▼"}</td>
            </tr>
            {open === s.name && <tr><td colSpan={8} className="bg-body-tertiary">
              {s.rotation && <div className="small mb-1"><b>Rotation:</b> {s.rotation.detail}</div>}
              <table className="table table-sm mb-0 small">
                <thead><tr><th>Pipeline / job</th><th>Triggers</th><th>Reach</th><th>Environment</th><th>Code next to the secret</th></tr></thead>
                <tbody>{s.uses.map((u) => (
                  <tr key={`${u.workflow}#${u.job}`}>
                    <td><Link href={pipelineHref(scanId, u.workflow)}>{u.workflow_name}</Link> / <code>{u.job}</code>
                      {u.self_hosted && <span className="badge bg-danger ms-1">self-hosted</span>}
                      {u.write_scopes.length > 0 && <span className="badge bg-warning text-dark ms-1">write: {u.write_scopes.join(",")}</span>}</td>
                    <td>{u.triggers.join(", ")}</td>
                    <td><span className={`badge lvl-${u.level} me-1`}>{u.level}</span>{u.reach_reason}</td>
                    <td>{u.environment ? <span className="badge bg-info text-dark">{u.environment}</span> : <span className="text-secondary">none</span>}</td>
                    <td>{u.exposing_findings.length ? u.exposing_findings.map((f) => (
                      <div key={f.id}><SevBadge s={f.severity} /> {f.title}{f.line ? ` (line ${f.line})` : ""}</div>)) : <span className="text-secondary">none found</span>}</td>
                  </tr>
                ))}</tbody>
              </table>
            </td></tr>}
          </Fragment>
        ))}</tbody>
      </table></div></div>
    </>
  );
}

// ------------------------------------------------------------------ remediation: what-if + fixes

function DiffView({ diff }: { diff: string }) {
  return <pre className="diff">{diff.split("\n").map((l, i) => (
    <span key={i} className={l.startsWith("@@") ? "hunk" : l.startsWith("+") && !l.startsWith("+++") ? "add" : l.startsWith("-") && !l.startsWith("---") ? "del" : ""}>{l || " "}</span>
  ))}</pre>;
}

function Simulator({ scanId, selected, setSelected, rec }: { scanId: string; selected: Set<string>; setSelected: (s: Set<string>) => void; rec: Recommendations }) {
  const [w, setW] = useState<WhatIf | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      api.post<WhatIf>(`/api/scans/${scanId}/whatif`, { finding_ids: Array.from(selected) }).then(setW).catch(() => setW(null));
    }, 250);
  }, [scanId, selected]);
  const toggle = (ids: string[]) => {
    const all = ids.every((i) => selected.has(i));
    const n = new Set(selected);
    ids.forEach((i) => (all ? n.delete(i) : n.add(i)));
    setSelected(n);
  };
  const b = w?.before, a = w?.after;
  return (
    <>
      <div className="row g-3 mb-3">
        <div className="col-12 col-lg-5"><div className="card h-100"><div className="card-body">
          <h2 className="h6">What-if result</h2>
          {!w ? <Loading /> : <>
            <table className="table table-sm mb-2"><thead><tr><th /><th>Now</th><th>After fixes</th><th>Change</th></tr></thead><tbody>
              <tr><td>Posture score</td><td>{b?.posture_score ?? "N/A"} ({b?.grade})</td><td className="fw-bold">{a?.posture_score ?? "N/A"} ({a?.grade})</td><td><Delta v={w.score_delta} /></td></tr>
              <tr><td>Attack paths</td><td>{b?.attack_paths}</td><td className="fw-bold">{a?.attack_paths}</td><td><Delta v={(a?.attack_paths ?? 0) - (b?.attack_paths ?? 0)} invert /></td></tr>
              <tr><td>Findings</td><td>{b?.findings}</td><td className="fw-bold">{a?.findings}</td><td><Delta v={(a?.findings ?? 0) - (b?.findings ?? 0)} invert /></td></tr>
              <tr><td>Controls passing</td><td colSpan={2} /><td><Delta v={a?.controls_fixed.length ?? 0} /></td></tr>
            </tbody></table>
            <div className="small text-secondary">{selected.size} finding(s) marked as fixed{w.removed_paths.length > 0 && <> · removes {w.removed_paths.join(", ")}</>}</div>
            {selected.size > 0 && <button className="btn btn-sm btn-outline-secondary mt-2" onClick={() => setSelected(new Set())}>Clear selection</button>}
          </>}
        </div></div></div>
        <div className="col-12 col-lg-7"><div className="card h-100"><div className="card-body">
          <h2 className="h6">Biggest wins: fix a whole rule</h2>
          <div className="table-responsive" style={{ maxHeight: 300 }}><table className="table table-sm small mb-0 align-middle">
            <thead className="sticky-top"><tr><th /><th>Rule</th><th>Findings</th><th>Paths removed</th><th>Score</th><th /></tr></thead>
            <tbody>{rec.by_rule.map((r) => (
              <tr key={r.rule_id}>
                <td><input type="checkbox" className="form-check-input" aria-label={`Simulate fixing ${r.rule_id}`}
                  checked={r.finding_ids.every((i) => selected.has(i))} onChange={() => toggle(r.finding_ids)} /></td>
                <td><div className="fw-semibold">{r.title}</div><div className="text-secondary">{r.rule_id}</div></td>
                <td>{r.findings}</td><td>{r.paths_removed || "—"}</td><td><Delta v={r.score_gain} /></td>
                <td>{r.auto_fixable && <span className="badge bg-success">auto-fix</span>}</td>
              </tr>
            ))}</tbody>
          </table></div>
        </div></div></div>
      </div>
      {rec.single_fixes.length > 0 && <div className="card mb-3"><div className="card-body">
        <h2 className="h6">Single fixes that break the most attack paths</h2>
        <div className="table-responsive"><table className="table table-sm small mb-0 align-middle">
          <thead><tr><th /><th>Finding</th><th>Location</th><th>Paths removed</th><th>Score</th><th /></tr></thead>
          <tbody>{rec.single_fixes.map((r) => (
            <tr key={r.finding_id}>
              <td><input type="checkbox" className="form-check-input" aria-label={`Simulate fixing ${r.title}`} checked={selected.has(r.finding_id)} onChange={() => toggle([r.finding_id])} /></td>
              <td><SevBadge s={r.severity} /> {r.title}<div className="text-secondary">{r.rule_id}{r.job ? ` · job ${r.job}` : ""}</div></td>
              <td className="text-break-all">{r.location}</td><td>{r.paths_removed || "—"}</td><td><Delta v={r.score_gain} /></td>
              <td>{r.auto_fixable && <span className="badge bg-success">auto-fix</span>}</td>
            </tr>
          ))}</tbody>
        </table></div>
      </div></div>}
    </>
  );
}

function FixesCard({ scanId, pipeline, isGithub, onSimulate }: { scanId: string; pipeline?: string; isGithub: boolean; onSimulate: (ids: string[]) => void }) {
  const { role } = useMe();
  const [plan, setPlan] = useState<FixPlan | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [creds, setCreds] = useState<{ id: string; name: string; hint: string }[]>([]);
  const [cred, setCred] = useState("");
  const [pr, setPr] = useState<{ url: string; number: number; files: number; fixes: number } | null>(null);
  const q = pipeline ? `?pipeline=${encodeURIComponent(pipeline)}` : "";
  const generate = async () => {
    setBusy(true); setErr(null); setPr(null);
    try { setPlan(await api.get<FixPlan>(`/api/scans/${scanId}/fixes${q}`)); } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };
  useEffect(() => { if (isGithub && canEdit(role)) api.get<{ id: string; name: string; hint: string }[]>("/api/credentials").then(setCreds).catch(() => setCreds([])); }, [isGithub, role]);
  const openPr = async () => {
    setBusy(true); setErr(null);
    try { setPr(await api.post(`/api/scans/${scanId}/fixes/pull-request`, { credential_id: cred, pipeline: pipeline || null })); }
    catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };
  const verifiedIds = plan ? plan.fixes.filter((f) => f.verified).map((f) => f.finding_id) : [];
  return (
    <div className="card"><div className="card-body">
      <div className="d-flex flex-wrap justify-content-between align-items-center gap-2">
        <div><h2 className="h6 mb-0">One-click fixes</h2>
          <div className="small text-secondary">Rule-based fixes for unpinned actions, missing token permissions, persisted checkout tokens and script injection.
            Every patched file is re-checked by the same rules before it is offered.</div></div>
        <button className="btn btn-primary btn-sm" onClick={generate} disabled={busy}>{busy && !plan ? "Generating…" : plan ? "Regenerate" : "Generate fixes"}</button>
      </div>
      <ErrorBox error={err} />
      {plan && <div className="mt-3">
        <div className="d-flex flex-wrap gap-3 small mb-2">
          <span><b>{plan.summary.applied}</b> fix(es) applied</span><span className="text-success"><b>{plan.summary.verified}</b> verified</span>
          <span><b>{plan.summary.skipped}</b> need manual work</span><span><b>{plan.summary.files}</b> file(s)</span>
          {plan.summary.needs_review > 0 && <span className="text-warning"><b>{plan.summary.needs_review}</b> to review</span>}
          {plan.summary.introduced > 0 && <span className="text-danger"><b>{plan.summary.introduced}</b> new issue(s) detected</span>}
        </div>
        {plan.summary.applied === 0 ? <Empty>No automatic fixes available{pipeline ? " for this pipeline" : ""}.</Empty> : <>
          <div className="d-flex flex-wrap gap-2 mb-3">
            <button className="btn btn-sm btn-outline-primary" onClick={() => onSimulate(verifiedIds)}>Simulate these fixes</button>
            <button className="btn btn-sm btn-outline-primary" onClick={() => api.download(`/api/scans/${scanId}/fixes.patch${q}`, `pipelinetrust-fixes-${scanId.slice(0, 8)}.patch`).catch((e) => setErr(e.message))}>Download .patch</button>
            {isGithub && canEdit(role) && <div className="d-flex gap-2 align-items-center">
              <select className="form-select form-select-sm" style={{ maxWidth: 260 }} value={cred} onChange={(e) => setCred(e.target.value)} aria-label="Credential for pull request">
                <option value="">Token with write access…</option>{creds.map((c) => <option key={c.id} value={c.id}>{c.name} ({c.hint})</option>)}
              </select>
              <button className="btn btn-sm btn-success" disabled={!cred || busy} onClick={openPr}>{busy ? "Opening…" : "Open pull request"}</button>
            </div>}
          </div>
          {isGithub && canEdit(role) && <div className="small text-secondary mb-2">Opening a pull request needs a token with <b>Contents: write</b> and <b>Pull requests: write</b>. Scanning tokens are read-only by design; add a separate token under Settings.</div>}
          {pr && <div className="alert alert-success py-2">Pull request <a href={pr.url} target="_blank" rel="noreferrer">#{pr.number}</a> opened with {pr.fixes} fix(es) in {pr.files} file(s).</div>}
          <div className="table-responsive mb-3"><table className="table table-sm small mb-0 align-middle">
            <thead><tr><th>Fix</th><th>Location</th><th>Result</th><th>Detail</th></tr></thead>
            <tbody>{plan.fixes.map((f) => (
              <tr key={f.finding_id}>
                <td><div className="fw-semibold">{f.label}</div><div className="text-secondary">{f.rule_id}</div></td>
                <td className="text-break-all"><code>{f.file}</code>{f.line ? `:${f.line}` : ""}{f.job && <div className="text-secondary">job {f.job}</div>}</td>
                <td>{f.status === "applied" ? (f.verified ? <span className="badge bg-success">verified</span> : <span className="badge bg-warning text-dark">unverified</span>)
                  : <span className="badge bg-secondary">manual</span>}</td>
                <td>{f.detail}{f.review && <div className="text-warning-emphasis mt-1">Review: {f.review}</div>}</td>
              </tr>
            ))}</tbody>
          </table></div>
          {plan.files.map((fl) => (
            <details key={fl.path} className="mb-2" open={plan.files.length <= 2}>
              <summary className="small"><code>{fl.path}</code> · {fl.applied} change(s) · {fl.verified ? <span className="text-success">verified</span> : <span className="text-danger">not verified</span>}
                {fl.parse_error && <span className="text-danger"> · parse error: {fl.parse_error}</span>}</summary>
              <DiffView diff={fl.diff} />
            </details>
          ))}
        </>}
      </div>}
    </div></div>
  );
}

export function RemediationPanel({ scanId, pipeline, isGithub, pipelineFindingIds }: { scanId: string; pipeline?: string; isGithub: boolean; pipelineFindingIds?: string[] }) {
  const [rec, setRec] = useState<Recommendations | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  useEffect(() => { api.get<Recommendations>(`/api/scans/${scanId}/whatif/recommendations`).then(setRec).catch((e) => setErr(e.message)); }, [scanId]);
  const scoped = useMemo(() => {
    if (!rec || !pipelineFindingIds) return rec;
    const mine = new Set(pipelineFindingIds);
    return {
      ...rec,
      by_rule: rec.by_rule.map((r) => ({ ...r, finding_ids: r.finding_ids.filter((i) => mine.has(i)) })).filter((r) => r.finding_ids.length)
        .map((r) => ({ ...r, findings: r.finding_ids.length })),
      single_fixes: rec.single_fixes.filter((s) => mine.has(s.finding_id)),
    };
  }, [rec, pipelineFindingIds]);
  const simulate = useCallback((ids: string[]) => setSelected(new Set(ids)), []);
  if (err) return <ErrorBox error={err} />;
  if (!scoped) return <Loading />;
  return (
    <>
      {pipeline && <div className="alert alert-secondary small py-2">Rules and fixes are limited to this pipeline; the score and attack paths are for the whole repository.</div>}
      <Simulator scanId={scanId} selected={selected} setSelected={setSelected} rec={scoped} />
      <FixesCard scanId={scanId} pipeline={pipeline} isGithub={isGithub} onSimulate={simulate} />
    </>
  );
}

// ------------------------------------------------------------------ compliance

export function CompliancePanel({ scanId }: { scanId: string }) {
  const [fw, setFw] = useState("ssdf");
  const [pack, setPack] = useState<CompliancePack | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  useEffect(() => { setPack(null); api.get<CompliancePack>(`/api/scans/${scanId}/compliance/${fw}`).then(setPack).catch((e) => setErr(e.message)); }, [scanId, fw]);
  const dl = (fmt: string) => api.download(`/api/scans/${scanId}/compliance/${fw}/export.${fmt}`, `pipelinetrust-${fw}-${scanId.slice(0, 8)}.${fmt}`).catch((e) => setErr(e.message));
  return (
    <>
      <div className="d-flex flex-wrap gap-2 align-items-center mb-2">
        <select className="form-select form-select-sm" style={{ maxWidth: 360 }} value={fw} onChange={(e) => setFw(e.target.value)} aria-label="Framework">
          {(pack?.frameworks || [{ id: fw, name: fw }]).map((f) => <option key={f.id} value={f.id}>{f.name}</option>)}
        </select>
        <div className="btn-group btn-group-sm">
          {["html", "csv", "json"].map((x) => <button key={x} className="btn btn-outline-primary" onClick={() => dl(x)}>Export {x.toUpperCase()}</button>)}
        </div>
      </div>
      <ErrorBox error={err} />
      {!pack ? <Loading /> : <>
        <div className="d-flex flex-wrap gap-2 align-items-center small mb-2">
          <b>{pack.satisfied_percent}%</b> of decided requirements satisfied ·
          {Object.entries(pack.counts).map(([k, v]) => <span key={k}><StatusBadge s={k} /> {v}</span>)}
        </div>
        <div className="alert alert-warning small py-2">{pack.disclaimer}</div>
        <div className="card"><div className="table-responsive"><table className="table table-sm mb-0 align-middle">
          <thead><tr><th>Requirement</th><th>Status</th><th>Mapped controls</th><th>Open findings</th><th /></tr></thead>
          <tbody>{pack.requirements.map((r) => (
            <Fragment key={r.id}>
              <tr className="finding-row" onClick={() => setOpen(open === r.id ? null : r.id)}>
                <td><b>{r.id}</b> <span className="small">{r.title}</span></td><td><StatusBadge s={r.status} /></td>
                <td>{r.evidence.length}</td><td>{r.open_findings || "—"}</td><td className="small text-secondary">{open === r.id ? "▲" : "▼"}</td>
              </tr>
              {open === r.id && <tr><td colSpan={5} className="bg-body-tertiary small">
                {r.evidence.map((e) => (
                  <div key={e.rule_id} className="mb-2">
                    <StatusBadge s={e.status} /> <code>{e.rule_id}</code> {e.title}
                    {e.open_findings > 0 && <span className="text-danger"> · {e.open_findings} open</span>}
                    {e.accepted_risk > 0 && <span className="text-secondary"> · {e.accepted_risk} accepted risk</span>}
                    {e.note && <div className="text-secondary">{e.note}</div>}
                    {e.evidence.map((x, i) => <div key={i} className="text-secondary">{x}</div>)}
                    {e.findings.map((f) => <div key={f.id}><SevBadge s={f.severity} /> {f.title} <span className="text-secondary">{f.location}</span></div>)}
                  </div>
                ))}
              </td></tr>}
            </Fragment>
          ))}</tbody>
        </table></div></div>
      </>}
    </>
  );
}

// ------------------------------------------------------------------ ask

function renderAnswer(text: string) {
  return text.split(/(`[^`]+`)/g).map((part, i) => (part.startsWith("`") && part.endsWith("`") ? <code key={i}>{part.slice(1, -1)}</code> : <Fragment key={i}>{part}</Fragment>));
}

export function AskPanel({ scanId }: { scanId: string }) {
  const [q, setQ] = useState("");
  const [examples, setExamples] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [hist, setHist] = useState<{ q: string; a: AskAnswer }[]>([]);
  useEffect(() => { api.get<string[]>("/api/ask/examples").then(setExamples).catch(() => setExamples([])); }, []);
  const send = async (question: string) => {
    if (question.trim().length < 3) return;
    setBusy(true); setErr(null);
    try { const a = await api.post<AskAnswer>(`/api/scans/${scanId}/ask`, { question }); setHist((h) => [{ q: question, a }, ...h]); setQ(""); }
    catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };
  return (
    <>
      <form className="d-flex gap-2 mb-2" onSubmit={(e) => { e.preventDefault(); send(q); }}>
        <input className="form-control" placeholder="Ask about this repository's pipelines…" value={q} onChange={(e) => setQ(e.target.value)} maxLength={500} aria-label="Question" />
        <button className="btn btn-primary" disabled={busy || q.trim().length < 3}>{busy ? "…" : "Ask"}</button>
      </form>
      <div className="d-flex flex-wrap gap-1 mb-3">
        {examples.map((x) => <button key={x} className="btn btn-sm btn-outline-secondary" onClick={() => send(x)} disabled={busy}>{x}</button>)}
      </div>
      <ErrorBox error={err} />
      {hist.length === 0 && <div className="small text-secondary">Answers come only from this scan&apos;s data. With an LLM configured, every cited finding, path, pipeline or secret is checked and anything that does not exist is removed.</div>}
      {hist.map(({ q: question, a }, i) => (
        <div key={i} className="card mb-2"><div className="card-body">
          <div className="fw-semibold mb-1">{question}</div>
          <div className="answer small">{renderAnswer(a.answer)}</div>
          {a.references.length > 0 && <div className="mt-2 small"><span className="text-secondary">Sources: </span>
            {a.references.map((r) => (
              <span key={`${r.kind}:${r.id}`} className="me-2 d-inline-block">
                {r.kind === "pipeline" ? <Link href={pipelineHref(scanId, r.id)}>{r.label}</Link>
                  : r.kind === "finding" ? <Link href={`/scan?id=${scanId}&finding=${r.id}`}>{r.label}</Link>
                  : <span className="badge bg-light text-dark border">{r.label}</span>}
              </span>
            ))}</div>}
          <div className="small text-secondary mt-1">Mode: {a.mode}{a.provider ? ` · ${a.provider}/${a.model}` : ""}
            {a.guardrail && <> · guardrail removed {a.guardrail.dropped_count} unknown reference(s)</>}{a.note && <> · {a.note}</>}</div>
        </div></div>
      ))}
    </>
  );
}
