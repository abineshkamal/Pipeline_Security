"use client";
import dynamic from "next/dynamic";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import FindingDetail from "@/components/FindingDetail";
import { RuntimePanel } from "@/components/analysis";
import { LeastPrivilegePanel } from "@/components/enterprise";
import { RemediationPanel, SecretsPanel } from "@/components/insights";
import Shell from "@/components/Shell";
import { Empty, ErrorBox, Loading, SevBadge } from "@/components/ui";
import { api, CATEGORIES, fmtDate, pipelineHref, type AttackPath, type Finding, type PipelineDetail } from "@/lib/api";

const AttackGraph = dynamic(() => import("@/components/AttackGraph"), { ssr: false, loading: () => <Loading label="Loading graph…" /> });
const TABS = ["Findings", "Fix & simulate", "Secrets", "Runtime", "Jobs & permissions", "Actions", "Attack paths", "Repository settings"] as const;
type Tab = (typeof TABS)[number];

function Stat({ label, value, sub, tone }: { label: string; value: React.ReactNode; sub?: React.ReactNode; tone?: string }) {
  return (
    <div className="col-6 col-lg"><div className="card h-100"><div className="card-body py-3">
      <div className="small text-secondary text-uppercase">{label}</div>
      <div className={`fs-3 fw-bold ${tone || ""}`}>{value}</div>
      {sub && <div className="small text-secondary">{sub}</div>}
    </div></div></div>
  );
}

function FindingList({ findings, empty, onSaved }: { findings: Finding[]; empty: string; onSaved: (f: Finding) => void }) {
  const [sel, setSel] = useState<Finding | null>(findings[0] || null);
  const [cat, setCat] = useState("");
  const rows = findings.filter((f) => !cat || f.category === cat);
  useEffect(() => { setSel((s) => (s && findings.find((f) => f.id === s.id)) || findings[0] || null); }, [findings]);
  if (!findings.length) return <Empty>{empty}</Empty>;
  const cats = Array.from(new Set(findings.map((f) => f.category))).sort();
  return (
    <div className="row g-3">
      <div className="col-12 col-xl-7">
        <select className="form-select form-select-sm mb-2" style={{ maxWidth: 300 }} value={cat} onChange={(e) => setCat(e.target.value)} aria-label="Category">
          <option value="">All categories ({findings.length})</option>
          {cats.map((c) => <option key={c} value={c}>{c} · {CATEGORIES[c] || ""} ({findings.filter((f) => f.category === c).length})</option>)}
        </select>
        <div className="card"><div className="table-responsive" style={{ maxHeight: 600 }}><table className="table table-sm mb-0">
          <thead className="sticky-top"><tr><th>Sev</th><th>Finding</th><th>Job / line</th><th>Risk</th><th>Triage</th></tr></thead>
          <tbody>{rows.map((f) => (
            <tr key={f.id} className={`finding-row ${sel?.id === f.id ? "table-active" : ""}`} onClick={() => setSel(f)}>
              <td><SevBadge s={f.severity} /></td>
              <td><div className="fw-semibold small">{f.title}</div><div className="small text-secondary">{f.rule_id} · {f.category}</div></td>
              <td className="small">{f.job && <code>{f.job}</code>}{f.line ? <div className="text-secondary">line {f.line}</div> : null}</td>
              <td>{f.risk_score}</td><td className="small">{f.triage_status}</td>
            </tr>
          ))}</tbody>
        </table></div></div>
      </div>
      <div className="col-12 col-xl-5">
        {sel ? <FindingDetail f={sel} onSaved={(nf) => { onSaved(nf); setSel(nf); }} />
          : <div className="text-secondary small p-3 border rounded">Select a finding to see evidence, remediation and triage.</div>}
      </div>
    </div>
  );
}

function Jobs({ d }: { d: PipelineDetail }) {
  const wf = d.workflow;
  return (
    <div className="card"><div className="table-responsive"><table className="table table-sm mb-0 align-middle">
      <thead><tr><th>Job</th><th>Runs on</th><th>Environment</th><th>Token permissions</th><th>Secrets</th><th>Deploys</th></tr></thead>
      <tbody>{wf.jobs.map((j) => (
        <tr key={j.id}>
          <td><b>{j.id}</b>{j.name && j.name !== j.id && <div className="small text-secondary">{j.name}</div>}
            {j.reusable && <div className="small">calls <code className="text-break-all">{j.reusable}</code></div>}
            {j.line ? <div className="small text-secondary">line {j.line}{j.steps != null ? ` · ${j.steps} step(s)` : ""}</div> : null}</td>
          <td className="small">{j.runs_on.join(", ") || "—"}{j.self_hosted && <span className="badge bg-danger ms-1">self-hosted</span>}</td>
          <td className="small">{j.environment ? <span className="badge bg-info text-dark">{j.environment}</span> : <span className="text-secondary">none</span>}</td>
          <td className="small">{j.write_scopes?.length ? <span className="text-danger">write: {j.write_scopes.join(", ")}</span>
            : j.write_scopes ? <span className="text-success">read-only</span> : <span className="text-secondary">repository default</span>}
            <div className="text-secondary">set at: {j.permissions_source}</div></td>
          <td className="small">{j.secrets.length ? j.secrets.map((s) => <div key={s}><code>{s}</code></div>) : <span className="text-secondary">none</span>}</td>
          <td className="small">{j.deploy_indicators.length ? j.deploy_indicators.map((x, i) => <div key={i} className="text-break-all">{x}</div>) : <span className="text-secondary">no</span>}</td>
        </tr>
      ))}</tbody>
    </table></div></div>
  );
}

function Actions({ d }: { d: PipelineDetail }) {
  if (!d.actions.length) return <Empty>This pipeline uses no external actions or container images.</Empty>;
  const unpinned = d.actions.filter((a) => !a.sha_pinned && !a.first_party).length;
  return (
    <>
      <div className="small text-secondary mb-2">{d.actions.length} external reference(s); {unpinned} third-party reference(s) not pinned to a commit SHA.</div>
      <div className="card"><div className="table-responsive"><table className="table table-sm mb-0">
        <thead><tr><th>Reference</th><th>Kind</th><th>Publisher</th><th>Pinned</th></tr></thead>
        <tbody>{d.actions.map((a) => (
          <tr key={a.uses}><td className="text-break-all"><code>{a.uses}</code></td><td className="small">{a.kind}</td>
            <td className="small">{a.first_party ? "GitHub" : a.owner}</td>
            <td>{a.sha_pinned ? <span className="text-success">✔ SHA</span> : <span className={a.first_party ? "text-secondary" : "text-danger"}>✖ {a.ref || "unpinned"}</span>}</td></tr>
        ))}</tbody>
      </table></div></div>
    </>
  );
}

function Paths({ d, goFinding }: { d: PipelineDetail; goFinding: (id: string) => void }) {
  const [hl, setHl] = useState<AttackPath | null>(d.attack_paths[0] || null);
  if (!d.attack_paths.length) return <Empty>No evidence-backed attack paths run through this pipeline.</Empty>;
  return (
    <div className="row g-3">
      <div className="col-12 col-lg-4">
        <div className="small text-secondary mb-2">{d.attack_paths.length} path(s) run through a job in this pipeline.</div>
        <div className="list-group" style={{ maxHeight: 520, overflowY: "auto" }}>
          {d.attack_paths.map((p) => (
            <button key={p.id} className={`list-group-item list-group-item-action ${hl?.id === p.id ? "active" : ""}`} onClick={() => setHl(p)}>
              <div className="d-flex justify-content-between"><b>{p.id}</b><span>risk {p.risk}</span></div>
              <div className="small">{p.impact}</div><div className="small opacity-75">{p.actor}</div>
            </button>
          ))}
        </div>
      </div>
      <div className="col-12 col-lg-8">
        <AttackGraph nodes={d.graph.nodes} edges={d.graph.edges} highlight={hl} pathOnly={!!hl} />
        {hl && <div className="card mt-2"><div className="card-body">
          <ol className="small mb-2">{hl.labels.map((l, i) => <li key={i}>{l}</li>)}</ol>
          {hl.gated_by.length > 0 && <div className="small text-secondary">Partially gated by environment(s): {hl.gated_by.join(", ")}</div>}
          <div className="small">Evidence: {(hl.finding_ids || []).map((id) => <button key={id} className="btn btn-link btn-sm p-0 me-2" onClick={() => goFinding(id)}>{id.slice(0, 8)}</button>)}</div>
        </div></div>}
      </div>
    </div>
  );
}

function Body() {
  const sp = useSearchParams();
  const router = useRouter();
  const scanId = sp.get("scan") || "";
  const path = sp.get("path") || "";
  const [d, setD] = useState<PipelineDetail | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("Findings");

  const load = useCallback(() => {
    if (!scanId || !path) { setErr("Missing scan or pipeline."); return; }
    setD(null); setErr(null);
    api.get<PipelineDetail>(`/api/scans/${scanId}/pipeline?path=${encodeURIComponent(path)}`).then(setD).catch((e) => setErr(e.message));
  }, [scanId, path]);
  useEffect(() => { load(); setTab("Findings"); }, [load]);

  const replace = (nf: Finding) => setD((x) => x && {
    ...x, findings: x.findings.map((f) => (f.id === nf.id ? nf : f)),
    repo_setting_findings: x.repo_setting_findings.map((f) => (f.id === nf.id ? nf : f)),
  });
  const goFinding = (id: string) => {
    if (!d) return;
    if (d.findings.some((f) => f.id === id)) setTab("Findings");
    else if (d.repo_setting_findings.some((f) => f.id === id)) setTab("Repository settings");
    else router.push(`/scan?id=${scanId}&finding=${id}`);
  };
  const idx = useMemo(() => (d ? d.pipelines.findIndex((p) => p.path === path) : -1), [d, path]);

  if (err) return <ErrorBox error={err} />;
  if (!d) return <Loading />;
  const s = d.summary, wf = d.workflow;
  const prev = idx > 0 ? d.pipelines[idx - 1] : null, next = idx >= 0 && idx < d.pipelines.length - 1 ? d.pipelines[idx + 1] : null;
  return (
    <>
      <nav aria-label="breadcrumb"><ol className="breadcrumb small mb-2">
        <li className="breadcrumb-item"><Link href="/projects">Projects</Link></li>
        <li className="breadcrumb-item"><Link href={`/project?id=${d.project.id}`}>{d.project.name}</Link></li>
        <li className="breadcrumb-item active" aria-current="page">{s.name}</li>
      </ol></nav>

      <div className="d-flex flex-wrap justify-content-between align-items-start gap-2 mb-3">
        <div>
          <h1 className="h4 mb-0">{s.name}</h1>
          <div className="text-secondary small"><code>{wf.path}</code> · {d.project.repo_full_name || "uploaded repository"} · scanned {fmtDate(d.scan.created_at)}
            {d.scan.commit_sha && <> · commit <code>{d.scan.commit_sha.slice(0, 10)}</code></>}</div>
          {wf.error && <div className="small text-danger">{wf.error}</div>}
        </div>
        <div className="d-flex flex-wrap gap-2 align-items-center">
          <select className="form-select form-select-sm" style={{ maxWidth: 320 }} value={path} aria-label="Switch pipeline"
            onChange={(e) => router.push(pipelineHref(scanId, e.target.value))}>
            {d.pipelines.map((p) => <option key={p.path} value={p.path}>{p.name} ({p.path.split("/").pop()})</option>)}
          </select>
          <div className="btn-group btn-group-sm">
            <button className="btn btn-outline-secondary" disabled={!prev} onClick={() => prev && router.push(pipelineHref(scanId, prev.path))} aria-label="Previous pipeline">‹</button>
            <button className="btn btn-outline-secondary" disabled={!next} onClick={() => next && router.push(pipelineHref(scanId, next.path))} aria-label="Next pipeline">›</button>
          </div>
          <Link href={`/scan?id=${scanId}`} className="btn btn-sm btn-outline-primary">Full scan results</Link>
        </div>
      </div>

      <div className="row g-3 mb-3">
        <Stat label="Findings" value={s.findings} tone={s.findings ? "" : "text-success"}
          sub={(["critical", "high", "medium", "low"] as const).filter((k) => s.severity_counts[k]).map((k) => <span key={k} className={`badge sev-${k} me-1`}>{s.severity_counts[k]} {k}</span>)} />
        <Stat label="Max risk" value={s.max_risk || "—"} tone={s.max_risk >= 7 ? "text-danger" : ""} sub="highest finding risk, 0–10" />
        <Stat label="Attack paths" value={s.attack_paths} tone={s.attack_paths ? "text-danger" : "text-success"} sub="through this pipeline" />
        <Stat label="Jobs" value={s.jobs} sub={[s.self_hosted && "self-hosted runner", s.deploys && "deploys"].filter(Boolean).join(" · ") || undefined} />
        <Stat label="Secrets" value={s.secrets.length} sub={s.write_access ? "write-scoped token in use" : undefined} />
      </div>

      <div className="card mb-3"><div className="card-body py-2 small">
        <b>Triggers: </b>{wf.triggers.length ? wf.triggers.map((t) => (
          <span key={t} className={`badge me-1 ${wf.privileged_triggers.includes(t) ? "bg-danger" : wf.external_triggers.includes(t) ? "bg-warning text-dark" : "bg-secondary"}`}>{t}</span>
        )) : "none"}
        {wf.privileged_triggers.length > 0 && <span className="text-danger ms-2">Privileged trigger reachable by outsiders: runs with secrets or write access on untrusted input.</span>}
        {!wf.privileged_triggers.length && wf.external_triggers.length > 0 && <span className="text-secondary ms-2">Can be started from outside the repository.</span>}
      </div></div>

      <ul className="nav nav-tabs mb-3 flex-nowrap overflow-auto">
        {TABS.map((t) => {
          const n = t === "Findings" ? d.findings.length : t === "Attack paths" ? d.attack_paths.length : t === "Actions" ? d.actions.length
            : t === "Repository settings" ? d.repo_setting_findings.length : t === "Secrets" ? s.secrets.length : t === "Jobs & permissions" ? wf.jobs.length : null;
          return <li className="nav-item" key={t}><button className={`nav-link text-nowrap ${tab === t ? "active" : ""}`} onClick={() => setTab(t)}>{t}
            {n != null && <span className="badge bg-light text-dark border ms-1">{n}</span>}</button></li>;
        })}
      </ul>
      {tab === "Findings" && <FindingList findings={d.findings} empty="No findings in this pipeline file." onSaved={replace} />}
      {tab === "Fix & simulate" && <RemediationPanel scanId={scanId} pipeline={path} isGithub={d.project.source_type === "github"}
        pipelineFindingIds={d.findings.map((f) => f.id)} />}
      {tab === "Secrets" && <SecretsPanel scanId={scanId} pipeline={path} />}
      {tab === "Runtime" && (d.project.source_type === "github" ? <RuntimePanel scanId={scanId} pipeline={path} /> :
        <div className="text-secondary p-4 border rounded">Run history comes from GitHub; ZIP assessments have none.</div>)}
      {tab === "Jobs & permissions" && <><LeastPrivilegePanel scanId={scanId} pipeline={path} /><Jobs d={d} /></>}
      {tab === "Actions" && <Actions d={d} />}
      {tab === "Attack paths" && <Paths d={d} goFinding={goFinding} />}
      {tab === "Repository settings" && <>
        <div className="alert alert-secondary small py-2">These findings come from repository or organization settings (branch protection, default token permissions and similar). They are not in this file, but they apply to every pipeline in the repository.</div>
        <FindingList findings={d.repo_setting_findings} empty="No repository-setting findings." onSaved={replace} />
      </>}
    </>
  );
}

export default function Page() { return <Shell><Suspense fallback={<Loading />}><Body /></Suspense></Shell>; }
