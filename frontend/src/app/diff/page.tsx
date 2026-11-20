"use client";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";
import Shell from "@/components/Shell";
import { Empty, ErrorBox, Loading, SevBadge } from "@/components/ui";
import { api, fmtDate, pipelineHref, type DiffScan, type PipelineDiff } from "@/lib/api";

const RISK: Record<string, [string, string]> = { increase: ["bg-danger", "Riskier"], decrease: ["bg-success", "Safer"], neutral: ["bg-secondary", "Changed"] };

function ScanCard({ s, label }: { s: DiffScan; label: string }) {
  return (
    <div className="card h-100"><div className="card-body py-2">
      <div className="small text-secondary">{label}</div>
      <div className="fw-semibold">{s.ref || "default branch"} <code className="small">{s.commit_sha.slice(0, 10)}</code></div>
      <div className="small">{fmtDate(s.created_at)} · score <b>{s.posture_score ?? "—"}</b> {s.grade} · {s.workflows} pipeline(s) · {s.attack_paths} attack path(s)</div>
      <Link className="small" href={`/scan?id=${s.id}`}>Open scan</Link>
    </div></div>
  );
}

function Body() {
  const sp = useSearchParams();
  const router = useRouter();
  const base = sp.get("base") || "", scan = sp.get("scan") || "";
  const [d, setD] = useState<PipelineDiff | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [only, setOnly] = useState<string>("all");
  useEffect(() => {
    if (!base || !scan) { setErr("Pick two scans to compare on the project page."); return; }
    api.get<PipelineDiff>(`/api/scans/${scan}/pipeline-diff/${base}`).then(setD).catch((e) => setErr(e.message));
  }, [base, scan]);
  if (err) return <ErrorBox error={err} />;
  if (!d) return <Loading />;
  const c = d.counts;
  const changes = d.changes.filter((x) => only === "all" || x.risk === only);
  return (
    <>
      <nav aria-label="breadcrumb"><ol className="breadcrumb small mb-1">
        <li className="breadcrumb-item"><Link href={`/project?id=${d.project.id}`}>{d.project.name}</Link></li><li className="breadcrumb-item active">Pipeline changes</li></ol></nav>
      <div className="d-flex flex-wrap align-items-center gap-2 mb-3">
        <h1 className="h4 mb-0 me-auto">What changed in the pipelines</h1>
        <span className="small text-secondary">Ordered by scan time - comparing an older release you scanned later? Swap.</span>
        <button className="btn btn-sm btn-outline-primary" onClick={() => router.replace(`/diff?base=${scan}&scan=${base}`)}>⇄ Swap direction</button>
      </div>
      <div className="row g-2 mb-3">
        <div className="col-12 col-md-5"><ScanCard s={d.from} label="From (older)" /></div>
        <div className="col-12 col-md-2 d-flex align-items-center justify-content-center fs-3 text-secondary">→</div>
        <div className="col-12 col-md-5"><ScanCard s={d.to} label="To (newer)" /></div>
      </div>
      <div className="row g-2 mb-3">{([
        ["Score change", d.score_delta == null ? "—" : `${d.score_delta > 0 ? "+" : ""}${d.score_delta}`, d.score_delta != null && d.score_delta < 0 ? "text-danger" : "text-success"],
        ["Riskier changes", c.increase, c.increase ? "text-danger" : ""], ["Safer changes", c.decrease, c.decrease ? "text-success" : ""],
        ["New attack paths", c.new_paths, c.new_paths ? "text-danger" : ""], ["Removed attack paths", c.removed_paths, ""],
        ["New / fixed findings", `${c.new_findings} / ${c.fixed_findings}`, ""],
      ] as [string, string | number, string][]).map(([l, v, cls]) => (
        <div className="col-6 col-md-4 col-xl-2" key={l}><div className="card h-100"><div className="card-body py-2"><div className={`fs-5 fw-bold ${cls}`}>{v}</div><div className="small text-secondary">{l}</div></div></div></div>))}
      </div>

      <div className="card mb-3"><div className="card-body">
        <div className="d-flex flex-wrap align-items-center gap-2 mb-2">
          <h2 className="h6 mb-0 me-auto">Build-chain changes ({d.changes.length})</h2>
          <div className="btn-group btn-group-sm">{["all", "increase", "decrease", "neutral"].map((k) =>
            <button key={k} className={`btn ${only === k ? "btn-primary" : "btn-outline-primary"}`} onClick={() => setOnly(k)}>{k === "all" ? "All" : RISK[k][1]}</button>)}</div>
        </div>
        {!changes.length ? <Empty>No pipeline changes{only !== "all" ? " of this kind" : ""}.</Empty> : (
          <ul className="list-unstyled mb-0">{changes.map((x, i) => (
            <li key={i} className={`small py-1 ps-2 mb-1 risk-${x.risk}`}>
              <span className={`badge ${RISK[x.risk][0]} me-2`}>{RISK[x.risk][1]}</span>{x.text}
              {x.workflow && !x.workflow.includes(",") && <> · <Link href={pipelineHref(d.to.id, x.workflow)}>{x.workflow.split("/").pop()}</Link></>}
            </li>))}</ul>)}
      </div></div>

      <div className="row g-3">
        <div className="col-12 col-xl-6"><div className="card h-100"><div className="card-body">
          <h2 className="h6">New attack paths ({d.new_attack_paths.length})</h2>
          {!d.new_attack_paths.length ? <div className="small text-secondary">None.</div> : d.new_attack_paths.map((p) => (
            <div key={p.id} className="small mb-2"><Link href={`/scan?id=${d.to.id}`}><b>{p.id}</b></Link> risk {p.risk} · {p.impact}<div className="text-secondary">{p.labels.join(" → ")}</div></div>))}
          {d.removed_attack_paths.length > 0 && <><h3 className="h6 mt-3">Removed ({d.removed_attack_paths.length})</h3>
            {d.removed_attack_paths.map((p) => <div key={p.id} className="small text-secondary mb-1"><s>{p.labels.join(" → ")}</s></div>)}</>}
        </div></div></div>
        <div className="col-12 col-xl-6"><div className="card h-100"><div className="card-body">
          <h2 className="h6">New findings ({d.new_findings.length})</h2>
          {d.new_findings.slice(0, 40).map((f) => <div key={f.id} className="small mb-1"><SevBadge s={f.severity} /> <Link href={`/scan?id=${d.to.id}&finding=${f.id}`}>{f.rule_id} {f.title}</Link>
            <span className="text-secondary"> {f.file_path}{f.line ? `:${f.line}` : ""}</span></div>)}
          {d.new_findings.length > 40 && <div className="small text-secondary">…and {d.new_findings.length - 40} more</div>}
          <h3 className="h6 mt-3">Fixed ({d.fixed_findings.length})</h3>
          {d.fixed_findings.slice(0, 20).map((f) => <div key={f.id} className="small text-success mb-1">✔ {f.rule_id} {f.title}</div>)}
          {!d.fixed_findings.length && <div className="small text-secondary">None.</div>}
        </div></div></div>
      </div>
    </>
  );
}

export default function Page() { return <Shell><Suspense fallback={<Loading />}><Body /></Suspense></Shell>; }
