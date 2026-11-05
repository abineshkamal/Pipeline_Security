"use client";
import { useEffect, useState } from "react";
import Shell from "@/components/Shell";
import { Loading, SevBadge } from "@/components/ui";
import { api, CATEGORIES, type Rule } from "@/lib/api";

export default function Page() {
  const [rules, setRules] = useState<Rule[] | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  useEffect(() => { api.get<Rule[]>("/api/rules").then(setRules); }, []);
  return (
    <Shell>
      <h1 className="h4 mb-1">Detection rule catalog</h1>
      <p className="text-secondary small">{rules?.length ?? "…"} deterministic rules mapped to the OWASP Top 10 CI/CD Security Risks. Rules are independent Python modules in <code>backend/app/scanner/rules/</code>.</p>
      {!rules ? <Loading /> : Object.keys(CATEGORIES).map((cat) => {
        const rs = rules.filter((r) => r.category === cat);
        return (
          <div className="card mb-3" key={cat}><div className="card-body">
            <h2 className="h6 mb-1">{cat} · {rs[0]?.category_name || CATEGORIES[cat]}</h2>
            <p className="small text-secondary">{rs[0]?.objective}</p>
            <div className="list-group">{rs.map((r) => (
              <div key={r.id} className="list-group-item">
                <button className="btn btn-link p-0 text-start text-decoration-none w-100" onClick={() => setOpen(open === r.id ? null : r.id)}>
                  <span className="font-monospace small me-2">{r.id}</span><SevBadge s={r.severity} /> <span className="ms-1">{r.title}</span>
                </button>
                {open === r.id && <div className="small mt-2">
                  <p>{r.description}</p>
                  <p><b>Evidence:</b> {r.evidence_requirements}</p>
                  <p><b>Remediation:</b> {r.remediation}</p>
                  <p><b>False-positive considerations:</b> {r.false_positives}</p>
                  <p><b>Data sources:</b> {r.data_sources.join(", ")} {r.cwe.length > 0 && <> · <b>CWE:</b> {r.cwe.join(", ")}</>}</p>
                  <ul className="mb-0">{r.references.map((u) => <li key={u}><a href={u} target="_blank" rel="noopener noreferrer">{u}</a></li>)}</ul>
                </div>}
              </div>
            ))}</div>
          </div></div>
        );
      })}
    </Shell>
  );
}
