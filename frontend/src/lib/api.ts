// Thin API client. Same-origin by default (static export served by FastAPI); NEXT_PUBLIC_API_URL for `next dev`.
export const API_BASE = process.env.NEXT_PUBLIC_API_URL || "";

const TOKEN_KEY = "pt_token";
const ORG_KEY = "pt_org";

function store(): Storage | null {
  try { return typeof window !== "undefined" ? window.localStorage : null; } catch { return null; }
}
export const getToken = () => { try { return store()?.getItem(TOKEN_KEY) || null; } catch { return null; } };
export const setToken = (t: string | null) => { try { t ? store()?.setItem(TOKEN_KEY, t) : store()?.removeItem(TOKEN_KEY); } catch { /* ignore */ } };
export const getOrg = () => { try { return store()?.getItem(ORG_KEY) || null; } catch { return null; } };
export const setOrg = (o: string | null) => { try { o ? store()?.setItem(ORG_KEY, o) : store()?.removeItem(ORG_KEY); } catch { /* ignore */ } };

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

function headers(extra: Record<string, string> = {}): Record<string, string> {
  const h: Record<string, string> = { ...extra };
  const t = getToken();
  if (t) h["Authorization"] = `Bearer ${t}`;
  const o = getOrg();
  if (o) h["X-Org-Id"] = o;
  return h;
}

async function handle<T>(r: Response): Promise<T> {
  if (r.status === 401 && typeof window !== "undefined" && !location.pathname.startsWith("/login")) {
    setToken(null);
    location.href = "/login";
  }
  if (!r.ok) {
    let msg = r.statusText;
    try {
      const j = await r.json();
      msg = typeof j.detail === "string" ? j.detail : Array.isArray(j.detail) ? j.detail.map((d: { msg: string }) => d.msg).join("; ") : msg;
    } catch { /* not json */ }
    throw new ApiError(r.status, msg);
  }
  if (r.status === 204) return undefined as T;
  return r.json() as Promise<T>;
}

export const api = {
  get: <T,>(p: string) => fetch(API_BASE + p, { headers: headers() }).then((r) => handle<T>(r)),
  post: <T,>(p: string, body?: unknown) =>
    fetch(API_BASE + p, { method: "POST", headers: headers({ "Content-Type": "application/json" }), body: body === undefined ? undefined : JSON.stringify(body) }).then((r) => handle<T>(r)),
  patch: <T,>(p: string, body: unknown) =>
    fetch(API_BASE + p, { method: "PATCH", headers: headers({ "Content-Type": "application/json" }), body: JSON.stringify(body) }).then((r) => handle<T>(r)),
  del: <T,>(p: string) => fetch(API_BASE + p, { method: "DELETE", headers: headers() }).then((r) => handle<T>(r)),
  upload: <T,>(p: string, file: File) => {
    const fd = new FormData();
    fd.append("file", file);
    return fetch(API_BASE + p, { method: "POST", headers: headers(), body: fd }).then((r) => handle<T>(r));
  },
  download: async (p: string, filename: string) => {
    const r = await fetch(API_BASE + p, { headers: headers() });
    if (!r.ok) throw new ApiError(r.status, "download failed");
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  },
};

// ------------------------------------------------------------------ types
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Status = "PASS" | "FAIL" | "NOT_ASSESSED" | "NOT_APPLICABLE" | "NEEDS_MANUAL_VALIDATION";
export interface SevCounts { critical: number; high: number; medium: number; low: number; info: number }
export interface Me { id: string; email: string; full_name: string; organizations: { id: string; name: string; role: string }[] }
export interface Project {
  id: string; name: string; description: string; source_type: "github" | "upload"; repo_full_name: string; ref: string;
  credential_id: string | null; created_at: string; scan_count: number;
  last_scan: { id: string; status: string; posture_score: number | null; created_at: string; severity_counts: SevCounts | null } | null;
}
export interface Control { rule_id: string; category: string; category_name: string; title: string; severity: Severity; status: Status; note: string; evidence: string[]; finding_count: number; data_sources: string[] }
export interface CategorySummary { category: string; name: string; status: Status; score: number | null; grade: string; pass: number; fail: number; not_assessed: number; not_applicable: number; manual: number; findings: number }
export interface Summary {
  posture_score: number | null; grade: string; severity_counts: SevCounts; total_findings: number; categories: CategorySummary[];
  coverage: { controls: number; automated_decisions: number; not_assessed: number; manual: number; not_applicable: number; percent: number };
  coverage_notes: string[];
}
export interface GraphNode { id: string; type: "actor" | "trigger" | "job" | "capability" | "impact"; label: string; on_path: boolean }
export interface GraphEdge { source: string; target: string; label: string; risk: number; findings: string[]; finding_ids?: string[]; gated: string }
export interface AttackPath { id: string; nodes: string[]; labels: string[]; impact: string; actor: string; findings: string[]; finding_ids: string[]; risk: number; gated_by: string[]; length: number }
export interface ToolRun { tool: string; status: string; detail: string; seconds: number; count: number }
export interface AIAnalysis {
  provider: string; model: string; mode: string; seconds: number; disclaimer: string;
  context?: { summary: string; deployment_targets: string[]; crown_jewels: string[]; trust_boundaries: string[] };
  report?: { executive_summary: string; top_risks: string[]; recommended_actions: string[] };
  narratives?: Record<string, { narrative: string; break_point: string; source: string }>;
  trace?: { agent: string; mode: string; provider: string; seconds: number; error: string }[];
  guardrail?: { dropped_references: string[]; dropped_count: number; policy: string };
}
export interface Scan {
  id: string; project_id: string; status: string; progress: string; error: string; posture_score: number | null; commit_sha: string;
  created_at: string; started_at: string | null; finished_at: string | null; severity_counts: SevCounts | null; grade: string | null;
  options: { tools: string[]; ai: boolean };
  summary?: Summary; inventory?: Inventory; controls?: Control[]; tool_runs?: ToolRun[];
  attack_graph?: { nodes: GraphNode[]; edges: GraphEdge[]; paths: AttackPath[]; stats: Record<string, number> };
  ai_analysis?: AIAnalysis; project?: { id: string; name: string; source_type: string; repo_full_name: string };
}
export interface Inventory {
  source: string; repository: string; default_branch: string; visibility: string; file_count: number;
  workflows: { path: string; name: string; error: string | null; triggers: string[]; external_triggers: string[]; privileged_triggers: string[];
    jobs: { id: string; runs_on: string[]; self_hosted: boolean; environment: string | null; secrets: string[]; write_scopes: string[] | null; permissions_source: string; deploy_indicators: string[] }[] }[];
  actions: { uses: string; kind: string; owner: string; action: string; ref: string; sha_pinned: boolean; first_party: boolean; workflows: string[]; count: number }[];
  secrets: Record<string, string[]>; self_hosted_runners: Record<string, string[]>; environments: Record<string, string[]>;
  other_ci_systems: { system: string; file: string }[]; sbom_available?: boolean;
}
export interface Finding {
  id: string; rule_id: string; category: string; title: string; severity: Severity; confidence: string; risk_score: number; evidence_type: string;
  message: string; file_path: string; line: number | null; snippet: string; workflow: string; job: string; fingerprint: string;
  extra: Record<string, unknown> & { corroborated_by?: string[]; suggested_pin?: string };
  triage_status: string; validation_status: string; triage_note: string;
  ai_notes: { triage?: { exploitability: string; priority: string; rationale: string; false_positive_likelihood: string; source: string }; fix?: { explanation: string; patch: string; source: string } };
}
export interface Rule { id: string; category: string; category_name: string; title: string; description: string; severity: Severity; cwe: string[]; references: string[]; remediation: string; evidence_requirements: string; false_positives: string; data_sources: string[]; objective: string }

export const CATEGORIES: Record<string, string> = {
  "CICD-SEC-1": "Flow Control", "CICD-SEC-2": "Identity & Access", "CICD-SEC-3": "Dependency Chain", "CICD-SEC-4": "Poisoned Pipeline Exec.",
  "CICD-SEC-5": "Pipeline Access Controls", "CICD-SEC-6": "Credential Hygiene", "CICD-SEC-7": "System Configuration",
  "CICD-SEC-8": "Third-Party Services", "CICD-SEC-9": "Artifact Integrity", "CICD-SEC-10": "Logging & Visibility",
};
export const fmtDate = (s: string | null | undefined) => (s ? new Date(s).toLocaleString() : "—");
