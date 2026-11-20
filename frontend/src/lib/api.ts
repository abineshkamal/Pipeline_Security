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
  put: <T,>(p: string, body: unknown) =>
    fetch(API_BASE + p, { method: "PUT", headers: headers({ "Content-Type": "application/json" }), body: JSON.stringify(body) }).then((r) => handle<T>(r)),
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
  credential_id: string | null; created_at: string; scan_count: number; schedule: "" | "daily" | "weekly"; next_scan_at: string | null;
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
  options: { tools: string[]; ai: boolean; ref?: string; trigger?: string }; ref?: string; trigger?: string;
  summary?: Summary; inventory?: Inventory; controls?: Control[]; tool_runs?: ToolRun[];
  attack_graph?: { nodes: GraphNode[]; edges: GraphEdge[]; paths: AttackPath[]; stats: Record<string, number> };
  ai_analysis?: AIAnalysis; project?: { id: string; name: string; source_type: string; repo_full_name: string };
}
export interface Inventory {
  source: string; repository: string; default_branch: string; visibility: string; file_count: number;
  workflows: { path: string; name: string; error: string | null; triggers: string[]; external_triggers: string[]; privileged_triggers: string[];
    jobs: { id: string; name?: string; line?: number; runs_on: string[]; self_hosted: boolean; environment: string | null; secrets: string[]; write_scopes: string[] | null;
      permissions_source: string; deploy_indicators: string[]; steps?: number; reusable?: string | null }[] }[];
  actions: { uses: string; kind: string; owner: string; action: string; ref: string; sha_pinned: boolean; first_party: boolean; workflows: string[]; count: number }[];
  secrets: Record<string, string[]>; self_hosted_runners: Record<string, string[]>; environments: Record<string, string[]>;
  other_ci_systems: { system: string; file: string }[]; sbom_available?: boolean;
}
export interface Finding {
  id: string; rule_id: string; category: string; title: string; severity: Severity; confidence: string; risk_score: number; evidence_type: string;
  message: string; file_path: string; line: number | null; snippet: string; workflow: string; job: string; fingerprint: string;
  extra: Record<string, unknown> & { corroborated_by?: string[]; suggested_pin?: string;
    exception?: { id: string; expires_on: string; owner: string; approved_by: string; scope: string };
    ticket?: { key: string; url: string; system: string; status: string } };
  triage_status: string; validation_status: string; triage_note: string;
  ai_notes: { triage?: { exploitability: string; priority: string; rationale: string; false_positive_likelihood: string; source: string }; fix?: { explanation: string; patch: string; source: string } };
}
export type Workflow = Inventory["workflows"][number];
export interface PipelineSummary {
  path: string; name: string; error: string | null; triggers: string[]; external_triggers: string[]; privileged_triggers: string[];
  jobs: number; secrets: string[]; self_hosted: boolean; write_access: boolean; deploys: boolean;
  findings: number; open_findings: number; severity_counts: SevCounts; max_risk: number; attack_paths: number;
}
export interface ProjectPipelines {
  scan: { id: string; created_at: string; commit_sha: string; posture_score: number | null } | null;
  pipelines: PipelineSummary[]; repo_setting_findings: number; other_ci_systems: { system: string; file: string }[];
}
export interface PipelineDetail {
  scan: { id: string; created_at: string; commit_sha: string };
  project: { id: string; name: string; repo_full_name: string; source_type: string };
  summary: PipelineSummary; workflow: Workflow; actions: Inventory["actions"];
  findings: Finding[]; categories: Record<string, number>; repo_setting_findings: Finding[];
  attack_paths: AttackPath[]; graph: { nodes: GraphNode[]; edges: GraphEdge[] };
  pipelines: { path: string; name: string }[];
}
export type Level = "critical" | "high" | "medium" | "low";
export interface SecretUse {
  workflow: string; workflow_name: string; job: string; triggers: string[]; reach: string; reach_reason: string; environment: string;
  self_hosted: boolean; write_scopes: string[]; level: Level; exposing_findings: { id: string; rule_id: string; title: string; severity: Severity; line: number | null }[];
}
export interface Rotation { status: "ok" | "aging" | "stale" | "missing" | "unknown" | "automatic"; detail: string; age_days?: number; updated_at?: string; scope?: string }
export interface SecretsMap {
  secrets: { name: string; level: Level; reach: string; pipelines: number; jobs: number; attack_paths: number; rotation: Rotation; rotate_first: boolean; uses: SecretUse[] }[];
  counts: Record<Level, number>; outsider_reachable: number;
  rotation: { status: string; detail: string; counts: Record<string, number>; aging_days: number; stale_days: number; rotate_first: string[] };
}
export interface PortfolioRow {
  rank: number; project_id: string; name: string; repo: string; source_type: string; team: string; scan_id: string | null; scanned_at: string | null;
  posture_score: number | null; grade: string | null; score_delta: number | null; severity_counts: Partial<SevCounts>; attack_paths: number;
  outsider_secrets: number; stale_secrets: number; open_findings: number; workflows: number; exceptions_active: number; exceptions_pending: number;
  open_alerts: number; schedule: string; next_scan_at: string | null; last_status: string | null; last_error: string;
}
export interface Portfolio {
  totals: { projects: number; assessed: number; average_score: number | null; critical: number; attack_paths: number; outsider_secrets: number;
    stale_secrets: number; open_alerts: number; scheduled: number; never_scanned: number; failed_last_scan: number };
  projects: PortfolioRow[];
  teams: { team: string; projects: number; assessed: number; average_score: number | null; worst_score: number | null; critical: number; high: number;
    attack_paths: number; outsider_secrets: number; open_alerts: number }[];
}
export interface DriftItem { kind: string; severity: Severity; text: string; ref?: string; rule_id?: string }
export interface DriftAlert {
  id: string; project_id: string; project: string; scan_id: string; previous_scan_id: string; severity: Severity; title: string; items: DriftItem[];
  deliveries: { channel: string; ok: boolean; detail: string }[]; created_at: string; acknowledged_by: string; acknowledged_at: string | null;
}
export interface Channel { id: string; name: string; kind: "slack" | "teams" | "webhook"; url_hint: string; min_severity: string; enabled: boolean; created_at: string }
export interface RiskException {
  id: string; project_id: string; project: string; scope: "finding" | "rule"; rule_id: string; workflow: string; title: string; reason: string;
  compensating_controls: string; owner: string; expires_on: string; status: string; state: "pending" | "active" | "expired" | "rejected" | "revoked";
  days_left: number | null; expiring_soon: boolean; requested_by: string; requested_at: string; decided_by: string; decided_at: string | null;
  decision_note: string; matched_findings: number;
}
export interface WhatIfState { posture_score: number | null; grade: string; severity_counts: SevCounts; findings: number; attack_paths: number; path_ids: string[]; categories: Record<string, number | null>; controls_fixed: string[] }
export interface WhatIf { fixed: string[]; before: WhatIfState; after: WhatIfState; score_delta: number | null; removed_paths: string[]; category_deltas: Record<string, number | null> }
export interface Impact { score_gain: number | null; paths_removed: number; after_score: number | null; controls_fixed: string[]; auto_fixable: boolean }
export interface Recommendations {
  baseline: { posture_score: number | null; grade: string; attack_paths: number; findings: number };
  by_rule: (Impact & { rule_id: string; title: string; category: string; findings: number; finding_ids: string[] })[];
  single_fixes: (Impact & { finding_id: string; rule_id: string; title: string; severity: Severity; location: string; job: string })[];
}
export interface FixItem { finding_id: string; rule_id: string; label: string; title: string; severity: Severity; file: string; line: number | null; job: string; status: "applied" | "skipped"; detail: string; review: string; verified: boolean }
export interface FixPlan {
  files: { path: string; diff: string; patched: string; parse_error: string | null; verified: boolean; introduced: { rule_id: string; job: string }[]; resolved: number; applied: number }[];
  fixes: FixItem[]; patch: string; fixable_rules: Record<string, string>;
  summary: { candidates: number; applied: number; verified: number; skipped: number; needs_review: number; files: number; introduced: number };
}
export interface CompliancePack {
  framework: string; name: string; disclaimer: string; satisfied_percent: number; counts: Record<string, number>; frameworks: { id: string; name: string }[];
  requirements: { id: string; title: string; status: string; open_findings: number;
    evidence: { rule_id: string; title: string; status: string; note: string; evidence: string[]; open_findings: number; accepted_risk: number;
      findings: { id: string; title: string; severity: Severity; location: string; triage: string }[] }[] }[];
}
export interface AskRef { kind: "finding" | "path" | "pipeline" | "secret"; id: string; label: string; pipeline?: string | null }
export interface AskAnswer { answer: string; references: AskRef[]; mode: string; intent?: string | null; examples?: string[]; note?: string; provider?: string; model?: string; guardrail?: { dropped_count: number; dropped_references: string[] } }
export const pipelineHref =(scanId: string, path: string) => `/pipeline?scan=${scanId}&path=${encodeURIComponent(path)}`;
export interface Rule { id: string; category: string; category_name: string; title: string; description: string; severity: Severity; cwe: string[]; references: string[]; remediation: string; evidence_requirements: string; false_positives: string; data_sources: string[]; objective: string }

export const CATEGORIES: Record<string, string> = {
  "CICD-SEC-1": "Flow Control", "CICD-SEC-2": "Identity & Access", "CICD-SEC-3": "Dependency Chain", "CICD-SEC-4": "Poisoned Pipeline Exec.",
  "CICD-SEC-5": "Pipeline Access Controls", "CICD-SEC-6": "Credential Hygiene", "CICD-SEC-7": "System Configuration",
  "CICD-SEC-8": "Third-Party Services", "CICD-SEC-9": "Artifact Integrity", "CICD-SEC-10": "Logging & Visibility",
};
export const fmtDate = (s: string | null | undefined) => (s ? new Date(s).toLocaleString() : "—");

export interface DiffChange { kind: string; risk: "increase" | "decrease" | "neutral"; text: string; workflow: string; job?: string; secret?: string; action?: string }
export interface DiffScan { id: string; ref: string; commit_sha: string; created_at: string; posture_score: number | null; grade: string | null; workflows: number; attack_paths: number }
export interface PipelineDiff {
  project: { id: string; name: string }; from: DiffScan; to: DiffScan; score_delta: number | null;
  counts: { increase: number; decrease: number; neutral: number; new_findings: number; fixed_findings: number; new_paths: number; removed_paths: number };
  changes: DiffChange[];
  new_attack_paths: { id: string; risk: number; labels: string[]; impact: string }[]; removed_attack_paths: { id: string; risk: number; labels: string[]; impact: string }[];
  new_findings: { id: string; rule_id: string; title: string; severity: Severity; file_path: string; line: number | null }[];
  fixed_findings: { id: string; rule_id: string; title: string; severity: Severity; file_path: string; line: number | null }[];
}
export interface StoryEvidence { id: string; rule_id: string; title: string; severity: Severity; file_path: string; line: number | null; job: string }
export interface PathStory {
  path: { id: string; risk: number; impact: string; actor: string; labels: string[]; gated_by: string[]; length: number };
  story: string; steps: { step: number; node: string; type: string; label: string; action: string; defence: string; evidence: StoryEvidence[] }[];
  breakers: (StoryEvidence & { paths_removed: number; score_gain: number | null; auto_fixable: boolean })[];
  step_fixes: { step: number; finding_ids: string[]; rule_ids: string[]; findings: number; paths_removed: number; score_gain: number | null; auto_fixable: boolean }[];
  fix_all: { finding_ids: string[]; paths_removed: number; score_gain: number | null }; note: string;
}
export interface RuntimeWorkflow {
  workflow: string; name: string; runs: number; events: Record<string, number>; last_run: string | null; days_since_last_run: number | null;
  fork_runs: number; privileged_fork_runs: number; outsider_privileged_runs: number; failure_rate: number | null; holds_secrets: boolean;
  privileged_triggers: string[]; flags: string[]; examples: { url: string; event: string; actor: string; head: string; created_at: string }[];
}
export interface RuntimeEvidence {
  status: string; detail: string; runs_analysed?: number; window?: { from: string | null; to: string }; dormant_days?: number;
  workflows: RuntimeWorkflow[]; observed: { workflow: string; name: string; runs: number; text: string }[];
  counts?: { observed_untrusted_trigger: number; dormant_with_secrets: number };
}
export interface Runners {
  runners: { name: string; scope: string; os: string; status: string; busy: boolean; labels: string[]; ephemeral: boolean | null }[];
  groups: { name: string; visibility: string; allows_public_repositories: boolean; restricted_to_workflows: boolean; default: boolean }[];
  self_hosted_jobs: { workflow: string; workflow_name: string; job: string; labels: string[]; fork_reachable: boolean; secrets: string[]; matching_runners: string[] }[];
  risks: { severity: Severity; text: string }[]; access: Record<string, string>; note: string;
}
export interface TicketIntegration { id: string; name: string; kind: "jira" | "servicenow"; base_url: string; target: string; issue_type: string; username: string; close_action: string; enabled: boolean; created_at: string }
export interface TicketLink { id: string; project_id: string; project?: string; fingerprint: string; rule_id: string; title: string; system: string; key: string; url: string;
  status: "open" | "resolved"; created_by: string; created_at: string; resolved_at: string | null; sync_detail: string }

/** Open an authenticated HTML page (report) in a new tab. */
export async function openHtml(path: string) {
  const w = window.open("", "_blank");
  const r = await fetch(API_BASE + path, { headers: headers() });
  const html = await r.text();
  const url = URL.createObjectURL(new Blob([html], { type: "text/html" }));
  if (w) w.location.href = url; else window.location.href = url;
}
