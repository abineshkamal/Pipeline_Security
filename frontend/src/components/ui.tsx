"use client";
import type { Severity, Status } from "@/lib/api";

export function SevBadge({ s }: { s: Severity | string }) {
  return <span className={`badge sev-${s}`}>{s}</span>;
}

const STATUS_LABEL: Record<string, string> = {
  PASS: "Pass", FAIL: "Fail", NOT_ASSESSED: "Not assessed", NOT_APPLICABLE: "N/A", NEEDS_MANUAL_VALIDATION: "Manual validation",
  completed: "Completed", running: "Running", queued: "Queued", failed: "Failed",
};
export function StatusBadge({ s }: { s: Status | string }) {
  return <span className={`badge st-${s}`}>{STATUS_LABEL[s] || s}</span>;
}

export function ScoreRing({ score, size = 96 }: { score: number | null | undefined; size?: number }) {
  const v = score ?? 0;
  const r = size / 2 - 8;
  const c = 2 * Math.PI * r;
  const color = score == null ? "var(--pt-muted)" : v >= 90 ? "var(--pt-pass)" : v >= 65 ? "var(--pt-medium)" : "var(--pt-critical)";
  return (
    <svg width={size} height={size} role="img" aria-label={`Posture score ${score ?? "not available"}`}>
      <circle cx={size / 2} cy={size / 2} r={r} stroke="var(--pt-line)" strokeWidth={8} fill="none" />
      <circle cx={size / 2} cy={size / 2} r={r} stroke={color} strokeWidth={8} fill="none" strokeLinecap="round"
        strokeDasharray={`${(c * v) / 100} ${c}`} transform={`rotate(-90 ${size / 2} ${size / 2})`} />
      <text x="50%" y="50%" dominantBaseline="central" textAnchor="middle" fontSize={size / 4} fontWeight={700} fill="var(--pt-ink)">
        {score == null ? "N/A" : Math.round(v)}
      </text>
    </svg>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return <div className="d-flex align-items-center gap-2 text-secondary py-4"><div className="spinner-border spinner-border-sm" />{label}</div>;
}

export function ErrorBox({ error }: { error: string | null }) {
  if (!error) return null;
  return <div className="alert alert-danger py-2">{error}</div>;
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <div className="text-center text-secondary py-5 border rounded bg-body">{children}</div>;
}
