import type { ReactNode } from "react";
import type { Severity } from "../types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export function SeverityBadge({ severity }: { severity: Severity }) {
  const known = SEVERITIES.includes(severity) ? severity : "info";
  return <span className={`badge sev-${known}`}>{known.toUpperCase()}</span>;
}

export function StatusPill({ status }: { status: string }) {
  const slug = status.replace(/_/g, "-");
  return <span className={`pill status-${slug}`}>{status.replace(/_/g, " ")}</span>;
}

export function RiskPill({ level }: { level: string }) {
  return <span className={`pill risk-${level}`}>{level} risk</span>;
}

export function VerdictPill({ verdict }: { verdict: string | null }) {
  if (!verdict) return null;
  const slug = verdict.replace(/_/g, "-");
  return <span className={`pill verdict-${slug}`}>{verdict.replace(/_/g, " ")}</span>;
}

export function Card({
  title,
  subtitle,
  actions,
  children,
  className = "",
}: {
  title?: string;
  subtitle?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`card ${className}`.trim()}>
      {(title || actions) && (
        <header className="card-head">
          <div>
            {title && <h2>{title}</h2>}
            {subtitle && <p className="muted small">{subtitle}</p>}
          </div>
          {actions}
        </header>
      )}
      {children}
    </section>
  );
}

export function Stat({
  label,
  value,
  hint,
  tone,
}: {
  label: string;
  value: number | string;
  hint?: string;
  tone?: "critical" | "warning" | "ok" | "neutral";
}) {
  return (
    <div className={`stat ${tone ? `stat-${tone}` : ""}`.trim()}>
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
      {hint && <span className="stat-hint">{hint}</span>}
    </div>
  );
}

export function Spinner({ label = "Loading" }: { label?: string }) {
  return (
    <div className="loading" role="status">
      <span className="spinner" aria-hidden="true" />
      {label}…
    </div>
  );
}

export function ErrorBox({ message }: { message: string }) {
  return (
    <div className="error-box" role="alert">
      <strong>Request failed.</strong> {message}
    </div>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}

export function formatTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const value = new Date(iso);
  if (Number.isNaN(value.getTime())) return "—";
  return value.toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatRelative(iso: string | null | undefined): string {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  const minutes = Math.round(diff / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

export function confidencePct(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return `${Math.round(value * 100)}%`;
}
