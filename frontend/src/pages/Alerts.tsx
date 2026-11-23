import { useEffect, useState } from "react";
import { Card, EmptyState, ErrorBox, SeverityBadge, Spinner, formatTime } from "../components/ui";
import { api } from "../lib/api";
import type { AlertPage } from "../types";

const PAGE_SIZE = 25;

const SEVERITIES = ["", "critical", "high", "medium", "low", "info"];
const STATUSES = ["", "new", "triaged", "closed"];
const CATEGORIES = ["", "brute_force", "powershell", "network", "privilege_change", "file_integrity", "other"];

export default function Alerts() {
  const [data, setData] = useState<AlertPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [category, setCategory] = useState("");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<number | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    // Typing quickly must not let an older response overwrite the newest filter.
    const timer = setTimeout(() => {
      setLoading(true);
      api
        .alerts({ q, severity, status, category, limit: PAGE_SIZE, offset }, controller.signal)
        .then((page) => {
          setData(page);
          setError(null);
        })
        .catch((err: unknown) => {
          if (controller.signal.aborted) return;
          setError(err instanceof Error ? err.message : "Unable to load alerts");
        })
        .finally(() => {
          if (!controller.signal.aborted) setLoading(false);
        });
    }, 200);
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [q, severity, status, category, offset]);

  const active = data?.items.find((alert) => alert.id === selected) ?? null;
  const total = data?.total ?? 0;

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Alert queue</h1>
          <p className="muted">Normalized Wazuh and Sysmon telemetry, newest first.</p>
        </div>
        <span className="counter">{total} alerts</span>
      </div>

      <div className="filters">
        <input
          type="search"
          placeholder="Search title, host, IP or user…"
          value={q}
          onChange={(event) => {
            setQ(event.target.value);
            setOffset(0);
          }}
          aria-label="Search alerts"
        />
        <select
          value={severity}
          onChange={(event) => {
            setSeverity(event.target.value);
            setOffset(0);
          }}
          aria-label="Filter by severity"
        >
          {SEVERITIES.map((value) => (
            <option key={value} value={value}>
              {value ? value.toUpperCase() : "All severities"}
            </option>
          ))}
        </select>
        <select
          value={category}
          onChange={(event) => {
            setCategory(event.target.value);
            setOffset(0);
          }}
          aria-label="Filter by category"
        >
          {CATEGORIES.map((value) => (
            <option key={value} value={value}>
              {value ? value.replace(/_/g, " ") : "All behaviors"}
            </option>
          ))}
        </select>
        <select
          value={status}
          onChange={(event) => {
            setStatus(event.target.value);
            setOffset(0);
          }}
          aria-label="Filter by status"
        >
          {STATUSES.map((value) => (
            <option key={value} value={value}>
              {value ? value : "All states"}
            </option>
          ))}
        </select>
      </div>

      {error && <ErrorBox message={error} />}

      <Card>
        {loading && !data ? (
          <Spinner label="Loading alerts" />
        ) : !data || data.items.length === 0 ? (
          <EmptyState>No alerts match these filters.</EmptyState>
        ) : (
          <div className="table-wrap">
            <table className="clickable">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Severity</th>
                  <th>Rule</th>
                  <th>Alert</th>
                  <th>Host</th>
                  <th>Source IP</th>
                  <th>User</th>
                  <th>Technique</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((alert) => (
                  <tr
                    key={alert.id}
                    className={selected === alert.id ? "row-active" : undefined}
                    onClick={() => setSelected(selected === alert.id ? null : alert.id)}
                  >
                    <td className="mono small">{formatTime(alert.event_time)}</td>
                    <td>
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td className="mono small">{alert.rule_id}</td>
                    <td>{alert.title}</td>
                    <td className="mono small">{alert.host ?? "—"}</td>
                    <td className="mono small">{alert.src_ip ?? "—"}</td>
                    <td className="mono small">{alert.username ?? "—"}</td>
                    <td className="small muted">{alert.technique?.split(" - ")[0] ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="pager">
          <button
            type="button"
            className="btn ghost"
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
          >
            Newer
          </button>
          <span className="muted small">
            {total === 0 ? "0" : `${offset + 1}–${Math.min(offset + PAGE_SIZE, total)}`} of {total}
          </span>
          <button
            type="button"
            className="btn ghost"
            disabled={offset + PAGE_SIZE >= total}
            onClick={() => setOffset(offset + PAGE_SIZE)}
          >
            Older
          </button>
        </div>
      </Card>

      {active && (
        <Card title={`Alert #${active.id} · ${active.title}`} subtitle={`Rule ${active.rule_id} · level ${active.rule_level} · ${active.source}`}>
          <dl className="detail-grid">
            <div>
              <dt>Observed</dt>
              <dd>{formatTime(active.event_time)}</dd>
            </div>
            <div>
              <dt>Host</dt>
              <dd className="mono">{active.host ?? "—"}</dd>
            </div>
            <div>
              <dt>Source / destination</dt>
              <dd className="mono">
                {active.src_ip ?? "—"} → {active.dst_ip ?? "—"}
              </dd>
            </div>
            <div>
              <dt>Account</dt>
              <dd className="mono">{active.username ?? "—"}</dd>
            </div>
            <div>
              <dt>Behavior</dt>
              <dd>{active.category.replace(/_/g, " ")}</dd>
            </div>
            <div>
              <dt>MITRE technique</dt>
              <dd>{active.technique ?? "—"}</dd>
            </div>
            <div>
              <dt>Incident</dt>
              <dd>{active.incident_id ? `#${active.incident_id}` : "—"}</dd>
            </div>
            <div>
              <dt>Status</dt>
              <dd>{active.status}</dd>
            </div>
          </dl>
          <div className="evidence-block">
            <h3>Event detail</h3>
            <pre>{active.description || "No description supplied by the source."}</pre>
          </div>
        </Card>
      )}
    </div>
  );
}
