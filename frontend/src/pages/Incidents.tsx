import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Card,
  EmptyState,
  ErrorBox,
  SeverityBadge,
  Spinner,
  StatusPill,
  confidencePct,
  formatRelative,
} from "../components/ui";
import { api } from "../lib/api";
import type { Incident } from "../types";

const STATUSES = ["", "open", "investigating", "awaiting_approval", "contained", "closed"];
const SEVERITIES = ["", "critical", "high", "medium", "low", "info"];

export default function Incidents() {
  const [incidents, setIncidents] = useState<Incident[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [q, setQ] = useState("");

  useEffect(() => {
    let cancelled = false;
    const timer = setTimeout(() => {
      api
        .incidents({ status, severity, q, limit: 100 })
        .then((list) => {
          if (!cancelled) {
            setIncidents(list);
            setError(null);
          }
        })
        .catch((err: unknown) => {
          if (!cancelled) setError(err instanceof Error ? err.message : "Unable to load incidents");
        });
    }, 200);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [status, severity, q]);

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Incidents</h1>
          <p className="muted">
            Alerts correlated by entity and behaviour. Open an incident to read the investigator and critic
            assessments.
          </p>
        </div>
        <span className="counter">{incidents?.length ?? 0} shown</span>
      </div>

      <div className="filters">
        <input
          type="search"
          placeholder="Search incident or entity…"
          value={q}
          onChange={(event) => setQ(event.target.value)}
          aria-label="Search incidents"
        />
        <select value={status} onChange={(event) => setStatus(event.target.value)} aria-label="Filter by status">
          {STATUSES.map((value) => (
            <option key={value} value={value}>
              {value ? value.replace(/_/g, " ") : "All statuses"}
            </option>
          ))}
        </select>
        <select
          value={severity}
          onChange={(event) => setSeverity(event.target.value)}
          aria-label="Filter by severity"
        >
          {SEVERITIES.map((value) => (
            <option key={value} value={value}>
              {value ? value.toUpperCase() : "All severities"}
            </option>
          ))}
        </select>
      </div>

      {error && <ErrorBox message={error} />}

      <Card>
        {!incidents ? (
          <Spinner label="Loading incidents" />
        ) : incidents.length === 0 ? (
          <EmptyState>No incidents match these filters.</EmptyState>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>P</th>
                  <th>Severity</th>
                  <th>Incident</th>
                  <th>Behaviour</th>
                  <th>Entity</th>
                  <th>Status</th>
                  <th>Alerts</th>
                  <th>Confidence</th>
                  <th>Last activity</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((incident) => (
                  <tr key={incident.id}>
                    <td>
                      <span className={`priority p${incident.priority}`}>P{incident.priority}</span>
                    </td>
                    <td>
                      <SeverityBadge severity={incident.severity} />
                    </td>
                    <td>
                      <Link className="link" to={`/incidents/${incident.id}`}>
                        {incident.title}
                      </Link>
                      <div className="mono tiny muted">INC-{String(incident.id).padStart(4, "0")}</div>
                    </td>
                    <td className="small">{incident.category.replace(/_/g, " ")}</td>
                    <td className="mono small">{incident.entity}</td>
                    <td>
                      <StatusPill status={incident.status} />
                    </td>
                    <td>{incident.alert_count}</td>
                    <td className="small">{confidencePct(incident.confidence)}</td>
                    <td className="muted small">{formatRelative(incident.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
