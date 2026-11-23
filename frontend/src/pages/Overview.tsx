import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Card, EmptyState, ErrorBox, SeverityBadge, Spinner, Stat, StatusPill, formatRelative } from "../components/ui";
import { api } from "../lib/api";
import type { Incident, StatsOverview } from "../types";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ff4d6d",
  high: "#ff8a3d",
  medium: "#ffd166",
  low: "#4cc9f0",
  info: "#8b98a8",
};

const tooltipStyle = {
  background: "#0f1722",
  border: "1px solid #24303f",
  borderRadius: 8,
  color: "#e6edf6",
  fontSize: 12,
};

export default function Overview() {
  const [stats, setStats] = useState<StatsOverview | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let canceled = false;

    const load = () => {
      Promise.all([api.overview(), api.incidents({ limit: 6 })])
        .then(([overview, list]) => {
          if (canceled) return;
          setStats(overview);
          setIncidents(list);
          setError(null);
        })
        .catch((err: unknown) => {
          if (!canceled) setError(err instanceof Error ? err.message : "Unable to load dashboard");
        });
    };

    load();
    // The collector ships events continuously, so keep the "live" view current.
    const timer = window.setInterval(load, 15_000);
    return () => {
      canceled = true;
      window.clearInterval(timer);
    };
  }, []);

  if (error) return <ErrorBox message={error} />;
  if (!stats) return <Spinner label="Loading telemetry" />;

  const timeline = stats.timeline.map((point) => ({
    ...point,
    label: new Date(point.bucket).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
  }));

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Operations overview</h1>
          <p className="muted">Correlated security events across monitored endpoints and servers.</p>
        </div>
        <span className="live-tag">
          <span className="dot" aria-hidden="true" /> live
        </span>
      </div>

      <div className="stat-grid">
        <Stat label="Alerts (24h)" value={stats.alerts_last_24h} hint={`${stats.total_alerts} total retained`} />
        <Stat
          label="Open incidents"
          value={stats.open_incidents}
          hint="open, investigating or awaiting approval"
          tone="warning"
        />
        <Stat label="Critical" value={stats.critical_incidents} hint="unresolved critical incidents" tone="critical" />
        <Stat label="Pending approvals" value={stats.pending_approvals} hint="agent-proposed actions" tone="ok" />
      </div>

      <div className="grid-2">
        <Card title="Alert volume" subtitle="Last 24 hours, hourly buckets">
          <div className="chart">
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={timeline} margin={{ top: 8, right: 12, left: -18, bottom: 0 }}>
                <CartesianGrid stroke="#1b2634" strokeDasharray="3 3" />
                <XAxis dataKey="label" stroke="#7d8fa5" fontSize={11} interval={3} tickLine={false} />
                <YAxis stroke="#7d8fa5" fontSize={11} allowDecimals={false} tickLine={false} />
                <Tooltip contentStyle={tooltipStyle} labelStyle={{ color: "#9fb0c6" }} />
                <Line type="monotone" dataKey="count" stroke="#4cc9f0" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card title="Severity mix" subtitle="All retained alerts">
          <div className="chart chart-split">
            <ResponsiveContainer width="55%" height={200}>
              <PieChart>
                <Pie
                  data={stats.by_severity.filter((bucket) => bucket.count > 0)}
                  dataKey="count"
                  nameKey="severity"
                  innerRadius={48}
                  outerRadius={76}
                  paddingAngle={2}
                  stroke="#0b1119"
                >
                  {stats.by_severity
                    .filter((bucket) => bucket.count > 0)
                    .map((bucket) => (
                      <Cell key={bucket.severity} fill={SEVERITY_COLORS[bucket.severity] ?? "#8b98a8"} />
                    ))}
                </Pie>
                <Tooltip contentStyle={tooltipStyle} />
              </PieChart>
            </ResponsiveContainer>
            <ul className="legend">
              {stats.by_severity.map((bucket) => (
                <li key={bucket.severity}>
                  <span
                    className="legend-dot"
                    style={{ background: SEVERITY_COLORS[bucket.severity] ?? "#8b98a8" }}
                    aria-hidden="true"
                  />
                  <span className="legend-label">{bucket.severity}</span>
                  <strong>{bucket.count}</strong>
                </li>
              ))}
            </ul>
          </div>
        </Card>
      </div>

      <div className="grid-2">
        <Card title="Most active hosts" subtitle="Alert volume by endpoint">
          <div className="chart">
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={stats.top_hosts} margin={{ top: 8, right: 12, left: -18, bottom: 0 }}>
                <CartesianGrid stroke="#1b2634" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="name" stroke="#7d8fa5" fontSize={11} tickLine={false} />
                <YAxis stroke="#7d8fa5" fontSize={11} allowDecimals={false} tickLine={false} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "rgba(76,201,240,0.08)" }} />
                <Bar dataKey="count" fill="#3f8cff" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card title="Detection coverage" subtitle="Alerts by behavior category">
          <ul className="category-list">
            {stats.top_categories.map((category) => (
              <li key={category.name}>
                <span className="category-name">{category.name.replace(/_/g, " ")}</span>
                <span className="category-bar" aria-hidden="true">
                  <span
                    style={{
                      width: `${Math.max(
                        6,
                        (category.count / Math.max(1, stats.top_categories[0]?.count ?? 1)) * 100,
                      )}%`,
                    }}
                  />
                </span>
                <strong>{category.count}</strong>
              </li>
            ))}
            {stats.top_categories.length === 0 && <EmptyState>No categorized alerts yet.</EmptyState>}
          </ul>
        </Card>
      </div>

      <Card
        title="Incident queue"
        subtitle="Priority-ordered; agents investigate, humans decide"
        actions={
          <Link className="btn ghost" to="/incidents">
            View all
          </Link>
        }
      >
        {incidents.length === 0 ? (
          <EmptyState>No incidents yet. Run the attack simulator to generate telemetry.</EmptyState>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Priority</th>
                  <th>Severity</th>
                  <th>Incident</th>
                  <th>Entity</th>
                  <th>Status</th>
                  <th>Alerts</th>
                  <th>Last seen</th>
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
                    </td>
                    <td className="mono">{incident.entity}</td>
                    <td>
                      <StatusPill status={incident.status} />
                    </td>
                    <td>{incident.alert_count}</td>
                    <td className="muted">{formatRelative(incident.last_seen)}</td>
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
