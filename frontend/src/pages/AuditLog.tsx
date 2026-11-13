import { useEffect, useState } from "react";
import { Card, EmptyState, ErrorBox, Spinner, formatTime } from "../components/ui";
import { api } from "../lib/api";
import type { AuditEntry } from "../types";

export default function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");

  useEffect(() => {
    api
      .audit(200)
      .then(setEntries)
      .catch((err: unknown) => setError(err instanceof Error ? err.message : "Unable to load audit log"));
  }, []);

  if (error) return <ErrorBox message={error} />;
  if (!entries) return <Spinner label="Loading audit trail" />;

  const needle = filter.trim().toLowerCase();
  const visible = needle
    ? entries.filter((entry) =>
        [entry.actor, entry.action, entry.target, entry.actor_role].join(" ").toLowerCase().includes(needle),
      )
    : entries;

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Audit log</h1>
          <p className="muted">Immutable record of authentication, ingestion, investigation and approval events.</p>
        </div>
        <span className="counter">{entries.length} entries</span>
      </div>

      <div className="filters">
        <input
          type="search"
          placeholder="Filter by actor, action or target…"
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
          aria-label="Filter audit entries"
        />
      </div>

      <Card>
        {visible.length === 0 ? (
          <EmptyState>No audit entries match this filter.</EmptyState>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Actor</th>
                  <th>Role</th>
                  <th>Action</th>
                  <th>Target</th>
                  <th>Source IP</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((entry) => (
                  <tr key={entry.id}>
                    <td className="mono small">{formatTime(entry.ts)}</td>
                    <td className="small">{entry.actor}</td>
                    <td className="small muted">{entry.actor_role}</td>
                    <td>
                      <span className="pill">{entry.action}</span>
                    </td>
                    <td className="mono small">{entry.target || "—"}</td>
                    <td className="mono small">{entry.source_ip ?? "—"}</td>
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
