import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Card, EmptyState, ErrorBox, RiskPill, SeverityBadge, Spinner, formatTime } from "../components/ui";
import { api } from "../lib/api";
import { canApprove, useAuth } from "../lib/auth";
import type { Approval } from "../types";

export default function Approvals() {
  const { user } = useAuth();
  const [items, setItems] = useState<Approval[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const [notes, setNotes] = useState<Record<number, string>>({});

  async function load() {
    try {
      setItems(await api.approvals("pending"));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load approvals");
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function decide(actionId: number, decision: "approve" | "reject") {
    setBusy(actionId);
    try {
      await api.decide(actionId, decision, notes[actionId] ?? "");
      setItems((current) => (current ? current.filter((item) => item.id !== actionId) : current));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Decision failed");
    } finally {
      setBusy(null);
    }
  }

  if (error && !items) return <ErrorBox message={error} />;
  if (!items) return <Spinner label="Loading approval queue" />;

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Approval queue</h1>
          <p className="muted">
            Agents can only propose. Nothing here executes without an approver, and approved actions are
            recorded as a simulated (dry-run) containment.
          </p>
        </div>
        <span className="counter">{items.length} pending</span>
      </div>

      {error && <ErrorBox message={error} />}

      <Card title="Awaiting decision" subtitle="Highest risk first is recommended — review the linked incident evidence">
        {items.length === 0 ? (
          <EmptyState>Nothing awaiting approval. Investigate an incident to generate proposals.</EmptyState>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Requested</th>
                  <th>Incident</th>
                  <th>Action</th>
                  <th>Target</th>
                  <th>Risk</th>
                  <th>Rationale</th>
                  <th>Decision</th>
                </tr>
              </thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item.id}>
                    <td className="mono small">
                      {formatTime(item.requested_at)}
                      {item.expires_at && (
                        <div className="tiny muted">expires {formatTime(item.expires_at)}</div>
                      )}
                    </td>
                    <td>
                      <Link className="link" to={`/incidents/${item.incident_id}`}>
                        {item.incident_title}
                      </Link>
                      <div className="spacer-4">
                        <SeverityBadge severity={item.incident_severity} />
                      </div>
                    </td>
                    <td>
                      <strong>{item.action_type.replace(/_/g, " ")}</strong>
                      <div className="muted tiny">{item.proposed_by}</div>
                    </td>
                    <td className="mono small">{item.target}</td>
                    <td>
                      <RiskPill level={item.risk_level} />
                    </td>
                    <td className="small muted">{item.rationale}</td>
                    <td>
                      {canApprove(user?.role) ? (
                        item.proposed_by_id !== null && item.proposed_by_id === user?.id ? (
                          <span className="muted small">Your own proposal — another approver must decide</span>
                        ) : (
                        <div className="decision">
                          <input
                            placeholder="Note"
                            value={notes[item.id] ?? ""}
                            onChange={(event) =>
                              setNotes((current) => ({ ...current, [item.id]: event.target.value }))
                            }
                            aria-label={`Decision note for action ${item.id}`}
                          />
                          <div className="decision-buttons">
                            <button
                              type="button"
                              className="btn approve"
                              disabled={busy === item.id}
                              onClick={() => decide(item.id, "approve")}
                            >
                              Approve
                            </button>
                            <button
                              type="button"
                              className="btn reject"
                              disabled={busy === item.id}
                              onClick={() => decide(item.id, "reject")}
                            >
                              Reject
                            </button>
                          </div>
                        </div>
                        )
                      ) : (
                        <span className="muted small">approver role required</span>
                      )}
                    </td>
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
