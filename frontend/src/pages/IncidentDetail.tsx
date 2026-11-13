import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  Card,
  EmptyState,
  ErrorBox,
  RiskPill,
  SeverityBadge,
  Spinner,
  StatusPill,
  VerdictPill,
  confidencePct,
  formatTime,
} from "../components/ui";
import { api } from "../lib/api";
import { canApprove, canInvestigate, useAuth } from "../lib/auth";
import type { Finding, IncidentDetail as IncidentDetailType } from "../types";

export default function IncidentDetail() {
  const { incidentId } = useParams();
  const { user } = useAuth();
  const id = Number(incidentId);
  const [incident, setIncident] = useState<IncidentDetailType | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [notes, setNotes] = useState<Record<number, string>>({});

  const load = useCallback(async () => {
    try {
      const detail = await api.incident(id);
      setIncident(detail);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load incident");
    }
  }, [id]);

  useEffect(() => {
    if (Number.isFinite(id)) void load();
  }, [id, load]);

  async function investigate() {
    setBusy("investigate");
    try {
      const detail = await api.investigate(id);
      setIncident(detail);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Investigation failed");
    } finally {
      setBusy(null);
    }
  }

  async function changeStatus(status: string) {
    setBusy("status");
    try {
      await api.setStatus(id, status);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to change status");
    } finally {
      setBusy(null);
    }
  }

  async function decide(actionId: number, decision: "approve" | "reject") {
    setBusy(`action-${actionId}`);
    try {
      await api.decide(actionId, decision, notes[actionId] ?? "");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Decision failed");
    } finally {
      setBusy(null);
    }
  }

  if (error && !incident) return <ErrorBox message={error} />;
  if (!incident) return <Spinner label="Loading incident" />;

  const investigator = incident.investigations.filter((i) => i.agent === "investigator").at(-1);
  const critic = incident.investigations.filter((i) => i.agent === "critic").at(-1);
  const confirmed = investigator?.findings.filter((f) => f.nature === "confirmed") ?? [];
  const hypotheses = investigator?.findings.filter((f) => f.nature === "hypothesis") ?? [];
  const pendingActions = incident.actions.filter((a) => a.status === "pending");

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <p className="tiny muted">
            <Link className="link" to="/incidents">
              ← Incidents
            </Link>{" "}
            · INC-{String(incident.id).padStart(4, "0")}
          </p>
          <h1>{incident.title}</h1>
          <div className="head-badges">
            <SeverityBadge severity={incident.severity} />
            <StatusPill status={incident.status} />
            <span className={`priority p${incident.priority}`}>P{incident.priority}</span>
            <span className="pill">{incident.category.replace(/_/g, " ")}</span>
            <span className="pill">confidence {confidencePct(incident.confidence)}</span>
          </div>
        </div>
        <div className="head-actions">
          {canInvestigate(user?.role) && (
            <button type="button" className="btn primary" onClick={investigate} disabled={busy !== null}>
              {busy === "investigate" ? "Investigating…" : investigator ? "Re-run investigation" : "Investigate"}
            </button>
          )}
          {canInvestigate(user?.role) && (
            <select
              aria-label="Change incident status"
              value=""
              disabled={busy !== null}
              onChange={(event) => event.target.value && changeStatus(event.target.value)}
            >
              <option value="">Change status…</option>
              <option value="investigating">investigating</option>
              {canApprove(user?.role) && <option value="contained">contained</option>}
              <option value="closed">closed</option>
            </select>
          )}
        </div>
      </div>

      {error && <ErrorBox message={error} />}

      <div className="detail-grid cards">
        <div className="mini">
          <span className="stat-label">Entity</span>
          <strong className="mono">{incident.entity}</strong>
        </div>
        <div className="mini">
          <span className="stat-label">Host</span>
          <strong className="mono">{incident.host ?? "—"}</strong>
        </div>
        <div className="mini">
          <span className="stat-label">Alerts</span>
          <strong>{incident.alert_count}</strong>
        </div>
        <div className="mini">
          <span className="stat-label">First seen</span>
          <strong>{formatTime(incident.first_seen)}</strong>
        </div>
        <div className="mini">
          <span className="stat-label">Last seen</span>
          <strong>{formatTime(incident.last_seen)}</strong>
        </div>
        <div className="mini">
          <span className="stat-label">MITRE</span>
          <strong className="small">{incident.techniques.join(", ") || "—"}</strong>
        </div>
      </div>

      <Card
        title="AI investigation summary"
        subtitle={
          investigator
            ? `${investigator.provider} · ${investigator.model} · reviewer verdict: ${critic?.verdict ?? "pending"}`
            : "No investigation has been run yet"
        }
      >
        {incident.summary ? (
          <p className="summary-text">{incident.summary}</p>
        ) : (
          <EmptyState>
            Run an investigation to have the investigator agent build a case and the critic agent review it.
          </EmptyState>
        )}
        {investigator?.error && (
          <p className="notice">
            <strong>Model note:</strong> {investigator.error}
          </p>
        )}
      </Card>

      <div className="grid-2">
        <Card
          title="Investigator findings"
          subtitle={
            investigator
              ? `${confirmed.length} confirmed · ${hypotheses.length} hypothesis · ${investigator.findings.length} total`
              : undefined
          }
        >
          {!investigator ? (
            <EmptyState>No investigator report yet.</EmptyState>
          ) : (
            <div className="stack-tight">
              <h3 className="section-label">Confirmed from evidence</h3>
              <FindingList findings={confirmed} empty="No confirmed findings." />
              <h3 className="section-label">Hypotheses (unconfirmed)</h3>
              <FindingList findings={hypotheses} empty="No hypotheses recorded." />
              {investigator.hypotheses.length > 0 && (
                <ul className="hypothesis-list">
                  {investigator.hypotheses.map((item, index) => (
                    <li key={index}>{item}</li>
                  ))}
                </ul>
              )}
              <h3 className="section-label">Recommended actions (proposals only)</h3>
              {investigator.recommendations.length === 0 ? (
                <p className="muted small">No recommendations.</p>
              ) : (
                <ul className="recommendations">
                  {investigator.recommendations.map((rec, index) => (
                    <li key={index}>
                      <strong>{rec.action_type.replace(/_/g, " ")}</strong> →{" "}
                      <span className="mono">{rec.target}</span>
                      <p className="muted small">{rec.rationale}</p>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </Card>

        <Card title="Independent review" subtitle="Critic agent: can the findings be supported?">
          {!critic ? (
            <EmptyState>No critic review yet.</EmptyState>
          ) : (
            <div className="stack-tight">
              <div className="head-badges">
                <VerdictPill verdict={critic.verdict} />
                <span className="pill">confidence {confidencePct(critic.confidence)}</span>
                <span className="pill">{critic.provider}</span>
              </div>
              <p className="summary-text">{critic.summary}</p>
              <h3 className="section-label">Unsupported claims</h3>
              {critic.unsupported_claims.length === 0 ? (
                <p className="muted small">No unsupported claims were found.</p>
              ) : (
                <ul className="warn-list">
                  {critic.unsupported_claims.map((item, index) => (
                    <li key={index}>{item}</li>
                  ))}
                </ul>
              )}
              <h3 className="section-label">Missing information</h3>
              {critic.missing_information.length === 0 ? (
                <p className="muted small">Nothing flagged.</p>
              ) : (
                <ul className="muted-list">
                  {critic.missing_information.map((item, index) => (
                    <li key={index}>{item}</li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </Card>
      </div>

      <Card
        title="Containment actions"
        subtitle={
          canApprove(user?.role)
            ? "Approval is required before anything is executed. Execution is simulated (dry-run)."
            : "Actions proposed by agents. An approver must decide before anything is executed."
        }
        actions={<span className="counter">{pendingActions.length} pending</span>}
      >
        {incident.actions.length === 0 ? (
          <EmptyState>No actions proposed for this incident.</EmptyState>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Action</th>
                  <th>Target</th>
                  <th>Risk</th>
                  <th>Proposed by</th>
                  <th>Status</th>
                  <th>Decision</th>
                </tr>
              </thead>
              <tbody>
                {incident.actions.map((action) => (
                  <tr key={action.id}>
                    <td>
                      <strong>{action.action_type.replace(/_/g, " ")}</strong>
                      <div className="muted tiny">{action.rationale}</div>
                    </td>
                    <td className="mono small">{action.target}</td>
                    <td>
                      <RiskPill level={action.risk_level} />
                    </td>
                    <td className="small">{action.proposed_by}</td>
                    <td>
                      <span className={`pill status-${action.status}`}>{action.status}</span>
                    </td>
                    <td>
                      {action.status === "pending" && canApprove(user?.role) ? (
                        <div className="decision">
                          <input
                            placeholder="Decision note (optional)"
                            value={notes[action.id] ?? ""}
                            onChange={(event) =>
                              setNotes((current) => ({ ...current, [action.id]: event.target.value }))
                            }
                            aria-label={`Decision note for action ${action.id}`}
                          />
                          <div className="decision-buttons">
                            <button
                              type="button"
                              className="btn approve"
                              disabled={busy === `action-${action.id}`}
                              onClick={() => decide(action.id, "approve")}
                            >
                              Approve
                            </button>
                            <button
                              type="button"
                              className="btn reject"
                              disabled={busy === `action-${action.id}`}
                              onClick={() => decide(action.id, "reject")}
                            >
                              Reject
                            </button>
                          </div>
                        </div>
                      ) : (
                        <span className="muted small">{action.decision_note || "—"}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card title="Correlated alerts" subtitle={`${incident.alerts.length} alerts in this incident`}>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Severity</th>
                <th>Alert</th>
                <th>Host</th>
                <th>Source</th>
                <th>User</th>
              </tr>
            </thead>
            <tbody>
              {incident.alerts.map((alert) => (
                <tr key={alert.id}>
                  <td className="mono small">{formatTime(alert.event_time)}</td>
                  <td>
                    <SeverityBadge severity={alert.severity} />
                  </td>
                  <td>{alert.title}</td>
                  <td className="mono small">{alert.host ?? "—"}</td>
                  <td className="mono small">{alert.src_ip ?? "—"}</td>
                  <td className="mono small">{alert.username ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

function FindingList({ findings, empty }: { findings: Finding[]; empty: string }) {
  if (findings.length === 0) return <p className="muted small">{empty}</p>;
  return (
    <ul className="findings">
      {findings.map((finding, index) => (
        <li key={index} className={`finding ${finding.nature}`}>
          <span>{finding.statement}</span>
          <span className="finding-meta">
            {finding.evidence_alert_ids.length > 0 && (
              <span className="evidence-ids">alerts {finding.evidence_alert_ids.join(", ")}</span>
            )}
            <span className="pill tiny">{finding.confidence}</span>
            {finding.source === "llm" && <span className="pill tiny">model</span>}
          </span>
        </li>
      ))}
    </ul>
  );
}
