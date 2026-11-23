export type Role = "admin" | "approver" | "analyst" | "viewer";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface User {
  id: number;
  email: string;
  full_name: string;
  role: Role;
  is_active: boolean;
  last_login_at: string | null;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export interface Alert {
  id: number;
  alert_uid: string;
  source: string;
  rule_id: string;
  rule_level: number;
  severity: Severity;
  category: string;
  detection_rule: string | null;
  suppressed: boolean;
  title: string;
  description: string;
  src_ip: string | null;
  dst_ip: string | null;
  host: string | null;
  username: string | null;
  technique: string | null;
  event_time: string;
  event_time_inferred: boolean;
  ingested_at: string;
  status: string;
  incident_id: number | null;
}

export interface AlertPage {
  items: Alert[];
  total: number;
  limit: number;
  offset: number;
}

export interface Finding {
  statement: string;
  evidence_alert_ids: number[];
  confidence: string;
  nature: "confirmed" | "hypothesis";
  source?: string;
}

export interface Recommendation {
  action_type: string;
  target: string;
  rationale: string;
  risk_level: string;
}

export interface Investigation {
  id: number;
  incident_id: number;
  agent: "investigator" | "critic";
  provider: string;
  model: string;
  engine_version: string | null;
  status: string;
  summary: string;
  findings: Finding[];
  evidence: { alert_id: number; title: string; severity: Severity }[];
  hypotheses: string[];
  unsupported_claims: string[];
  missing_information: string[];
  recommendations: Recommendation[];
  inputs: { alert_ids?: number[]; digest?: string; alert_count?: number } | null;
  priority: number | null;
  confidence: number | null;
  verdict: string | null;
  error: string | null;
  created_at: string;
}

export interface ProposedAction {
  id: number;
  incident_id: number;
  action_type: string;
  target: string;
  rationale: string;
  risk_level: string;
  status: string;
  proposed_by: string;
  proposed_by_id: number | null;
  requested_at: string;
  expires_at: string | null;
  decided_by_id: number | null;
  decided_at: string | null;
  decision_note: string | null;
  execution_status: string | null;
  execution_note: string | null;
  executed_at: string | null;
}

export interface InvestigationRun {
  id: number;
  incident_id: number;
  status: "queued" | "running" | "succeeded" | "failed";
  requested_by: string;
  requested_at: string;
  started_at: string | null;
  finished_at: string | null;
  investigator_id: number | null;
  critic_id: number | null;
  error: string | null;
}

export interface InvestigationQueued {
  run_id: number;
  incident_id: number;
  status: string;
}

export interface Approval extends ProposedAction {
  incident_title: string;
  incident_severity: Severity;
}

export interface Incident {
  id: number;
  title: string;
  entity: string;
  category: string;
  severity: Severity;
  status: string;
  priority: number;
  host: string | null;
  alert_count: number;
  first_seen: string;
  last_seen: string;
  summary: string | null;
  confidence: number | null;
  techniques: string[];
  related_incident_ids: number[];
  created_at: string;
  updated_at: string;
}

export interface IncidentDetail extends Incident {
  alerts: Alert[];
  investigations: Investigation[];
  actions: ProposedAction[];
  runs: InvestigationRun[];
}

export interface StatsOverview {
  total_alerts: number;
  open_incidents: number;
  critical_incidents: number;
  pending_approvals: number;
  alerts_last_24h: number;
  by_severity: { severity: string; count: number }[];
  timeline: { bucket: string; count: number }[];
  top_hosts: { name: string; count: number }[];
  top_categories: { name: string; count: number }[];
}

export interface AuditEntry {
  id: number;
  ts: string;
  actor: string;
  actor_role: string;
  action: string;
  target: string;
  source_ip: string | null;
  request_id: string | null;
  detail: Record<string, unknown>;
  hash: string | null;
}

export interface AgentStatus {
  mode: string;
  engine: string;
  rules_version?: string;
  rules?: number;
  detail: string;
}
