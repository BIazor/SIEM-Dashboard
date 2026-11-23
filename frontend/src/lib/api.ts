import type {
  Alert,
  AlertPage,
  AgentStatus,
  Approval,
  AuditEntry,
  Incident,
  IncidentDetail,
  Investigation,
  InvestigationQueued,
  InvestigationRun,
  LoginResponse,
  ProposedAction,
  StatsOverview,
  User,
} from "../types";

// The session is an httpOnly cookie set by the API; the browser never holds the token.
const USER_KEY = "aegis.user";

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export function storeUser(user: User): void {
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function getStoredUser(): User | null {
  const raw = localStorage.getItem(USER_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as User;
  } catch {
    return null;
  }
}

export function clearSession(): void {
  localStorage.removeItem(USER_KEY);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body !== undefined) headers.set("Content-Type", "application/json");

  const response = await fetch(path, { ...init, headers, credentials: "include" });
  if (response.status === 401 && !path.startsWith("/api/auth/login")) {
    clearSession();
    // Let AuthProvider drop the in-memory user so the UI does not keep a stale session.
    window.dispatchEvent(new Event("aegis:session-expired"));
  }
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      if (typeof body.detail === "string") detail = body.detail;
      else if (Array.isArray(body.detail) && body.detail.length > 0) {
        detail = body.detail[0]?.msg ?? detail;
      }
    } catch {
      /* response body was not JSON */
    }
    throw new ApiError(response.status, detail);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

function query(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== "") search.set(key, String(value));
  });
  const text = search.toString();
  return text ? `?${text}` : "";
}

export const api = {
  login: (email: string, password: string) =>
    request<LoginResponse>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),
  logout: () => request<{ status: string }>("/api/auth/logout", { method: "POST" }),
  changePassword: (currentPassword: string, newPassword: string) =>
    request<{ status: string }>("/api/auth/password", {
      method: "POST",
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    }),
  me: () => request<User>("/api/auth/me"),
  overview: () => request<StatsOverview>("/api/stats/overview"),
  alerts: (
    params: {
      q?: string;
      severity?: string;
      status?: string;
      category?: string;
      limit?: number;
      offset?: number;
    },
    signal?: AbortSignal,
  ) => request<AlertPage>(`/api/alerts${query(params)}`, { signal }),
  alert: (id: number) => request<Alert>(`/api/alerts/${id}`),
  incidents: (
    params: { q?: string; status?: string; severity?: string; limit?: number; offset?: number },
    signal?: AbortSignal,
  ) => request<Incident[]>(`/api/incidents${query(params)}`, { signal }),
  incident: (id: number, signal?: AbortSignal) =>
    request<IncidentDetail>(`/api/incidents/${id}`, { signal }),
  investigations: (id: number) => request<Investigation[]>(`/api/incidents/${id}/investigations`),
  runs: (id: number) => request<InvestigationRun[]>(`/api/incidents/${id}/runs`),
  investigate: (id: number) =>
    request<InvestigationQueued>(`/api/incidents/${id}/investigate`, { method: "POST" }),
  setStatus: (id: number, status: string) =>
    request<Incident>(`/api/incidents/${id}/status`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),
  proposeAction: (
    id: number,
    body: { action_type: string; target: string; rationale: string; risk_level: string },
  ) =>
    request<ProposedAction>(`/api/incidents/${id}/actions`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  approvals: (status = "pending") => request<Approval[]>(`/api/approvals${query({ status })}`),
  decide: (id: number, decision: "approve" | "reject", note: string) =>
    request<Approval>(`/api/approvals/${id}/decision`, {
      method: "POST",
      body: JSON.stringify({ decision, note }),
    }),
  audit: (limit = 100) => request<AuditEntry[]>(`/api/audit${query({ limit })}`),
  agentStatus: () => request<AgentStatus>("/api/agents/status"),
};
