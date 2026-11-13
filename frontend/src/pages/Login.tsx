import { useState, type FormEvent } from "react";
import { useAuth } from "../lib/auth";

export default function Login() {
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(email.trim(), password);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to sign in");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-page">
      <div className="login-panel">
        <div className="login-brand">
          <span className="brand-mark">◆</span>
          <div>
            <strong>AEGIS</strong>
            <span className="brand-sub">SOC ANALYST PLATFORM</span>
          </div>
        </div>

        <h1>Analyst sign in</h1>
        <p className="muted">
          Authorised personnel only. All authentication attempts and analyst actions are written to the
          audit log.
        </p>

        <form onSubmit={onSubmit} className="login-form">
          <label>
            Work email
            <input
              type="email"
              name="email"
              autoComplete="username"
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="analyst@soc.local"
            />
          </label>
          <label>
            Password
            <input
              type="password"
              name="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="••••••••••••"
            />
          </label>
          {error && (
            <p className="form-error" role="alert">
              {error}
            </p>
          )}
          <button className="btn primary" type="submit" disabled={busy}>
            {busy ? "Authenticating…" : "Sign in"}
          </button>
        </form>

        <p className="tiny muted login-foot">
          Read-only AI agents · human-approved containment · scrypt password hashing · JWT sessions
        </p>
      </div>
      <div className="login-aside">
        <h2>Continuous monitoring, explained.</h2>
        <p>
          Ingest Wazuh and Sysmon events, correlate them into incidents, and let two independent agents
          investigate: one builds the case, the other tries to break it.
        </p>
        <ul>
          <li>Severity-classified alert queue with full-text search</li>
          <li>Evidence-linked findings, hypotheses kept separate</li>
          <li>Every containment action requires an approver</li>
        </ul>
      </div>
    </div>
  );
}
