import { useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import type { AgentStatus } from "../types";

const NAV = [
  { to: "/", label: "Overview", icon: "◉", end: true },
  { to: "/alerts", label: "Alerts", icon: "⚡" },
  { to: "/incidents", label: "Incidents", icon: "⚠" },
  { to: "/approvals", label: "Approvals", icon: "✓" },
  { to: "/audit", label: "Audit log", icon: "≡", adminOnly: true },
];

export default function Layout() {
  const { user, logout } = useAuth();
  const [agent, setAgent] = useState<AgentStatus | null>(null);

  useEffect(() => {
    api.agentStatus().then(setAgent).catch(() => setAgent(null));
  }, []);

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">◆</span>
          <div>
            <strong>AEGIS</strong>
            <span className="brand-sub">SOC ANALYST</span>
          </div>
        </div>

        <nav>
          {NAV.filter((item) => !item.adminOnly || user?.role === "admin").map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) => `nav-item${isActive ? " active" : ""}`}
            >
              <span className="nav-icon" aria-hidden="true">
                {item.icon}
              </span>
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-foot">
          <div className="agent-pill agent-heuristic">
            <span className="dot" aria-hidden="true" />
            Rules engine
          </div>
          <p className="tiny muted">{agent?.detail ?? "Rule-based analysis; no model required."}</p>
        </div>
      </aside>

      <div className="main-wrap">
        <header className="topbar">
          <div>
            <span className="topbar-title">Security Operations Center</span>
            <span className="topbar-env">lab environment</span>
          </div>
          <div className="topbar-user">
            <div className="user-block">
              <span className="user-name">{user?.full_name}</span>
              <span className="user-role">{user?.role}</span>
            </div>
            <button type="button" className="btn ghost" onClick={logout}>
              Sign out
            </button>
          </div>
        </header>

        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
