import { lazy, Suspense } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import ErrorBoundary from "./components/ErrorBoundary";
import Layout from "./components/Layout";
import { Spinner } from "./components/ui";
import { AuthProvider, useAuth } from "./lib/auth";
import Login from "./pages/Login";

// Routes are split so the chart-heavy overview does not load on the login screen.
const Alerts = lazy(() => import("./pages/Alerts"));
const Approvals = lazy(() => import("./pages/Approvals"));
const AuditLog = lazy(() => import("./pages/AuditLog"));
const IncidentDetail = lazy(() => import("./pages/IncidentDetail"));
const Incidents = lazy(() => import("./pages/Incidents"));
const Overview = lazy(() => import("./pages/Overview"));

function Shell() {
  const { user, ready } = useAuth();

  if (!ready) {
    return (
      <div className="boot">
        <Spinner label="Starting SOC console" />
      </div>
    );
  }
  if (!user) return <Login />;

  return (
    <Suspense
      fallback={
        <div className="boot">
          <Spinner label="Loading view" />
        </div>
      }
    >
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Overview />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="incidents" element={<Incidents />} />
          <Route path="incidents/:incidentId" element={<IncidentDetail />} />
          <Route path="approvals" element={<Approvals />} />
          <Route
            path="audit"
            element={user.role === "admin" ? <AuditLog /> : <Navigate to="/" replace />}
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </Suspense>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <ErrorBoundary>
          <Shell />
        </ErrorBoundary>
      </BrowserRouter>
    </AuthProvider>
  );
}
