import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import { Spinner } from "./components/ui";
import { AuthProvider, useAuth } from "./lib/auth";
import Alerts from "./pages/Alerts";
import Approvals from "./pages/Approvals";
import AuditLog from "./pages/AuditLog";
import IncidentDetail from "./pages/IncidentDetail";
import Incidents from "./pages/Incidents";
import Login from "./pages/Login";
import Overview from "./pages/Overview";

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
  );
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Shell />
      </BrowserRouter>
    </AuthProvider>
  );
}
