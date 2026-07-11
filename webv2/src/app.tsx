import { lazy, useEffect, type ReactNode } from "react";
import { Navigate, Route, Routes, useLocation, useNavigate } from "react-router";
import { registerUnauthorizedHandler } from "@/api/http";
import { isAdminRole } from "@/lib/auth";
import { useSession } from "@/hooks/queries";
import { AppShell } from "@/components/layout/app-shell";
import { LoginPage } from "@/pages/login";

// Route-level code splitting — the old app shipped one ~670 KB chunk.
const DashboardPage = lazy(() => import("@/pages/dashboard").then((m) => ({ default: m.DashboardPage })));
const ConnectionsPage = lazy(() => import("@/pages/connections").then((m) => ({ default: m.ConnectionsPage })));
const TunnelsPage = lazy(() => import("@/pages/tunnels").then((m) => ({ default: m.TunnelsPage })));
const UsersPage = lazy(() => import("@/pages/users/index").then((m) => ({ default: m.UsersPage })));
const UserDetailPage = lazy(() => import("@/pages/users/detail").then((m) => ({ default: m.UserDetailPage })));
const GroupsPage = lazy(() => import("@/pages/groups/index").then((m) => ({ default: m.GroupsPage })));
const GroupDetailPage = lazy(() => import("@/pages/groups/detail").then((m) => ({ default: m.GroupDetailPage })));
const ApprovalsPage = lazy(() => import("@/pages/approvals").then((m) => ({ default: m.ApprovalsPage })));
const UsagePage = lazy(() => import("@/pages/usage").then((m) => ({ default: m.UsagePage })));
const AuditPage = lazy(() => import("@/pages/audit").then((m) => ({ default: m.AuditPage })));
const HealthPage = lazy(() => import("@/pages/health").then((m) => ({ default: m.HealthPage })));
const ConfigPage = lazy(() => import("@/pages/config").then((m) => ({ default: m.ConfigPage })));
const AccountPage = lazy(() => import("@/pages/account").then((m) => ({ default: m.AccountPage })));


function RequireAuth({ children }: { children: ReactNode }) {
  const session = useSession();
  const location = useLocation();
  if (!session) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return <>{children}</>;
}

function RequireAdmin({ children }: { children: ReactNode }) {
  const session = useSession();
  if (!isAdminRole(session?.role)) return <Navigate to="/approvals" replace />;
  return <>{children}</>;
}

function HomeRedirect() {
  const session = useSession();
  if (!session) return <Navigate to="/login" replace />;
  return <Navigate to={isAdminRole(session.role) ? "/dashboard" : "/account"} replace />;
}

export function App() {
  const navigate = useNavigate();
  useEffect(() => {
    // Soft redirect on 401 — keeps SPA state and lets the toast render.
    registerUnauthorizedHandler(() => navigate("/login", { replace: true }));
  }, [navigate]);

  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/" element={<HomeRedirect />} />
      <Route
        element={
          <RequireAuth>
            <AppShell />
          </RequireAuth>
        }
      >
        <Route path="/dashboard" element={<RequireAdmin><DashboardPage /></RequireAdmin>} />
        <Route path="/connections" element={<RequireAdmin><ConnectionsPage /></RequireAdmin>} />
        <Route path="/tunnels" element={<RequireAdmin><TunnelsPage /></RequireAdmin>} />
        <Route path="/users" element={<RequireAdmin><UsersPage /></RequireAdmin>} />
        <Route path="/users/:id" element={<UserDetailPage />} />
        <Route path="/groups" element={<RequireAdmin><GroupsPage /></RequireAdmin>} />
        <Route path="/groups/:id" element={<RequireAdmin><GroupDetailPage /></RequireAdmin>} />
        <Route path="/approvals" element={<ApprovalsPage />} />
        <Route path="/usage" element={<RequireAdmin><UsagePage /></RequireAdmin>} />
        <Route path="/audit" element={<RequireAdmin><AuditPage /></RequireAdmin>} />
        <Route path="/system-health" element={<RequireAdmin><HealthPage /></RequireAdmin>} />
        <Route path="/config" element={<RequireAdmin><ConfigPage /></RequireAdmin>} />
        <Route path="/account" element={<AccountPage />} />
        <Route path="*" element={<HomeRedirect />} />
      </Route>
    </Routes>
  );
}
