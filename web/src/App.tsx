import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Outlet, Route, Routes } from "react-router-dom";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AuthProvider, useAuth } from "@/contexts/AuthContext";
import { DashboardLayout } from "@/components/DashboardLayout";
import Index from "./pages/Index";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Connections from "./pages/Connections";
import UsersPage from "./pages/Users";
import UserDetail from "./pages/UserDetail";
import Groups from "./pages/Groups";
import GroupDetail from "./pages/GroupDetail";
import Approvals from "./pages/Approvals";
import Tunnels from "./pages/Tunnels";
import Configuration from "./pages/Configuration";
import AuditLog from "./pages/AuditLog";
import SystemHealth from "./pages/SystemHealth";
import UsageSummary from "./pages/UsageSummary";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

// Client-side admin gate. The backend already enforces authz (403s non-admins),
// but the UI must not present admin pages/nav to a normal user. Non-admins are
// redirected to /approvals, which has a self-service "my requests" view.
function AdminRoute() {
  const { isAdmin } = useAuth();
  return isAdmin ? <Outlet /> : <Navigate to="/approvals" replace />;
}

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<Index />} />
            <Route path="/login" element={<Login />} />
            <Route element={<DashboardLayout />}>
              {/* Accessible to any authenticated user (self-scoped or handles
                  its own non-admin view). */}
              <Route path="/approvals" element={<Approvals />} />
              <Route path="/users/:id" element={<UserDetail />} />
              <Route path="/api-keys" element={<UserDetail />} />

              {/* Admin-only pages — backend gates the data with AdminUser; this
                  guard keeps the UI consistent (no admin nav/pages for users). */}
              <Route element={<AdminRoute />}>
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/connections" element={<Connections />} />
                <Route path="/users" element={<UsersPage />} />
                <Route path="/groups" element={<Groups />} />
                <Route path="/groups/:id" element={<GroupDetail />} />
                <Route path="/usage" element={<UsageSummary />} />
                <Route path="/tunnels" element={<Tunnels />} />
                <Route path="/audit-log" element={<AuditLog />} />
                <Route path="/configuration" element={<Configuration />} />
                <Route path="/system-health" element={<SystemHealth />} />
              </Route>
            </Route>
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
