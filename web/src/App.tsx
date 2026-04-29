import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AuthProvider } from "@/contexts/AuthContext";
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
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/connections" element={<Connections />} />
              <Route path="/users" element={<UsersPage />} />
              <Route path="/users/:id" element={<UserDetail />} />
              <Route path="/groups" element={<Groups />} />
              <Route path="/groups/:id" element={<GroupDetail />} />
              <Route path="/api-keys" element={<UserDetail />} />
              <Route path="/usage" element={<UsageSummary />} />
              <Route path="/approvals" element={<Approvals />} />
              <Route path="/tunnels" element={<Tunnels />} />
              <Route path="/audit-log" element={<AuditLog />} />
              <Route path="/configuration" element={<Configuration />} />
              <Route path="/health" element={<SystemHealth />} />
            </Route>
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
