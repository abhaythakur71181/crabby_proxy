import { Outlet, createFileRoute, redirect, useRouterState } from "@tanstack/react-router";
import { AnimatePresence, motion } from "framer-motion";
import { Sidebar } from "@/components/app/sidebar";
import { TopBar } from "@/components/app/topbar";
import { CommandPalette } from "@/components/app/command-palette";
import { getSession, isAdmin, isAdminPath } from "@/lib/auth";

export const Route = createFileRoute("/_authenticated")({
  beforeLoad: ({ location }) => {
    if (typeof window === "undefined") return;
    if (!getSession()) {
      throw redirect({ to: "/login" });
    }
    // Role gate: non-admins can't reach admin-only pages (backend 403s anyway).
    // Send them to their approvals view instead.
    if (isAdminPath(location.pathname) && !isAdmin()) {
      throw redirect({ to: "/approvals" });
    }
  },
  component: AppShell,
});

const TITLES: Record<string, string> = {
  "/dashboard": "Overview",
  "/connections": "Connections",
  "/users": "Users",
  "/groups": "Groups",
  "/api-keys": "API Keys",
  "/usage": "Usage & Quotas",
  "/approvals": "Approvals",
  "/tunnels": "Tunnels",
  "/audit": "Audit Log",
  "/config": "Configuration",
  "/health": "System Health",
};

function AppShell() {
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const title = TITLES[pathname] ?? "Control Plane";
  return (
    <div className="relative flex min-h-dvh bg-background text-foreground">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar crumbs={[{ label: "Crabby", to: "/dashboard" }, { label: title }]} />
        <AnimatePresence mode="wait">
          <motion.main
            key={pathname}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }}
            transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
            className="relative flex-1"
          >
            <Outlet />
          </motion.main>
        </AnimatePresence>
      </div>
      <CommandPalette />
    </div>
  );
}