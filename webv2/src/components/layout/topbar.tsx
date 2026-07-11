// Top bar: mobile menu trigger, breadcrumb, live pill (admin, real data),
// ⌘K trigger, notifications (real), theme toggle, user menu.
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import {
  Bell,
  Check,
  LogOut,
  Menu,
  Monitor,
  Moon,
  Search,
  ShieldAlert,
  Sun,
  TriangleAlert,
  UserRound,
} from "lucide-react";
import { useMemo } from "react";
import { useLocation, useNavigate } from "react-router";
import { motion } from "motion/react";
import { clearSession } from "@/lib/auth";
import {
  useApprovalRequests,
  useDeepHealth,
  useIsAdmin,
  useJsonMetrics,
  useSession,
} from "@/hooks/queries";
import { useTheme, type Theme } from "@/hooks/use-theme";
import { Kbd } from "@/components/ui/misc";
import { StatusPill } from "@/components/ui/badge";
import { openPalette } from "./command-palette";
import { cn } from "@/lib/utils";

const TITLES: Record<string, string> = {
  "/dashboard": "Dashboard",
  "/system-health": "System health",
  "/connections": "Connections",
  "/tunnels": "Tunnels",
  "/usage": "Usage analytics",
  "/users": "Users",
  "/groups": "Groups",
  "/approvals": "Approvals",
  "/audit": "Audit log",
  "/config": "Configuration",
  "/account": "My account",
};

function pageTitle(pathname: string): string {
  const exact = TITLES[pathname];
  if (exact) return exact;
  const base = Object.keys(TITLES).find((k) => pathname.startsWith(`${k}/`));
  return base ? TITLES[base] : "Crabby Proxy";
}

interface Notice {
  id: string;
  tone: "danger" | "warning" | "info";
  title: string;
  detail: string;
  to?: string;
}

export function Topbar({ onOpenMobileNav }: { onOpenMobileNav: () => void }) {
  const location = useLocation();
  const navigate = useNavigate();
  const isAdmin = useIsAdmin();
  const session = useSession();
  const { theme, setTheme } = useTheme();

  const health = useDeepHealth(isAdmin);
  const metrics = useJsonMetrics(isAdmin);
  const requests = useApprovalRequests(true);

  const notices = useMemo<Notice[]>(() => {
    const out: Notice[] = [];
    if (health.data) {
      for (const [name, c] of Object.entries(health.data.checks)) {
        if (c.status !== "ok") {
          out.push({
            id: `health-${name}`,
            tone: "danger",
            title: `${name.replace(/_/g, " ")} unhealthy`,
            detail: c.detail ?? "Component check failing",
            to: "/system-health",
          });
        }
      }
    }
    if (metrics.data?.draining) {
      out.push({
        id: "draining",
        tone: "warning",
        title: "Server draining",
        detail: `${metrics.data.draining_connections} connections still open`,
        to: "/system-health",
      });
    }
    const pending = (requests.data ?? []).filter((r) => r.status === "pending");
    if (isAdmin && pending.length > 0) {
      out.push({
        id: "pending-approvals",
        tone: "info",
        title: `${pending.length} pending access ${pending.length === 1 ? "request" : "requests"}`,
        detail: "Awaiting an approval decision",
        to: "/approvals",
      });
    }
    if (!isAdmin) {
      const mine = (requests.data ?? []).filter(
        (r) => r.user_id === session?.userId && r.status !== "pending",
      );
      const latest = mine.sort((a, b) => (b.decided_at ?? 0) - (a.decided_at ?? 0))[0];
      if (latest?.decided_at && Date.now() / 1000 - latest.decided_at < 86400) {
        out.push({
          id: `decision-${latest.id}`,
          tone: latest.status === "approved" ? "info" : "warning",
          title: `Access request ${latest.status}`,
          detail: latest.decision_reason ?? `Request #${latest.id} was ${latest.status}`,
          to: "/approvals",
        });
      }
    }
    return out;
  }, [health.data, metrics.data, requests.data, isAdmin, session?.userId]);

  const overall: "ok" | "warn" | "down" = health.data
    ? health.data.status === "healthy"
      ? metrics.data?.draining
        ? "warn"
        : "ok"
      : "down"
    : "ok";

  return (
    <header className="sticky top-0 z-40 flex h-14 items-center gap-3 border-b border-line bg-bg/80 px-4 backdrop-blur-md">
      <button
        type="button"
        onClick={onOpenMobileNav}
        aria-label="Open navigation"
        className="grid size-8 place-items-center rounded-md text-fg-muted hover:bg-surface-2 lg:hidden"
      >
        <Menu className="size-4.5" />
      </button>

      <h1 className="min-w-0 truncate text-[14px] font-semibold tracking-tight">
        {pageTitle(location.pathname)}
      </h1>

      {isAdmin && health.data && (
        <div className="max-md:hidden">
          <StatusPill
            tone={overall === "ok" ? "success" : overall === "warn" ? "warning" : "danger"}
            label={
              overall === "ok" ? "All systems normal" : overall === "warn" ? "Draining" : "Degraded"
            }
            pulse={overall !== "ok"}
          />
        </div>
      )}

      <div className="ml-auto flex items-center gap-1.5">
        {/* ⌘K trigger */}
        <button
          type="button"
          onClick={openPalette}
          className="flex h-8 items-center gap-2 rounded-md border border-line-strong bg-surface-1 px-2.5 text-[12.5px] text-fg-faint transition-colors hover:border-accent/40 hover:text-fg-muted max-sm:px-2"
        >
          <Search className="size-3.5" aria-hidden />
          <span className="max-sm:hidden">Search or jump…</span>
          <span className="flex items-center gap-0.5 max-sm:hidden">
            <Kbd>⌘</Kbd>
            <Kbd>K</Kbd>
          </span>
        </button>

        {/* Notifications */}
        <DropdownMenu.Root>
          <DropdownMenu.Trigger asChild>
            <button
              type="button"
              aria-label={`Notifications${notices.length ? ` (${notices.length})` : ""}`}
              className="relative grid size-8 place-items-center rounded-md text-fg-muted transition-colors hover:bg-surface-2 hover:text-fg"
            >
              <Bell className="size-4" />
              {notices.length > 0 && (
                <motion.span
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                  className={cn(
                    "absolute right-1 top-1 size-2 rounded-full",
                    notices.some((n) => n.tone === "danger")
                      ? "bg-danger"
                      : notices.some((n) => n.tone === "warning")
                        ? "bg-warning"
                        : "bg-info",
                  )}
                />
              )}
            </button>
          </DropdownMenu.Trigger>
          <DropdownMenu.Portal>
            <DropdownMenu.Content
              align="end"
              sideOffset={8}
              className="z-50 w-80 rounded-lg border border-line glass p-1.5 shadow-pop"
            >
              <div className="px-2.5 py-1.5 text-[11px] font-semibold uppercase tracking-[0.07em] text-fg-faint">
                Notifications
              </div>
              {notices.length === 0 ? (
                <div className="flex items-center gap-2 px-2.5 py-3 text-[12.5px] text-fg-muted">
                  <Check className="size-4 text-success" /> All clear — nothing needs attention.
                </div>
              ) : (
                notices.map((n) => (
                  <DropdownMenu.Item
                    key={n.id}
                    onSelect={() => n.to && navigate(n.to)}
                    className="flex cursor-pointer items-start gap-2.5 rounded-md px-2.5 py-2 outline-none data-[highlighted]:bg-surface-2"
                  >
                    {n.tone === "danger" ? (
                      <ShieldAlert className="mt-0.5 size-4 shrink-0 text-danger" />
                    ) : n.tone === "warning" ? (
                      <TriangleAlert className="mt-0.5 size-4 shrink-0 text-warning" />
                    ) : (
                      <Bell className="mt-0.5 size-4 shrink-0 text-info" />
                    )}
                    <div className="min-w-0">
                      <div className="text-[12.5px] font-medium">{n.title}</div>
                      <div className="truncate text-[11.5px] text-fg-muted">{n.detail}</div>
                    </div>
                  </DropdownMenu.Item>
                ))
              )}
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>

        {/* Theme */}
        <DropdownMenu.Root>
          <DropdownMenu.Trigger asChild>
            <button
              type="button"
              aria-label="Theme"
              className="grid size-8 place-items-center rounded-md text-fg-muted transition-colors hover:bg-surface-2 hover:text-fg"
            >
              {theme === "light" ? <Sun className="size-4" /> : theme === "dark" ? <Moon className="size-4" /> : <Monitor className="size-4" />}
            </button>
          </DropdownMenu.Trigger>
          <DropdownMenu.Portal>
            <DropdownMenu.Content align="end" sideOffset={8} className="z-50 w-36 rounded-lg border border-line glass p-1 shadow-pop">
              {(["dark", "light", "system"] as Theme[]).map((t) => (
                <DropdownMenu.Item
                  key={t}
                  onSelect={() => setTheme(t)}
                  className="flex cursor-pointer items-center gap-2 rounded-md px-2.5 py-1.5 text-[12.5px] capitalize outline-none data-[highlighted]:bg-surface-2"
                >
                  {t === "dark" ? <Moon className="size-3.5" /> : t === "light" ? <Sun className="size-3.5" /> : <Monitor className="size-3.5" />}
                  {t}
                  {theme === t && <Check className="ml-auto size-3.5 text-accent" />}
                </DropdownMenu.Item>
              ))}
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>

        {/* User */}
        <DropdownMenu.Root>
          <DropdownMenu.Trigger asChild>
            <button
              type="button"
              aria-label="Account menu"
              className="grid size-8 place-items-center rounded-full bg-surface-3 font-mono text-[11px] font-semibold uppercase text-fg-muted transition-colors hover:bg-surface-2"
            >
              {session?.username.slice(0, 2) ?? "??"}
            </button>
          </DropdownMenu.Trigger>
          <DropdownMenu.Portal>
            <DropdownMenu.Content align="end" sideOffset={8} className="z-50 w-48 rounded-lg border border-line glass p-1 shadow-pop">
              <div className="px-2.5 py-2">
                <div className="truncate text-[12.5px] font-medium">{session?.username}</div>
                <div className="text-[11px] text-fg-faint">{session?.role.replace("_", " ")}</div>
              </div>
              <DropdownMenu.Separator className="my-1 h-px bg-line" />
              <DropdownMenu.Item
                onSelect={() => navigate("/account")}
                className="flex cursor-pointer items-center gap-2 rounded-md px-2.5 py-1.5 text-[12.5px] outline-none data-[highlighted]:bg-surface-2"
              >
                <UserRound className="size-3.5" /> My account
              </DropdownMenu.Item>
              <DropdownMenu.Item
                onSelect={() => {
                  clearSession();
                  navigate("/login");
                }}
                className="flex cursor-pointer items-center gap-2 rounded-md px-2.5 py-1.5 text-[12.5px] text-danger outline-none data-[highlighted]:bg-danger-soft"
              >
                <LogOut className="size-3.5" /> Sign out
              </DropdownMenu.Item>
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>
      </div>
    </header>
  );
}
