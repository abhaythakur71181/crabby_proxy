// Navigation rail. Desktop: fixed, collapsible to an icon rail (persisted).
// Mobile: hidden — the shell renders it inside a slide-over sheet instead,
// so small screens always have full navigation (the old UI had none).
import {
  Activity,
  ArrowLeftRight,
  BarChart3,
  Cable,
  CircleUser,
  FileClock,
  LayoutDashboard,
  PanelLeftClose,
  PanelLeftOpen,
  Settings2,
  ShieldCheck,
  UsersRound,
  Waypoints,
} from "lucide-react";
import { NavLink, useLocation } from "react-router";
import { motion } from "motion/react";
import { cn } from "@/lib/utils";
import { useIsAdmin, useSession } from "@/hooks/queries";
import { RoleBadge } from "@/components/ui/badge";
import { Tooltip } from "@/components/ui/misc";

export const NAV_SECTIONS = [
  {
    label: "Overview",
    items: [
      { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard, admin: true },
      { to: "/system-health", label: "System health", icon: Activity, admin: true },
    ],
  },
  {
    label: "Traffic",
    items: [
      { to: "/connections", label: "Connections", icon: Waypoints, admin: true, live: true },
      { to: "/tunnels", label: "Tunnels", icon: Cable, admin: true },
      { to: "/usage", label: "Usage analytics", icon: BarChart3, admin: true },
    ],
  },
  {
    label: "Access",
    items: [
      { to: "/users", label: "Users", icon: UsersRound, admin: true },
      { to: "/groups", label: "Groups", icon: ArrowLeftRight, admin: true },
      { to: "/approvals", label: "Approvals", icon: ShieldCheck, admin: false },
    ],
  },
  {
    label: "System",
    items: [
      { to: "/audit", label: "Audit log", icon: FileClock, admin: true },
      { to: "/config", label: "Configuration", icon: Settings2, admin: true },
    ],
  },
  {
    label: "Personal",
    items: [{ to: "/account", label: "My account", icon: CircleUser, admin: false }],
  },
] as const;

export function SidebarContent({
  collapsed = false,
  onToggleCollapse,
  onNavigate,
}: {
  collapsed?: boolean;
  onToggleCollapse?: () => void;
  onNavigate?: () => void;
}) {
  const isAdmin = useIsAdmin();
  const session = useSession();
  const location = useLocation();

  return (
    <div className="flex h-full flex-col">
      {/* Brand */}
      <div className={cn("flex h-14 items-center gap-2.5 px-4", collapsed && "justify-center px-0")}>
        <div className="grid size-7 shrink-0 place-items-center rounded-lg bg-brand-soft text-[15px] shadow-[inset_0_0_0_1px_var(--brand-soft)]">
          🦀
        </div>
        {!collapsed && (
          <div className="min-w-0">
            <div className="truncate text-[13.5px] font-semibold tracking-tight">Crabby Proxy</div>
            <div className="text-[10.5px] text-fg-faint">Control plane</div>
          </div>
        )}
      </div>

      {/* Nav */}
      <nav className="min-h-0 flex-1 space-y-4 overflow-y-auto px-2.5 py-2" aria-label="Primary">
        {NAV_SECTIONS.map((section) => {
          const items = section.items.filter((i) => !i.admin || isAdmin);
          if (items.length === 0) return null;
          return (
            <div key={section.label}>
              {!collapsed && <div className="eyebrow mb-1 px-2">{section.label}</div>}
              <ul className="space-y-0.5">
                {items.map((item) => {
                  const active = location.pathname.startsWith(item.to);
                  const link = (
                    <NavLink
                      to={item.to}
                      onClick={onNavigate}
                      className={cn(
                        "group relative flex items-center gap-2.5 rounded-md px-2 py-1.5 text-[13px] font-medium transition-colors",
                        collapsed && "justify-center px-0 py-2",
                        active
                          ? "text-fg"
                          : "text-fg-muted hover:bg-surface-2 hover:text-fg",
                      )}
                    >
                      {active && (
                        <motion.span
                          layoutId="nav-active"
                          className="absolute inset-0 rounded-md bg-accent-soft"
                          transition={{ type: "spring", duration: 0.45, bounce: 0.2 }}
                        />
                      )}
                      <item.icon
                        className={cn("relative size-4 shrink-0", active && "text-accent")}
                        aria-hidden
                      />
                      {!collapsed && <span className="relative truncate">{item.label}</span>}
                      {!collapsed && "live" in item && item.live && (
                        <span className="relative ml-auto flex items-center gap-1 text-[10px] font-semibold text-success">
                          <span className="size-1.5 animate-pulse-dot rounded-full bg-success" aria-hidden />
                          LIVE
                        </span>
                      )}
                    </NavLink>
                  );
                  return (
                    <li key={item.to}>
                      {collapsed ? <Tooltip content={item.label}>{link}</Tooltip> : link}
                    </li>
                  );
                })}
              </ul>
            </div>
          );
        })}
      </nav>

      {/* Footer: user + collapse */}
      <div className="border-t border-line p-2.5">
        <div className={cn("flex items-center gap-2.5", collapsed && "flex-col")}>
          <div
            className={cn(
              "flex min-w-0 flex-1 items-center gap-2.5 rounded-md px-1.5 py-1",
              collapsed && "flex-none px-0",
            )}
          >
            <div className="grid size-7 shrink-0 place-items-center rounded-full bg-surface-3 font-mono text-[11px] font-semibold uppercase text-fg-muted">
              {session?.username.slice(0, 2) ?? "??"}
            </div>
            {!collapsed && (
              <div className="min-w-0 flex-1">
                <div className="truncate text-[12.5px] font-medium">{session?.username}</div>
                <RoleBadge role={session?.role ?? "user"} />
              </div>
            )}
          </div>
          {onToggleCollapse && (
            <button
              type="button"
              onClick={onToggleCollapse}
              aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
              className="grid size-7 shrink-0 place-items-center rounded-md text-fg-faint transition-colors hover:bg-surface-2 hover:text-fg"
            >
              {collapsed ? <PanelLeftOpen className="size-4" /> : <PanelLeftClose className="size-4" />}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
