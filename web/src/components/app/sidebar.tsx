import { Link, useRouterState } from "@tanstack/react-router";
import {
  Activity,
  BarChart3,
  Cable,
  FolderTree,
  Gauge,
  HeartPulse,
  KeyRound,
  LayoutDashboard,
  ScrollText,
  Settings,
  ShieldCheck,
  Users,
  Waypoints,
} from "lucide-react";
import { motion } from "framer-motion";
import { cn } from "@/lib/utils";
import { isAdmin } from "@/lib/auth";
import { useSystemStats } from "@/lib/queries";
import { fmtBytes } from "@/lib/format";
import { Mono } from "./mono";

type Item = {
  to: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
  adminOnly?: boolean;
};

const groups: { id: string; title: string; items: Item[] }[] = [
  {
    id: "ops",
    title: "Operations",
    items: [
      { to: "/dashboard", label: "Overview", icon: LayoutDashboard, adminOnly: true },
      { to: "/connections", label: "Connections", icon: Cable, badge: "live", adminOnly: true },
      { to: "/tunnels", label: "Tunnels", icon: Waypoints, adminOnly: true },
    ],
  },
  {
    id: "ident",
    title: "Identity",
    items: [
      { to: "/users", label: "Users", icon: Users, adminOnly: true },
      { to: "/groups", label: "Groups", icon: FolderTree, adminOnly: true },
      { to: "/api-keys", label: "API Keys", icon: KeyRound },
      { to: "/approvals", label: "Approvals", icon: ShieldCheck },
    ],
  },
  {
    id: "obs",
    title: "Observability",
    items: [
      { to: "/usage", label: "Usage & Quotas", icon: BarChart3, adminOnly: true },
      { to: "/audit", label: "Audit Log", icon: ScrollText, adminOnly: true },
      { to: "/health", label: "System Health", icon: HeartPulse, adminOnly: true },
      { to: "/config", label: "Configuration", icon: Settings, adminOnly: true },
    ],
  },
];

export function Sidebar() {
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const admin = isAdmin();
  const { data: stats } = useSystemStats();
  const visibleGroups = groups
    .map((g) => ({ ...g, items: g.items.filter((it) => admin || !it.adminOnly) }))
    .filter((g) => g.items.length > 0);

  return (
    <aside className="sticky top-0 z-30 hidden h-dvh w-64 shrink-0 flex-col border-r border-white/[0.06] bg-[color-mix(in_oklab,var(--sidebar)_85%,transparent)] backdrop-blur-xl lg:flex">
      <div className="flex items-center gap-3 px-5 pt-5 pb-6">
        <div className="relative grid size-9 place-items-center rounded-xl bg-gradient-to-br from-[var(--accent-violet)] to-[oklch(0.55_0.22_300)] shadow-[0_8px_24px_-8px_var(--accent-violet)]">
          <span className="text-base">🦀</span>
          <span className="absolute -inset-1 rounded-2xl bg-[var(--accent-violet)] opacity-20 blur-xl" />
        </div>
        <div className="min-w-0">
          <div className="truncate text-sm font-semibold tracking-tight">Crabby Proxy</div>
          <div className="text-[10px] uppercase tracking-[0.18em] text-muted-foreground">
            <Mono>v{stats?.version ?? "0.1.0"}</Mono> · control plane
          </div>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto px-3 pb-4">
        {visibleGroups.map((g) => (
          <div key={g.id} className="mb-5">
            <div className="px-3 pb-1.5 text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground/70">
              {g.title}
            </div>
            <ul className="space-y-0.5">
              {g.items.map((it) => {
                const active =
                  pathname === it.to ||
                  (it.to !== "/dashboard" && pathname.startsWith(it.to));
                return (
                  <li key={it.to} className="relative">
                    {active && (
                      <motion.span
                        layoutId="navActive"
                        className="absolute inset-0 rounded-lg bg-white/[0.05]"
                        transition={{ type: "spring", damping: 30, stiffness: 260 }}
                      />
                    )}
                    {active && (
                      <span className="absolute left-0 top-1.5 bottom-1.5 w-[2px] rounded-r-full bg-[var(--accent-violet)] shadow-[0_0_8px_var(--accent-violet)]" />
                    )}
                    <Link
                      to={it.to}
                      className={cn(
                        "group relative z-10 flex items-center gap-2.5 rounded-lg px-3 py-2 text-[13px] font-medium transition-colors",
                        active
                          ? "text-foreground"
                          : "text-muted-foreground hover:text-foreground",
                      )}
                    >
                      <it.icon
                        className={cn(
                          "size-4 shrink-0 transition-colors",
                          active && "text-[var(--accent-violet)]",
                        )}
                      />
                      <span className="truncate">{it.label}</span>
                      {it.badge && (
                        <span
                          className={cn(
                            "ml-auto inline-flex items-center gap-1 rounded-full border px-1.5 py-px text-[9px] font-mono-tight uppercase tracking-wider",
                            it.badge === "live"
                              ? "border-[var(--success)]/30 bg-[var(--success)]/10 text-[var(--success)]"
                              : "border-[var(--warning)]/30 bg-[var(--warning)]/10 text-[var(--warning)]",
                          )}
                        >
                          {it.badge === "live" && (
                            <span className="size-1 rounded-full bg-[var(--success)] pulse-dot" />
                          )}
                          {it.badge}
                        </span>
                      )}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      {admin && (
        <div className="mx-3 mb-3 rounded-xl border border-white/[0.06] bg-white/[0.02] p-3">
          <div className="mb-2 flex items-center justify-between text-[10px] uppercase tracking-[0.18em] text-muted-foreground">
            <span>24h traffic</span>
            <Activity className="size-3" />
          </div>
          <div className="flex items-baseline justify-between">
            <Mono className="text-sm font-semibold">
              {fmtBytes((stats?.bytes_sent_24h ?? 0) + (stats?.bytes_received_24h ?? 0))}
            </Mono>
            <Mono className="text-[11px] text-muted-foreground">
              {stats?.active_connections ?? 0} live
            </Mono>
          </div>
        </div>
      )}

      <UserMenu />
    </aside>
  );
}

function UserMenu() {
  const session =
    typeof window !== "undefined"
      ? JSON.parse(window.localStorage.getItem("cbpx_session") || "null")
      : null;
  const initials = (session?.username ?? "R").slice(0, 2).toUpperCase();
  return (
    <div className="mx-3 mb-4 flex items-center gap-3 rounded-xl border border-white/[0.06] bg-white/[0.02] p-3">
      <div className="grid size-8 place-items-center rounded-lg bg-gradient-to-br from-[oklch(0.4_0.05_285)] to-[oklch(0.3_0.05_285)] text-[11px] font-semibold">
        {initials}
      </div>
      <div className="min-w-0 flex-1">
        <div className="truncate text-xs font-medium">{session?.username ?? "root"}</div>
        <Gauge className="inline size-3 text-muted-foreground" />
        <span className="ml-1 text-[10px] uppercase tracking-wider text-muted-foreground">
          {session?.role ?? "root_admin"}
        </span>
      </div>
    </div>
  );
}