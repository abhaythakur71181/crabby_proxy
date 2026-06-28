import { Link, useRouter } from "@tanstack/react-router";
import { Bell, ChevronRight, LogOut, Search } from "lucide-react";
import { Kbd, Mono } from "./mono";
import { StatusDot } from "./status-dot";
import { useTicker } from "@/mock/live";
import { useSystemStats } from "@/lib/queries";
import { fmtClockHMS } from "@/lib/format";
import { signOut, isAdmin } from "@/lib/auth";
import { useCommandPalette } from "./command-palette";

export function TopBar({ crumbs }: { crumbs: { label: string; to?: string }[] }) {
  const router = useRouter();
  const open = useCommandPalette((s) => s.open);
  const admin = isAdmin();
  const { data: stats } = useSystemStats(10000, admin); // admin-only /api/dashboard
  const now = stats?.active_connections ?? 0;
  // Tick the uptime clock forward between server polls.
  const tick = useTicker(1000);

  return (
    <header className="sticky top-0 z-20 flex h-14 items-center justify-between gap-4 border-b border-white/[0.06] bg-[color-mix(in_oklab,var(--background)_75%,transparent)] px-6 backdrop-blur-xl">
      <nav aria-label="Breadcrumb" className="flex min-w-0 items-center gap-2 text-xs">
        {crumbs.map((c, i) => (
          <span key={i} className="flex items-center gap-2">
            {i > 0 && <ChevronRight className="size-3 text-muted-foreground/50" />}
            {c.to ? (
              <Link
                to={c.to}
                className="text-muted-foreground transition hover:text-foreground"
              >
                {c.label}
              </Link>
            ) : (
              <span className="font-medium text-foreground">{c.label}</span>
            )}
          </span>
        ))}
      </nav>

      <div className="flex items-center gap-3">
        <button
          onClick={open}
          className="group hidden items-center gap-2 rounded-lg border border-white/[0.06] bg-white/[0.02] px-3 py-1.5 text-xs text-muted-foreground transition hover:border-white/10 hover:bg-white/[0.04] hover:text-foreground md:flex"
        >
          <Search className="size-3.5" />
          <span>Search anything…</span>
          <span className="ml-6 flex items-center gap-1">
            <Kbd>⌘</Kbd>
            <Kbd>K</Kbd>
          </span>
        </button>

        <div className={(admin ? "hidden md:flex" : "hidden") + " items-center gap-2.5 rounded-full border border-[var(--accent-violet)]/25 bg-[var(--accent-violet-soft)] px-3 py-1.5"}>
          <StatusDot tone="violet" />
          <Mono className="text-[11px] font-semibold uppercase tracking-wider text-[var(--accent-violet)]">
            {now} active
          </Mono>
          <span className="h-3 w-px bg-[var(--accent-violet)]/30" />
          <Mono className="text-[10px] text-[var(--accent-violet)]/80">
            {fmtClockHMS((stats?.uptime_seconds ?? 0) + tick)}
          </Mono>
        </div>

        <button
          aria-label="Notifications"
          className="grid size-9 place-items-center rounded-lg border border-white/[0.06] bg-white/[0.02] text-muted-foreground transition hover:border-white/10 hover:bg-white/[0.04] hover:text-foreground"
        >
          <Bell className="size-4" />
        </button>

        <button
          aria-label="Sign out"
          onClick={() => {
            signOut();
            router.navigate({ to: "/login" });
          }}
          className="grid size-9 place-items-center rounded-lg border border-white/[0.06] bg-white/[0.02] text-muted-foreground transition hover:border-white/10 hover:bg-white/[0.04] hover:text-foreground"
        >
          <LogOut className="size-4" />
        </button>
      </div>
    </header>
  );
}