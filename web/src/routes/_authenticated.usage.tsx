import { createFileRoute } from "@tanstack/react-router";
import { Activity, Cable, Gauge, Users as UsersIcon } from "lucide-react";
import { motion } from "framer-motion";
import { Panel, PanelHeader } from "@/components/app/card";
import { PageHeader } from "@/components/app/page-header";
import { AnimatedCounter } from "@/components/app/animated-counter";
import { Mono } from "@/components/app/mono";
import { systemStats, users } from "@/mock/seed";
import { fmtBytes } from "@/lib/format";

export const Route = createFileRoute("/_authenticated/usage")({
  head: () => ({ meta: [{ title: "Usage & Quotas · Crabby Proxy" }] }),
  component: UsagePage,
});

function UsagePage() {
  const sorted = [...users].sort((a, b) => b.bandwidth_used_mb - a.bandwidth_used_mb);
  const maxBw = Math.max(...users.map((u) => u.bandwidth_used_mb), 1);

  return (
    <div className="mx-auto w-full max-w-[1400px] px-6 py-8 lg:px-10">
      <PageHeader title="Usage & Quotas" subtitle="Who consumed what — and who's approaching their cap." />
      <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Kpi icon={<Cable className="size-4" />} label="Total connections" value={<AnimatedCounter value={systemStats.total_connections} />} />
        <Kpi icon={<Gauge className="size-4" />} label="Total bandwidth" value={<AnimatedCounter value={systemStats.bytes_received_24h + systemStats.bytes_sent_24h} format={(n) => fmtBytes(Math.round(n))} />} />
        <Kpi icon={<UsersIcon className="size-4" />} label="Unique users" value={<AnimatedCounter value={users.length} />} />
        <Kpi icon={<Activity className="size-4" />} label="Data sent" value={<AnimatedCounter value={systemStats.bytes_sent_24h} format={(n) => fmtBytes(Math.round(n))} />} />
      </section>

      <section className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Panel className="lg:col-span-2">
          <PanelHeader title="Top users by bandwidth" hint="last 24 hours" />
          <ul className="divide-y divide-white/[0.05]">
            {sorted.map((u, i) => {
              const pct = Math.round((u.bandwidth_used_mb / maxBw) * 100);
              const cap = Math.round((u.bandwidth_used_mb / u.bandwidth_limit_mb) * 100);
              return (
                <li key={u.id} className="px-5 py-4">
                  <div className="mb-2 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="grid size-7 place-items-center rounded-md bg-white/5 text-[10px] font-mono-tight">{i + 1}</div>
                      <div>
                        <div className="text-sm font-medium">{u.username}</div>
                        <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{u.role}</div>
                      </div>
                    </div>
                    <div className="text-right">
                      <Mono className="text-sm">{u.bandwidth_used_mb.toLocaleString()} MB</Mono>
                      <div className={"text-[10px] " + (cap > 80 ? "text-[var(--warning)]" : "text-muted-foreground")}>
                        {cap}% of cap
                      </div>
                    </div>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.06]">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${pct}%` }}
                      transition={{ duration: 1, ease: [0.16, 1, 0.3, 1], delay: i * 0.06 }}
                      className="h-full rounded-full bg-gradient-to-r from-[var(--accent-violet)] to-[oklch(0.74_0.17_200)]"
                    />
                  </div>
                </li>
              );
            })}
          </ul>
        </Panel>

        <Panel>
          <PanelHeader title="Leaderboard" hint="connections" />
          <ul className="divide-y divide-white/[0.05]">
            {sorted.map((u, i) => (
              <li key={u.id} className="flex items-center justify-between px-5 py-3 text-sm">
                <span className="flex items-center gap-3">
                  <span className="grid size-6 place-items-center rounded bg-white/5 text-[10px] font-mono-tight">{i + 1}</span>
                  {u.username}
                </span>
                <Mono className="text-xs text-foreground/80">{(u.bandwidth_used_mb * 12).toLocaleString()}</Mono>
              </li>
            ))}
          </ul>
        </Panel>
      </section>
    </div>
  );
}

function Kpi({ icon, label, value }: { icon: React.ReactNode; label: string; value: React.ReactNode }) {
  return (
    <Panel className="p-5">
      <div className="flex items-center justify-between text-muted-foreground">
        <span className="text-[10px] font-semibold uppercase tracking-[0.2em]">{label}</span>
        {icon}
      </div>
      <div className="mt-3 text-[28px] font-semibold leading-none tracking-tight"><Mono>{value}</Mono></div>
    </Panel>
  );
}
