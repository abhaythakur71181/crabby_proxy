import { createFileRoute } from "@tanstack/react-router";
import { Activity, Cable, Gauge, Users as UsersIcon } from "lucide-react";
import { motion } from "framer-motion";
import { Panel, PanelHeader } from "@/components/app/card";
import { PageHeader } from "@/components/app/page-header";
import { AnimatedCounter } from "@/components/app/animated-counter";
import { Mono } from "@/components/app/mono";
import { Sparkline } from "@/components/app/sparkline";
import { useUsageSummary, useUsageTimeseries, useUserMap } from "@/lib/queries";
import { fmtBytes } from "@/lib/format";

export const Route = createFileRoute("/_authenticated/usage")({
  head: () => ({ meta: [{ title: "Usage & Quotas · Crabby Proxy" }] }),
  component: UsagePage,
});

function UsagePage() {
  const { data } = useUsageSummary();
  const { data: ts } = useUsageTimeseries(7, "day");
  const nameOf = useUserMap();

  const topUsers = data?.top_users ?? [];
  const sorted = [...topUsers].sort((a, b) => b.total_bandwidth - a.total_bandwidth);
  const maxBw = Math.max(...sorted.map((u) => u.total_bandwidth), 1);

  const series = (ts?.points ?? []).map((p) => ({
    x: new Date(p.ts * 1000),
    y: p.bytes_sent + p.bytes_received,
  }));

  return (
    <div className="mx-auto w-full max-w-[1400px] px-6 py-8 lg:px-10">
      <PageHeader title="Usage & Quotas" subtitle="Who consumed what — and who's approaching their cap." />
      <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Kpi icon={<Cable className="size-4" />} label="Total connections" value={<AnimatedCounter value={data?.total_connections ?? 0} />} />
        <Kpi icon={<Gauge className="size-4" />} label="Total bandwidth" value={<AnimatedCounter value={data?.total_bandwidth ?? 0} format={(n) => fmtBytes(Math.round(n))} />} />
        <Kpi icon={<UsersIcon className="size-4" />} label="Unique users" value={<AnimatedCounter value={data?.unique_users ?? 0} />} />
        <Kpi icon={<Activity className="size-4" />} label="Data sent" value={<AnimatedCounter value={data?.total_bytes_sent ?? 0} format={(n) => fmtBytes(Math.round(n))} />} />
      </section>

      <section className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Panel className="lg:col-span-2">
          <PanelHeader
            title="Top users by bandwidth"
            hint={`last ${data?.period_days ?? 7} days`}
            action={series.length ? <Sparkline data={series.map((p) => p.y)} width={120} height={32} /> : undefined}
          />
          <ul className="divide-y divide-white/[0.05]">
            {sorted.map((u, i) => {
              const pct = Math.round((u.total_bandwidth / maxBw) * 100);
              return (
                <li key={u.user_id} className="px-5 py-4">
                  <div className="mb-2 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="grid size-7 place-items-center rounded-md bg-white/5 text-[10px] font-mono-tight">{i + 1}</div>
                      <div>
                        <div className="text-sm font-medium">{nameOf(u.user_id)}</div>
                        <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{u.connection_count.toLocaleString()} conns</div>
                      </div>
                    </div>
                    <div className="text-right">
                      <Mono className="text-sm">{fmtBytes(u.total_bandwidth)}</Mono>
                      <div className="text-[10px] text-muted-foreground">
                        {pct}% of top
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
              <li key={u.user_id} className="flex items-center justify-between px-5 py-3 text-sm">
                <span className="flex items-center gap-3">
                  <span className="grid size-6 place-items-center rounded bg-white/5 text-[10px] font-mono-tight">{i + 1}</span>
                  {nameOf(u.user_id)}
                </span>
                <Mono className="text-xs text-foreground/80">{u.connection_count.toLocaleString()}</Mono>
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
