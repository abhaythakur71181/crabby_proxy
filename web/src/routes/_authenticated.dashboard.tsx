import { createFileRoute } from "@tanstack/react-router";
import { motion } from "framer-motion";
import { Activity, Cable, Clock, Gauge } from "lucide-react";
import { useEffect, useState } from "react";
import { Panel, PanelHeader } from "@/components/app/card";
import { PageHeader } from "@/components/app/page-header";
import { AnimatedCounter } from "@/components/app/animated-counter";
import { Mono } from "@/components/app/mono";
import { Pill } from "@/components/app/badge";
import { StatusDot } from "@/components/app/status-dot";
import {
  useAudit,
  useDashboard,
  useUserMap,
  useUsageTimeseries,
} from "@/lib/queries";
import { useLiveConnections } from "@/mock/live";
import { fmtBytes, fmtClockHMS, fmtRelative } from "@/lib/format";

export const Route = createFileRoute("/_authenticated/dashboard")({
  head: () => ({
    meta: [
      { title: "Overview · Crabby Proxy" },
      { name: "description", content: "Live overview of the proxy control plane: connections, throughput, top users and recent activity." },
    ],
  }),
  component: DashboardPage,
});

function DashboardPage() {
  const { rows } = useLiveConnections([], 8);
  const { data: dash } = useDashboard();
  const { entries: auditEntries } = useAudit(7);
  const { data: ts } = useUsageTimeseries(1, "hour");
  const nameOf = useUserMap();

  const activeConnections = dash?.active_connections ?? 0;
  const totalConnections = dash?.total_connections ?? 0;
  const bytesSent = dash?.bytes_sent ?? 0;
  const bytesReceived = dash?.bytes_received ?? 0;
  const bandwidth24h = dash?.bandwidth_24h ?? 0;
  const topUsers = dash?.top_users_24h ?? [];

  // Live uptime clock: rebase from the server value on each poll, tick locally.
  const [uptime, setUptime] = useState(0);
  useEffect(() => {
    if (dash?.uptime_seconds == null) return;
    const base = dash.uptime_seconds;
    const start = Date.now();
    setUptime(base);
    const id = window.setInterval(
      () => setUptime(base + Math.floor((Date.now() - start) / 1000)),
      1000,
    );
    return () => window.clearInterval(id);
  }, [dash?.uptime_seconds]);

  const tsPoints = ts?.points ?? [];
  const maxBucket = Math.max(1, ...tsPoints.map((p) => p.bytes_sent + p.bytes_received));

  return (
    <div className="mx-auto w-full max-w-[1400px] px-6 py-8 lg:px-10">
      <PageHeader
        title="Overview"
        subtitle="Who's going where, how much, and is anything wrong — at a glance."
        action={
          <div className="flex items-center gap-2">
            <Pill variant="success">
              <StatusDot tone="success" /> all systems normal
            </Pill>
          </div>
        }
      />

      {/* KPI grid */}
      <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <KpiTile
          icon={<Clock className="size-4" />}
          label="Uptime"
          value={<Mono>{fmtClockHMS(uptime)}</Mono>}
          hint="since last restart"
        />
        <KpiTile
          icon={<Cable className="size-4" />}
          label="Active connections"
          value={
            <Mono>
              <AnimatedCounter value={activeConnections} />
            </Mono>
          }
          hint="live"
          glow
        />
        <KpiTile
          icon={<Activity className="size-4" />}
          label="Total connections"
          value={
            <Mono>
              <AnimatedCounter value={totalConnections} />
            </Mono>
          }
          hint="since start"
        />
        <KpiTile
          icon={<Gauge className="size-4" />}
          label="Bandwidth · 24h"
          value={
            <Mono>
              <AnimatedCounter value={bandwidth24h} format={(n) => fmtBytes(Math.round(n))} />
            </Mono>
          }
          hint="rolling 24 hours"
        />
      </section>

      {/* Mid: bandwidth split + top users */}
      <section className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Panel className="lg:col-span-2">
          <PanelHeader
            title="Bandwidth breakdown"
            hint="total since start"
            action={
              <div className="flex items-center gap-4 text-[10px] uppercase tracking-wider text-muted-foreground">
                <span className="flex items-center gap-1.5">
                  <span className="size-2 rounded-full bg-[var(--accent-violet)]" /> Sent
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="size-2 rounded-full bg-[oklch(0.74_0.17_200)]" /> Received
                </span>
              </div>
            }
          />
          <div className="grid grid-cols-2 gap-6 px-5 py-6">
            <BandwidthBar tone="violet" label="Sent" bytes={bytesSent} max={Math.max(bytesSent, bytesReceived)} />
            <BandwidthBar tone="cyan" label="Received" bytes={bytesReceived} max={Math.max(bytesSent, bytesReceived)} />
          </div>
          <div className="px-5 pb-5">
            <div className="mb-2 text-[10px] uppercase tracking-wider text-muted-foreground">
              Traffic · last 24h (hourly)
            </div>
            {tsPoints.length === 0 ? (
              <div className="flex h-32 items-center justify-center text-xs text-muted-foreground">
                No traffic recorded in the last 24 hours.
              </div>
            ) : (
              <div className="flex h-32 items-end gap-1.5">
                {tsPoints.map((p) => {
                  const total = p.bytes_sent + p.bytes_received;
                  const h = Math.max(4, Math.round((total / maxBucket) * 100));
                  return (
                    <motion.div
                      key={p.ts}
                      title={`${fmtBytes(total)} · ${p.connections} conns`}
                      initial={{ height: 0 }}
                      animate={{ height: `${h}%` }}
                      transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
                      className="flex-1 rounded-t bg-gradient-to-t from-[var(--accent-violet)]/30 to-[var(--accent-violet)]/80"
                    />
                  );
                })}
              </div>
            )}
          </div>
        </Panel>

        <Panel>
          <PanelHeader title="Top users · 24h" hint="by bandwidth" />
          {topUsers.length === 0 ? (
            <div className="px-5 py-10 text-center text-xs text-muted-foreground">
              No usage in the last 24 hours.
            </div>
          ) : (
            <ul className="divide-y divide-white/[0.05]">
              {topUsers.slice(0, 6).map((u, i) => (
                <motion.li
                  key={u.user_id}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.05 }}
                  className="flex items-center gap-3 px-5 py-3"
                >
                  <div className="grid size-7 place-items-center rounded-md bg-white/5 text-[10px] font-mono-tight text-muted-foreground">
                    {String(i + 1).padStart(2, "0")}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-xs font-medium text-foreground">{nameOf(u.user_id)}</div>
                    <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
                      {u.connections} conns
                    </div>
                  </div>
                  <Mono className="text-[11px] text-foreground/80">{fmtBytes(u.bandwidth)}</Mono>
                </motion.li>
              ))}
            </ul>
          )}
        </Panel>
      </section>

      {/* Live feed + audit */}
      <section className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Panel className="lg:col-span-2">
          <PanelHeader
            title="Live connections"
            hint="streaming · live"
            action={
              <Pill variant="success">
                <StatusDot tone="success" /> streaming
              </Pill>
            }
          />
          <div className="grid grid-cols-[110px_1fr_1fr_80px_90px] gap-3 px-5 py-3 text-[10px] uppercase tracking-wider text-muted-foreground">
            <span>When</span>
            <span>Client</span>
            <span>Target</span>
            <span>Proto</span>
            <span className="text-right">Bytes</span>
          </div>
          <ul className="divide-y divide-white/[0.04]">
            {rows.slice(0, 8).map((r, i) => (
              <li
                key={r.id}
                className="row-enter grid grid-cols-[110px_1fr_1fr_80px_90px] items-center gap-3 px-5 py-2.5 text-xs hover:bg-white/[0.02]"
                style={{ animationDelay: i === 0 ? "0ms" : undefined }}
              >
                <Mono className="text-[11px] text-muted-foreground">
                  {fmtRelative(r.started_at)}
                </Mono>
                <Mono className="truncate text-[11px] text-foreground/90">
                  {r.client_ip}:{r.client_port}
                </Mono>
                <Mono className="truncate text-[11px] text-foreground/70">
                  {r.target_host}:{r.target_port}
                </Mono>
                <Pill variant="mono">{r.protocol}</Pill>
                <Mono className="text-right text-[11px]">{fmtBytes(r.bytes_received)}</Mono>
              </li>
            ))}
          </ul>
        </Panel>

        <Panel>
          <PanelHeader title="Recent activity" hint="audit log" />
          <ul className="divide-y divide-white/[0.05]">
            {auditEntries.slice(0, 7).map((a, i) => (
              <motion.li
                key={a.id}
                initial={{ opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.04 }}
                className="flex items-start gap-3 px-5 py-3"
              >
                <StatusDot
                  tone={a.outcome === "ok" ? "success" : a.outcome === "denied" ? "warning" : "danger"}
                  pulse={false}
                  className="mt-1.5"
                />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-xs">
                    <span className="text-foreground">{nameOf(a.actor_id)}</span>{" "}
                    <span className="text-muted-foreground">{a.action}</span>{" "}
                    <Mono className="text-foreground/70">{a.target}</Mono>
                  </div>
                  <div className="mt-0.5 text-[10px] text-muted-foreground">
                    {fmtRelative(a.ts)} · <Mono>{a.ip}</Mono>
                  </div>
                </div>
              </motion.li>
            ))}
          </ul>
        </Panel>
      </section>
    </div>
  );
}

function KpiTile({
  icon,
  label,
  value,
  hint,
  glow,
}: {
  icon: React.ReactNode;
  label: string;
  value: React.ReactNode;
  hint?: React.ReactNode;
  glow?: boolean;
}) {
  return (
    <Panel glow={glow} className="px-5 py-5">
      <div className="flex items-center justify-between text-muted-foreground">
        <span className="text-[10px] font-semibold uppercase tracking-[0.2em]">{label}</span>
        <span className="text-foreground/60">{icon}</span>
      </div>
      <div className="mt-3 flex items-end justify-between gap-2">
        <div className="text-[28px] font-semibold leading-none tracking-tight">{value}</div>
      </div>
      {hint && <div className="mt-2 text-[10px] font-mono-tight text-muted-foreground">{hint}</div>}
    </Panel>
  );
}

function BandwidthBar({
  label,
  bytes,
  max,
  tone,
}: {
  label: string;
  bytes: number;
  max: number;
  tone: "violet" | "cyan";
}) {
  const pct = max > 0 ? Math.max(2, Math.round((bytes / max) * 100)) : 2;
  const color = tone === "violet" ? "var(--accent-violet)" : "oklch(0.74 0.17 200)";
  return (
    <div>
      <div className="mb-1.5 flex items-center justify-between text-[10px] uppercase tracking-wider text-muted-foreground">
        <span>{label}</span>
        <Mono className="text-foreground/80">{fmtBytes(bytes)}</Mono>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.06]">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 1.1, ease: [0.16, 1, 0.3, 1] }}
          className="h-full rounded-full"
          style={{ backgroundColor: color, boxShadow: `0 0 12px ${color}` }}
        />
      </div>
    </div>
  );
}