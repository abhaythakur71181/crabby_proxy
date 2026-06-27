import { createFileRoute } from "@tanstack/react-router";
import { motion } from "framer-motion";
import { HeartPulse } from "lucide-react";
import { Panel, PanelHeader } from "@/components/app/card";
import { PageHeader } from "@/components/app/page-header";
import { Pill } from "@/components/app/badge";
import { StatusDot } from "@/components/app/status-dot";
import { Mono } from "@/components/app/mono";
import { Sparkline, makeSeries } from "@/components/app/sparkline";
import { healthComponents, systemStats } from "@/mock/seed";
import { fmtClockHMS, fmtRelative } from "@/lib/format";

export const Route = createFileRoute("/_authenticated/health")({
  head: () => ({ meta: [{ title: "System Health · Crabby Proxy" }] }),
  component: HealthPage,
});

function HealthPage() {
  const degraded = healthComponents.some((c) => c.status !== "healthy");

  return (
    <div className="mx-auto w-full max-w-[1400px] px-6 py-8 lg:px-10">
      <PageHeader
        title="System Health"
        subtitle="Deep checks across subsystems. Alarms fire here first."
        action={
          <Pill variant={degraded ? "warning" : "success"}>
            <StatusDot tone={degraded ? "warning" : "success"} /> {degraded ? "degraded" : "all green"}
          </Pill>
        }
      />

      <section className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Big label="Uptime" value={fmtClockHMS(systemStats.uptime_seconds)} />
        <Big label="Version" value={`v${systemStats.version}`} />
        <Big label="Active proxies" value={systemStats.active_tunnels.toString()} />
      </section>

      <section className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-3">
        {healthComponents.map((c, i) => (
          <motion.div key={c.name} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}>
            <Panel className="overflow-hidden">
              <PanelHeader
                title={<span className="normal-case tracking-normal text-sm font-semibold text-foreground">{c.name}</span>}
                action={
                  <Pill variant={c.status === "healthy" ? "success" : c.status === "degraded" ? "warning" : "danger"}>
                    <StatusDot tone={c.status === "healthy" ? "success" : c.status === "degraded" ? "warning" : "danger"} /> {c.status}
                  </Pill>
                }
              />
              <div className="space-y-3 p-5">
                <div className="flex items-end justify-between">
                  <div>
                    <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Latency</div>
                    <Mono className={"text-2xl font-semibold " + (c.latency_ms > 100 ? "text-[var(--warning)]" : "")}>
                      {c.latency_ms.toFixed(1)}<span className="ml-1 text-sm text-muted-foreground">ms</span>
                    </Mono>
                  </div>
                  <Sparkline data={makeSeries(20, c.latency_ms || 8, (c.latency_ms || 8) * 0.6)} width={100} height={32} />
                </div>
                <p className="text-xs text-muted-foreground">{c.detail}</p>
                <div className="flex items-center justify-between border-t border-white/[0.06] pt-3 text-[10px] text-muted-foreground">
                  <span>Last check</span>
                  <span>{fmtRelative(c.last_check)}</span>
                </div>
              </div>
            </Panel>
          </motion.div>
        ))}
      </section>
    </div>
  );
}

function Big({ label, value }: { label: string; value: string }) {
  return (
    <Panel className="p-5">
      <div className="flex items-center justify-between text-muted-foreground">
        <span className="text-[10px] font-semibold uppercase tracking-[0.2em]">{label}</span>
        <HeartPulse className="size-4" />
      </div>
      <Mono className="mt-3 block text-[28px] font-semibold leading-none tracking-tight text-foreground">{value}</Mono>
    </Panel>
  );
}