import { createFileRoute } from "@tanstack/react-router";
import { Pause, Play, Waypoints } from "lucide-react";
import { Panel, PanelHeader } from "@/components/app/card";
import { PageHeader } from "@/components/app/page-header";
import { Pill } from "@/components/app/badge";
import { StatusDot } from "@/components/app/status-dot";
import { Mono } from "@/components/app/mono";
import { tunnels } from "@/mock/seed";
import { fmtBytes } from "@/lib/format";

export const Route = createFileRoute("/_authenticated/tunnels")({
  head: () => ({ meta: [{ title: "Tunnels · Crabby Proxy" }] }),
  component: TunnelsPage,
});

function TunnelsPage() {
  return (
    <div className="mx-auto w-full max-w-[1400px] px-6 py-8 lg:px-10">
      <PageHeader
        title="Tunnels"
        subtitle="Inbound listeners and the upstream routes they relay to."
      />
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
        {tunnels.map((t) => {
          const running = t.status === "running";
          return (
            <Panel key={t.id} className="overflow-hidden">
              <PanelHeader
                title={
                  <span className="flex items-center gap-2 normal-case tracking-normal">
                    <Waypoints className="size-3.5 text-[var(--accent-violet)]" />
                    <span className="text-sm font-semibold text-foreground">{t.name}</span>
                  </span>
                }
                action={
                  <Pill variant={running ? "success" : t.status === "stopped" ? "outline" : "danger"}>
                    <StatusDot tone={running ? "success" : t.status === "stopped" ? "muted" : "danger"} /> {t.status}
                  </Pill>
                }
              />
              <div className="space-y-3 p-5">
                <Row label="Listen" value={<Mono>{t.listen}</Mono>} />
                <Row label="Target" value={<Mono>{t.target}</Mono>} />
                <Row label="Protocol" value={<Pill variant="mono">{t.protocol}</Pill>} />
                <div className="grid grid-cols-3 gap-2 border-t border-white/[0.06] pt-3">
                  <Mini label="Active" value={t.active_connections.toLocaleString()} />
                  <Mini label="Traffic" value={fmtBytes(t.bytes_total)} />
                  <Mini label="Latency" value={`${t.latency_ms} ms`} />
                </div>
                <button
                  className={
                    "mt-2 inline-flex h-9 w-full items-center justify-center gap-2 rounded-xl text-xs font-semibold transition " +
                    (running
                      ? "border border-white/10 bg-white/[0.03] text-foreground hover:bg-white/[0.06]"
                      : "bg-[var(--accent-violet)] text-[var(--primary-foreground)] hover:brightness-110")
                  }
                >
                  {running ? <><Pause className="size-3.5" /> Stop tunnel</> : <><Play className="size-3.5" /> Start tunnel</>}
                </button>
              </div>
            </Panel>
          );
        })}
      </div>
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between text-xs">
      <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">{label}</span>
      <span>{value}</span>
    </div>
  );
}
function Mini({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">{label}</div>
      <Mono className="mt-0.5 text-sm">{value}</Mono>
    </div>
  );
}