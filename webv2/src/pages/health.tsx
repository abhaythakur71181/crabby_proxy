// System health — real component checks from /health/deep (latency,
// checked-at) and the full /api/metrics JSON the old UI never integrated:
// protocol mix, auth failures by reason, rate limits, IP filter, latency
// percentiles, draining state. No fabricated sparklines.
import { Activity, Ban, Gauge, ShieldAlert } from "lucide-react";
import { useMemo } from "react";
import { formatBytes, formatCompact, formatDuration, formatRelative } from "@/lib/format";
import { useDeepHealth, useJsonMetrics } from "@/hooks/queries";
import { BarList, Donut } from "@/components/charts";
import { Stagger, StaggerItem } from "@/components/motion";
import { Panel, PanelHeader } from "@/components/ui/card";
import { StatCard } from "@/components/ui/stat-card";
import { Mono, Progress } from "@/components/ui/misc";
import { StatusPill } from "@/components/ui/badge";
import { EmptyState, ErrorState, Skeleton } from "@/components/ui/states";

export function HealthPage() {
  const health = useDeepHealth();
  const metrics = useJsonMetrics();

  const protocolMix = useMemo(
    () =>
      Object.entries(metrics.data?.active_by_protocol ?? {})
        .map(([label, value]) => ({ label, value }))
        .sort((a, b) => b.value - a.value),
    [metrics.data],
  );

  const authFailures = useMemo(
    () =>
      Object.entries(metrics.data?.auth_failures_by_reason ?? {})
        .map(([reason, count]) => ({
          key: reason,
          label: reason.replace(/_/g, " "),
          value: count,
        }))
        .sort((a, b) => b.value - a.value),
    [metrics.data],
  );

  if (health.isError && metrics.isError) {
    return (
      <ErrorState
        title="Couldn't load system health"
        detail={(health.error as Error)?.message}
        onRetry={() => {
          health.refetch();
          metrics.refetch();
        }}
      />
    );
  }

  const m = metrics.data;
  const totalReq = (m?.requests_total.success ?? 0) + (m?.requests_total.failed ?? 0);
  const successRate = totalReq > 0 ? ((m?.requests_total.success ?? 0) / totalReq) * 100 : null;

  return (
    <Stagger className="space-y-4">
      {/* Draining banner */}
      {m?.draining && (
        <Panel className="flex items-center gap-3 border-warning/30 bg-warning-soft/50 px-4 py-3">
          <ShieldAlert className="size-4.5 text-warning" aria-hidden />
          <div className="text-[13px]">
            <span className="font-semibold">Server is draining.</span>{" "}
            <span className="text-fg-muted">
              Not accepting new connections; {m.draining_connections} still open.
            </span>
          </div>
        </Panel>
      )}

      {/* Component checks */}
      <StaggerItem className="grid gap-4 sm:grid-cols-3">
        {health.isLoading &&
          [0, 1, 2].map((i) => <Skeleton key={i} className="h-28" />)}
        {health.data &&
          Object.entries(health.data.checks).map(([name, c]) => (
            <Panel key={name} className="p-4">
              <div className="flex items-center justify-between">
                <span className="eyebrow">{name.replace(/_/g, " ")}</span>
                <StatusPill
                  tone={c.status === "ok" ? "success" : "danger"}
                  label={c.status === "ok" ? "healthy" : "failing"}
                  pulse={c.status !== "ok"}
                />
              </div>
              <div className="mt-2 font-mono num text-[24px] font-semibold">
                {c.latency_ms.toFixed(1)}
                <span className="text-[13px] text-fg-faint"> ms</span>
              </div>
              <div className="mt-1 text-[11.5px] text-fg-faint">
                {c.detail || `checked ${formatRelative(c.checked_at)}`}
              </div>
            </Panel>
          ))}
      </StaggerItem>

      {/* KPIs */}
      <StaggerItem className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Success rate"
          value={successRate != null ? `${successRate.toFixed(1)}%` : "—"}
          icon={Gauge}
          loading={metrics.isLoading}
          hint={`${formatCompact(m?.requests_total.success)} ok · ${formatCompact(m?.requests_total.failed)} failed`}
        />
        <StatCard
          label="Bytes moved"
          value={(m?.bytes_transferred.sent ?? 0) + (m?.bytes_transferred.received ?? 0)}
          format={(n) => formatBytes(n)}
          icon={Activity}
          loading={metrics.isLoading}
          hint={`↑ ${formatBytes(m?.bytes_transferred.sent)} · ↓ ${formatBytes(m?.bytes_transferred.received)}`}
        />
        <StatCard
          label="Rate-limit hits"
          value={(m?.rate_limit_exceeded.ip ?? 0) + (m?.rate_limit_exceeded.user ?? 0)}
          icon={Ban}
          loading={metrics.isLoading}
          hint={`ip ${formatCompact(m?.rate_limit_exceeded.ip)} · user ${formatCompact(m?.rate_limit_exceeded.user)}`}
        />
        <StatCard
          label="IP filter"
          value={m ? `${formatCompact(m.ip_filter.blocked)} blocked` : null}
          icon={ShieldAlert}
          loading={metrics.isLoading}
          hint={`${formatCompact(m?.ip_filter.allowed)} allowed`}
        />
      </StaggerItem>

      <div className="grid gap-4 xl:grid-cols-3">
        {/* Latency percentiles */}
        <StaggerItem>
          <Panel className="h-full">
            <PanelHeader eyebrow="connection duration" title="Latency percentiles" />
            <div className="space-y-4 px-4 pb-5">
              {metrics.isLoading ? (
                <Skeleton className="h-28" />
              ) : (
                (["p50", "p95", "p99"] as const).map((p) => {
                  const v = m?.[`connection_duration_${p}`] ?? 0;
                  const max = Math.max(m?.connection_duration_p99 ?? 1, 0.001);
                  return (
                    <div key={p}>
                      <div className="mb-1 flex justify-between text-[12.5px]">
                        <span className="font-medium uppercase">{p}</span>
                        <Mono>{v < 1 ? `${(v * 1000).toFixed(0)}ms` : formatDuration(v)}</Mono>
                      </div>
                      <Progress
                        value={(v / max) * 100}
                        tone={p === "p99" ? "warning" : "accent"}
                      />
                    </div>
                  );
                })
              )}
              {!metrics.isLoading && (m?.connection_duration_p99 ?? 0) === 0 && (
                <p className="text-[12px] text-fg-faint">No completed connections sampled yet.</p>
              )}
            </div>
          </Panel>
        </StaggerItem>

        {/* Protocol mix */}
        <StaggerItem>
          <Panel className="h-full">
            <PanelHeader eyebrow="active now" title="Protocol mix" />
            <div className="px-4 pb-4">
              {metrics.isLoading ? <Skeleton className="h-[148px]" /> : <Donut segments={protocolMix} />}
            </div>
          </Panel>
        </StaggerItem>

        {/* Auth failures */}
        <StaggerItem>
          <Panel className="h-full">
            <PanelHeader eyebrow="by reason" title="Auth failures" />
            <div className="px-4 pb-4">
              {metrics.isLoading ? (
                <Skeleton className="h-28" />
              ) : authFailures.length === 0 ? (
                <EmptyState
                  title="No auth failures"
                  description="Failed proxy authentications group here by reason."
                  className="border-0 py-8"
                />
              ) : (
                <BarList items={authFailures} formatValue={(n) => n.toLocaleString()} />
              )}
            </div>
          </Panel>
        </StaggerItem>
      </div>

      {/* Version footer */}
      {health.data && (
        <StaggerItem>
          <Panel className="flex flex-wrap items-center gap-x-6 gap-y-1 px-4 py-3 text-[12px] text-fg-faint">
            <span>
              Version <Mono>{health.data.version}</Mono>
            </span>
            <span>
              Uptime <Mono>{formatDuration(health.data.uptime_seconds)}</Mono>
            </span>
            <span>
              Overall{" "}
              <StatusPill
                tone={health.data.status === "healthy" ? "success" : "danger"}
                label={health.data.status}
              />
            </span>
          </Panel>
        </StaggerItem>
      )}
    </Stagger>
  );
}
