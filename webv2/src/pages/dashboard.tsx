// Dashboard — bento grid. Every pill and number here is real data:
// KPIs from /api/dashboard, traffic from /api/usage/timeseries, protocol
// mix from /api/metrics, health strip from /health/deep, activity from
// /api/audit-log, live feed from the WS+poll hybrid.
import { Link } from "react-router";
import {
  ArrowDownToLine,
  ArrowUpFromLine,
  Cable,
  Clock3,
  FileClock,
  Users,
  Waypoints,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { fillTimeseriesGaps } from "@/lib/utils";
import { formatBytes, formatCompact, formatDuration, formatRelative, humanizeAction, splitHostPort } from "@/lib/format";
import {
  useAuditLog,
  useDashboard,
  useDeepHealth,
  useJsonMetrics,
  useUsageTimeseries,
  useUserDirectory,
} from "@/hooks/queries";
import { useLiveConnections } from "@/hooks/use-live-connections";
import { AreaChart, BarList, Donut } from "@/components/charts";
import { Stagger, StaggerItem } from "@/components/motion";
import { Panel, PanelHeader } from "@/components/ui/card";
import { StatCard } from "@/components/ui/stat-card";
import { Mono } from "@/components/ui/misc";
import { ProtocolBadge, StatusPill } from "@/components/ui/badge";
import { EmptyState, ErrorState, Skeleton } from "@/components/ui/states";

export function DashboardPage() {
  const dash = useDashboard();
  const metrics = useJsonMetrics();
  const health = useDeepHealth();
  const ts = useUsageTimeseries(1, "hour");
  const audit = useAuditLog({ limit: 8, offset: 0 });
  const live = useLiveConnections();
  const resolveUser = useUserDirectory();

  // Uptime ticks locally between polls so it feels alive.
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setTick((v) => v + 1), 1000);
    return () => clearInterval(t);
  }, []);
  const uptime =
    dash.data != null
      ? dash.data.uptime_seconds + Math.floor((Date.now() - dash.dataUpdatedAt) / 1000)
      : null;
  void tick;

  const traffic = useMemo(() => {
    if (!ts.data) return [];
    return fillTimeseriesGaps(ts.data.points, ts.data.bucket_secs, 1).map((p) => ({
      ts: p.ts,
      value: p.bytes_sent,
      value2: p.bytes_received,
    }));
  }, [ts.data]);

  const protocolMix = useMemo(
    () =>
      Object.entries(metrics.data?.active_by_protocol ?? {})
        .map(([label, value]) => ({ label, value }))
        .sort((a, b) => b.value - a.value),
    [metrics.data],
  );

  const topUsers = useMemo(
    () =>
      (dash.data?.top_users_24h ?? []).map((u) => ({
        key: u.user_id,
        label: (
          <Link to={`/users/${u.user_id}`} className="hover:text-accent hover:underline">
            {resolveUser(u.user_id)}
          </Link>
        ),
        value: u.bandwidth,
      })),
    [dash.data, resolveUser],
  );

  if (dash.isError) {
    return (
      <ErrorState
        title="Couldn't load the dashboard"
        detail={(dash.error as Error)?.message}
        onRetry={() => dash.refetch()}
      />
    );
  }

  return (
    <Stagger className="space-y-4">
      {/* KPI row */}
      <StaggerItem className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Active connections"
          value={dash.data?.active_connections}
          icon={Waypoints}
          loading={dash.isLoading}
          hint="right now"
          trend={
            <StatusPill
              tone={live.socketState === "live" ? "success" : "warning"}
              label={live.socketState === "live" ? "streaming" : live.socketState}
              pulse={live.socketState === "live"}
            />
          }
        />
        <StatCard
          label="Connections · 24h"
          value={dash.data?.connections_24h ?? dash.data?.total_connections}
          icon={Clock3}
          loading={dash.isLoading}
          hint={`total all-time ${formatCompact(dash.data?.total_connections)}`}
        />
        <StatCard
          label="Bandwidth · 24h"
          value={dash.data?.bandwidth_24h}
          format={(n) => formatBytes(n)}
          icon={ArrowDownToLine}
          loading={dash.isLoading}
          hint={`sent ${formatBytes(dash.data?.bytes_sent)} · recv ${formatBytes(dash.data?.bytes_received)}`}
        />
        <StatCard
          label="Users"
          value={dash.data?.total_users}
          icon={Users}
          loading={dash.isLoading}
          hint={`${dash.data?.active_tunnels ?? 0} active tunnels · up ${formatDuration(uptime)}`}
        />
      </StaggerItem>

      {/* Traffic + protocol mix */}
      <div className="grid gap-4 xl:grid-cols-[2fr_1fr]">
        <StaggerItem>
          <Panel glow>
            <PanelHeader
              eyebrow="last 24 hours"
              title="Traffic"
              actions={
                <div className="flex items-center gap-3 text-[11.5px] text-fg-muted">
                  <span className="flex items-center gap-1.5">
                    <span className="size-1.5 rounded-full bg-accent" /> Sent
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="size-1.5 rounded-full bg-info" /> Received
                  </span>
                </div>
              }
            />
            <div className="px-4 pb-4">
              {ts.isLoading ? (
                <Skeleton className="h-[180px]" />
              ) : traffic.length === 0 || traffic.every((p) => p.value === 0 && p.value2 === 0) ? (
                <EmptyState
                  title="No traffic in the last 24 hours"
                  description="Bytes will chart here as soon as clients start proxying."
                  className="border-0"
                />
              ) : (
                <AreaChart points={traffic} />
              )}
            </div>
          </Panel>
        </StaggerItem>

        <StaggerItem>
          <Panel className="h-full">
            <PanelHeader eyebrow="active now" title="Protocol mix" />
            <div className="px-4 pb-4">
              {metrics.isLoading ? (
                <Skeleton className="h-[148px]" />
              ) : (
                <Donut segments={protocolMix} />
              )}
              {metrics.data && (
                <div className="mt-4 grid grid-cols-2 gap-2 border-t border-line pt-3 text-[11.5px] text-fg-muted">
                  <span>
                    OK <Mono className="text-success">{formatCompact(metrics.data.requests_total.success)}</Mono>
                  </span>
                  <span>
                    Failed <Mono className="text-danger">{formatCompact(metrics.data.requests_total.failed)}</Mono>
                  </span>
                  <span>
                    p95 <Mono>{metrics.data.connection_duration_p95.toFixed(1)}s</Mono>
                  </span>
                  <span>
                    p99 <Mono>{metrics.data.connection_duration_p99.toFixed(1)}s</Mono>
                  </span>
                </div>
              )}
            </div>
          </Panel>
        </StaggerItem>
      </div>

      {/* Top users + live feed + activity */}
      <div className="grid gap-4 xl:grid-cols-3">
        <StaggerItem>
          <Panel className="h-full">
            <PanelHeader eyebrow="24h bandwidth" title="Top users" />
            <div className="px-4 pb-4">
              {dash.isLoading ? (
                <div className="space-y-3">
                  {[0, 1, 2].map((i) => <Skeleton key={i} className="h-8" />)}
                </div>
              ) : topUsers.length === 0 ? (
                <EmptyState icon={Users} title="No usage yet" className="border-0 py-8" />
              ) : (
                <BarList items={topUsers} />
              )}
            </div>
          </Panel>
        </StaggerItem>

        <StaggerItem>
          <Panel className="h-full">
            <PanelHeader
              eyebrow="live"
              title="Connection feed"
              actions={
                <Link to="/connections" className="text-[12px] font-medium text-accent hover:underline">
                  View all
                </Link>
              }
            />
            <div className="px-2 pb-3">
              {live.isLoading ? (
                <div className="space-y-2 px-2">
                  {[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-7" />)}
                </div>
              ) : live.connections.length === 0 ? (
                <EmptyState icon={Waypoints} title="No active connections" className="mx-2 border-0 py-8" />
              ) : (
                <ul>
                  {live.connections.slice(0, 7).map((c) => {
                    const target = splitHostPort(c.target_addr);
                    return (
                      <li
                        key={c.id}
                        className="flex items-center gap-2.5 rounded-md px-2 py-1.5 text-[12.5px] hover:bg-surface-2"
                      >
                        <ProtocolBadge protocol={c.protocol} />
                        <Mono className="min-w-0 flex-1 truncate">{target.host}</Mono>
                        <Mono className="text-fg-faint">
                          {formatBytes(c.bytes_sent + c.bytes_received)}
                        </Mono>
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>
          </Panel>
        </StaggerItem>

        <StaggerItem>
          <Panel className="h-full">
            <PanelHeader
              eyebrow="recent"
              title="Activity"
              actions={
                <Link to="/audit" className="text-[12px] font-medium text-accent hover:underline">
                  Audit log
                </Link>
              }
            />
            <div className="px-4 pb-4">
              {audit.isLoading ? (
                <div className="space-y-2">
                  {[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-7" />)}
                </div>
              ) : (audit.data?.entries.length ?? 0) === 0 ? (
                <EmptyState icon={FileClock} title="No admin activity yet" className="border-0 py-8" />
              ) : (
                <ol className="relative space-y-3 border-l border-line pl-4">
                  {audit.data!.entries.map((e) => (
                    <li key={e.id} className="relative">
                      <span
                        aria-hidden
                        className="absolute -left-[21.5px] top-1.5 size-2 rounded-full border-2 border-surface-1 bg-accent"
                      />
                      <div className="text-[12.5px] font-medium leading-tight">
                        {humanizeAction(e.action)}
                      </div>
                      <div className="mt-0.5 flex items-center gap-2 text-[11.5px] text-fg-faint">
                        <span>{resolveUser(e.user_id)}</span>
                        <span aria-hidden>·</span>
                        <span>{formatRelative(e.created_at)}</span>
                      </div>
                    </li>
                  ))}
                </ol>
              )}
            </div>
          </Panel>
        </StaggerItem>
      </div>

      {/* Health strip */}
      <StaggerItem>
        <Panel className="flex flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3">
          <span className="eyebrow">System</span>
          {health.isLoading && <Skeleton className="h-5 w-64" />}
          {health.data &&
            Object.entries(health.data.checks).map(([name, c]) => (
              <span key={name} className="flex items-center gap-2 text-[12.5px]">
                <StatusPill
                  tone={c.status === "ok" ? "success" : "danger"}
                  label={name.replace(/_/g, " ")}
                />
                <Mono className="text-fg-faint">{c.latency_ms.toFixed(1)}ms</Mono>
              </span>
            ))}
          {metrics.data?.draining && (
            <StatusPill tone="warning" label={`draining ${metrics.data.draining_connections}`} pulse />
          )}
          <span className="ml-auto flex items-center gap-4 text-[11.5px] text-fg-faint">
            <span className="flex items-center gap-1">
              <ArrowUpFromLine className="size-3" /> {formatBytes(metrics.data?.bytes_transferred.sent)}
            </span>
            <span className="flex items-center gap-1">
              <ArrowDownToLine className="size-3" /> {formatBytes(metrics.data?.bytes_transferred.received)}
            </span>
            <span className="flex items-center gap-1">
              <Cable className="size-3" /> v{dash.data?.version ?? "…"}
            </span>
          </span>
        </Panel>
      </StaggerItem>
    </Stagger>
  );
}
