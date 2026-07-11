// Usage analytics — range picker (7/30/90d), gap-filled traffic chart,
// KPIs, top-users leaderboard with linked names, CSV export.
import { Download } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router";
import { downloadCsv, fillTimeseriesGaps, cn } from "@/lib/utils";
import { formatBytes, formatCompact } from "@/lib/format";
import { useUsageSummary, useUsageTimeseries, useUserDirectory } from "@/hooks/queries";
import { AreaChart, BarList } from "@/components/charts";
import { Stagger, StaggerItem } from "@/components/motion";
import { Panel, PanelHeader } from "@/components/ui/card";
import { StatCard } from "@/components/ui/stat-card";
import { Button } from "@/components/ui/button";
import { Mono } from "@/components/ui/misc";
import { TableShell, THead, Th, Td, TRow, TableSkeleton } from "@/components/ui/table";
import { EmptyState, ErrorState, Skeleton } from "@/components/ui/states";

const RANGES = [
  { days: 7, label: "7 days", bucket: "hour" as const },
  { days: 30, label: "30 days", bucket: "day" as const },
  { days: 90, label: "90 days", bucket: "day" as const },
];

export function UsagePage() {
  const [range, setRange] = useState(RANGES[1]);
  const summary = useUsageSummary(range.days);
  const ts = useUsageTimeseries(range.days, range.bucket);
  const resolveUser = useUserDirectory();

  const traffic = useMemo(() => {
    if (!ts.data) return [];
    return fillTimeseriesGaps(ts.data.points, ts.data.bucket_secs, range.days).map((p) => ({
      ts: p.ts,
      value: p.bytes_sent,
      value2: p.bytes_received,
    }));
  }, [ts.data, range.days]);

  const topUsers = useMemo(
    () =>
      (summary.data?.top_users ?? []).map((u) => ({
        key: u.user_id,
        label: (
          <Link to={`/users/${u.user_id}`} className="hover:text-accent hover:underline">
            {resolveUser(u.user_id)}
          </Link>
        ),
        value: u.total_bandwidth,
      })),
    [summary.data, resolveUser],
  );

  const exportCsv = () => {
    if (!summary.data) return;
    downloadCsv(
      `crabby-usage-${range.days}d.csv`,
      ["user_id", "username", "total_bandwidth_bytes", "connection_count"],
      summary.data.top_users.map((u) => [
        u.user_id,
        resolveUser(u.user_id),
        u.total_bandwidth,
        u.connection_count,
      ]),
    );
  };

  if (summary.isError) {
    return (
      <ErrorState
        title="Couldn't load usage"
        detail={(summary.error as Error)?.message}
        onRetry={() => summary.refetch()}
      />
    );
  }

  return (
    <Stagger className="space-y-4">
      {/* Controls */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex gap-1.5" role="group" aria-label="Time range">
          {RANGES.map((r) => (
            <button
              key={r.days}
              type="button"
              onClick={() => setRange(r)}
              aria-pressed={range.days === r.days}
              className={cn(
                "rounded-full border px-3 py-1 text-[12px] font-medium transition-all",
                range.days === r.days
                  ? "border-accent/40 bg-accent-soft text-accent"
                  : "border-line-strong text-fg-muted hover:bg-surface-2 hover:text-fg",
              )}
            >
              {r.label}
            </button>
          ))}
        </div>
        <Button variant="outline" size="sm" className="ml-auto" onClick={exportCsv} disabled={!summary.data}>
          <Download className="size-3.5" /> Export CSV
        </Button>
      </div>

      {/* KPIs */}
      <StaggerItem className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Total bandwidth"
          value={summary.data?.total_bandwidth}
          format={(n) => formatBytes(n)}
          loading={summary.isLoading}
          hint={`over ${range.days} days`}
        />
        <StatCard
          label="Connections"
          value={summary.data?.total_connections}
          format={formatCompact}
          loading={summary.isLoading}
        />
        <StatCard
          label="Unique users"
          value={summary.data?.unique_users}
          loading={summary.isLoading}
        />
        <StatCard
          label="Sent / received"
          value={
            summary.data
              ? `${formatBytes(summary.data.total_bytes_sent)} / ${formatBytes(summary.data.total_bytes_received)}`
              : null
          }
          loading={summary.isLoading}
        />
      </StaggerItem>

      {/* Chart */}
      <StaggerItem>
        <Panel glow>
          <PanelHeader
            eyebrow={`per ${range.bucket}`}
            title="Traffic over time"
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
              <Skeleton className="h-[200px]" />
            ) : traffic.every((p) => p.value === 0 && (p.value2 ?? 0) === 0) ? (
              <EmptyState title="No traffic in this window" className="border-0" />
            ) : (
              <AreaChart points={traffic} height={200} />
            )}
          </div>
        </Panel>
      </StaggerItem>

      {/* Leaderboard */}
      <StaggerItem className="grid gap-4 xl:grid-cols-2">
        <Panel>
          <PanelHeader eyebrow="by bandwidth" title="Top users" />
          <div className="px-4 pb-4">
            {summary.isLoading ? (
              <div className="space-y-3">
                {[0, 1, 2].map((i) => (
                  <Skeleton key={i} className="h-8" />
                ))}
              </div>
            ) : topUsers.length === 0 ? (
              <EmptyState title="No usage recorded" className="border-0 py-8" />
            ) : (
              <BarList items={topUsers} />
            )}
          </div>
        </Panel>

        <Panel>
          <PanelHeader eyebrow="detail" title="Leaderboard" />
          {summary.isLoading ? (
            <TableShell>
              <THead>
                <Th>#</Th>
                <Th>User</Th>
                <Th className="text-right">Bandwidth</Th>
                <Th className="text-right">Connections</Th>
              </THead>
              <TableSkeleton cols={4} rows={5} />
            </TableShell>
          ) : (
            <TableShell>
              <THead>
                <Th>#</Th>
                <Th>User</Th>
                <Th className="text-right">Bandwidth</Th>
                <Th className="text-right">Connections</Th>
              </THead>
              <tbody>
                {(summary.data?.top_users ?? []).map((u, i) => (
                  <TRow key={u.user_id}>
                    <Td className="text-fg-faint">
                      <Mono>{i + 1}</Mono>
                    </Td>
                    <Td>
                      <Link to={`/users/${u.user_id}`} className="font-medium hover:text-accent hover:underline">
                        {resolveUser(u.user_id)}
                      </Link>
                    </Td>
                    <Td className="text-right">
                      <Mono>{formatBytes(u.total_bandwidth)}</Mono>
                    </Td>
                    <Td className="text-right">
                      <Mono>{u.connection_count.toLocaleString()}</Mono>
                    </Td>
                  </TRow>
                ))}
              </tbody>
            </TableShell>
          )}
          {!summary.isLoading && (summary.data?.top_users.length ?? 0) === 0 && (
            <EmptyState title="Nothing to rank yet" className="m-4 border-0" />
          )}
        </Panel>
      </StaggerItem>
    </Stagger>
  );
}
