import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { formatDuration, formatBytes } from '@/lib/format';
import { StatCard } from '@/components/StatCard';
import { StatusDot } from '@/components/StatusDot';
import { Skeleton } from '@/components/ui/skeleton';
import { HeartPulse, Database, Server, Globe } from 'lucide-react';
import {
  Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale,
  LinearScale, BarElement, PointElement, LineElement, Filler,
} from 'chart.js';
import { Doughnut, Bar } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, PointElement, LineElement, Filler);

const chartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: { legend: { labels: { color: 'hsl(210, 40%, 70%)' } } },
  scales: {
    x: { ticks: { color: 'hsl(215, 20%, 55%)' }, grid: { color: 'hsl(217, 33%, 15%)' } },
    y: { ticks: { color: 'hsl(215, 20%, 55%)' }, grid: { color: 'hsl(217, 33%, 15%)' } },
  },
};

export default function SystemHealth() {
  const { data: health } = useQuery({ queryKey: ['health'], queryFn: api.getHealth, refetchInterval: 10000 });
  const { data: deep } = useQuery({ queryKey: ['deep-health'], queryFn: api.getDeepHealth, refetchInterval: 30000 });
  const { data: metrics } = useQuery({ queryKey: ['metrics'], queryFn: api.getMetrics, refetchInterval: 10000 });

  if (!health) return <div className="space-y-4"><Skeleton className="h-10 w-48" /><div className="grid grid-cols-3 gap-4">{[1,2,3].map(i => <Skeleton key={i} className="h-32" />)}</div></div>;

  const statusColor = health.status === 'healthy' ? 'green' : 'yellow';

  const protocolData = metrics ? {
    labels: Object.keys(metrics.active_by_protocol),
    datasets: [{
      data: Object.values(metrics.active_by_protocol),
      backgroundColor: ['#3b82f6', '#10b981', '#f97316', '#8b5cf6', '#06b6d4'],
      borderWidth: 0,
    }],
  } : null;

  const authFailureData = metrics ? {
    labels: Object.keys(metrics.auth_failures_by_reason).map(k => k.replace(/_/g, ' ')),
    datasets: [{
      label: 'Failures',
      data: Object.values(metrics.auth_failures_by_reason),
      backgroundColor: ['#ef4444', '#f59e0b', '#6b7280'],
      borderWidth: 0,
      borderRadius: 4,
    }],
  } : null;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <h1 className="text-2xl font-bold">System Health</h1>
        <StatusDot color={statusColor} />
        <span className="text-sm text-muted-foreground capitalize">{health.status}</span>
      </div>

      {metrics?.draining && (
        <div className="p-3 rounded-lg bg-amber/10 border border-amber/30 text-amber text-sm flex items-center gap-2">
          ⚠️ Proxy is shutting down — draining {metrics.draining_connections} remaining connections
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <StatCard label="Uptime" value={formatDuration(health.uptime_seconds)} icon={<HeartPulse className="h-5 w-5" />} color="cyan" />
        <StatCard label="Version" value={health.version} icon={<Server className="h-5 w-5" />} color="blue" />
        <StatCard label="Total Bandwidth" value={metrics ? formatBytes(metrics.bytes_transferred.sent + metrics.bytes_transferred.received) : '—'} icon={<Globe className="h-5 w-5" />} color="teal" />
      </div>

      {/* Health Checks */}
      {deep?.checks && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {Object.entries(deep.checks).map(([name, check]) => (
            <div key={name} className="glass-card p-4 flex items-start gap-3">
              <StatusDot color={check.status === 'ok' ? 'green' : 'red'} className="mt-1" />
              <div>
                <p className="font-semibold text-sm capitalize">{name.replace(/_/g, ' ')}</p>
                <p className="text-xs text-muted-foreground">{check.detail || 'OK'}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Charts */}
      {metrics && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="glass-card p-5">
            <h3 className="text-sm font-semibold text-muted-foreground mb-3">Active Connections by Protocol</h3>
            <div className="h-64">{protocolData && <Doughnut data={protocolData} options={{ responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: 'hsl(210,40%,70%)' } } } }} />}</div>
          </div>
          <div className="glass-card p-5">
            <h3 className="text-sm font-semibold text-muted-foreground mb-3">Auth Failures by Reason</h3>
            <div className="h-64">{authFailureData && <Bar data={authFailureData} options={chartOptions} />}</div>
          </div>
          <div className="glass-card p-5">
            <h3 className="text-sm font-semibold text-muted-foreground mb-3">Connection Duration Percentiles</h3>
            <div className="flex items-end gap-6 h-40 px-4">
              {[['p50', metrics.connection_duration_p50], ['p95', metrics.connection_duration_p95], ['p99', metrics.connection_duration_p99]].map(([label, val]) => (
                <div key={label as string} className="flex-1 flex flex-col items-center gap-2">
                  <div className="w-full bg-primary/30 rounded-t" style={{ height: `${Math.min(100, (val as number / metrics.connection_duration_p99) * 100)}%` }} />
                  <span className="text-lg font-mono font-bold text-primary">{(val as number).toFixed(1)}s</span>
                  <span className="text-xs text-muted-foreground">{label as string}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="glass-card p-5">
            <h3 className="text-sm font-semibold text-muted-foreground mb-3">Request Summary</h3>
            <div className="space-y-4">
              <div className="flex justify-between"><span className="text-sm text-muted-foreground">Successful Requests</span><span className="font-mono text-emerald-400">{metrics.requests_total.success.toLocaleString()}</span></div>
              <div className="flex justify-between"><span className="text-sm text-muted-foreground">Failed Requests</span><span className="font-mono text-red-400">{metrics.requests_total.failed.toLocaleString()}</span></div>
              <div className="flex justify-between"><span className="text-sm text-muted-foreground">IP Blocked</span><span className="font-mono text-amber">{metrics.ip_filter.blocked.toLocaleString()}</span></div>
              <div className="flex justify-between"><span className="text-sm text-muted-foreground">Rate Limited (IP)</span><span className="font-mono text-amber">{metrics.rate_limit_exceeded.ip}</span></div>
              <div className="flex justify-between"><span className="text-sm text-muted-foreground">Rate Limited (User)</span><span className="font-mono text-amber">{metrics.rate_limit_exceeded.user}</span></div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
