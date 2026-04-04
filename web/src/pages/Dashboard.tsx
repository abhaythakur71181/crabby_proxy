import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { formatBytes, formatDuration, formatNumber } from '@/lib/format';
import { StatCard } from '@/components/StatCard';
import { StatusDot } from '@/components/StatusDot';
import { Badge } from '@/components/ui/badge';
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from '@/components/ui/table';
import { Skeleton } from '@/components/ui/skeleton';
import { Timer, Cable, Activity, Wifi, Users, Landmark } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function Dashboard() {
  const { data, isLoading } = useQuery({ queryKey: ['dashboard'], queryFn: api.getDashboard, refetchInterval: 10000 });

  if (isLoading || !data) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-28 rounded-lg" />)}
        </div>
      </div>
    );
  }

  const statusColor = data.status === 'healthy' ? 'green' : data.status === 'degraded' ? 'yellow' : 'red';

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <div className="flex items-center gap-2">
          <StatusDot color={statusColor} />
          <span className="text-sm text-muted-foreground capitalize">{data.status}</span>
          <Badge variant="outline" className="text-xs font-mono border-primary/30 text-primary">{data.version}</Badge>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <StatCard label="Uptime" value={formatDuration(data.uptime_seconds)} icon={<Timer className="h-5 w-5" />} color="cyan" />
        <StatCard label="Active Connections" value={formatNumber(data.active_connections)} icon={<Cable className="h-5 w-5" />} color="green" />
        <StatCard label="Total Connections" value={formatNumber(data.total_connections)} icon={<Activity className="h-5 w-5" />} color="blue" />
        <StatCard label="Bandwidth (24h)" value={formatBytes(data.bandwidth_24h)} icon={<Wifi className="h-5 w-5" />} color="teal" />
        <StatCard label="Total Users" value={formatNumber(data.total_users)} icon={<Users className="h-5 w-5" />} color="purple" />
        <StatCard label="Active Tunnels" value={formatNumber(data.active_tunnels)} icon={<Landmark className="h-5 w-5" />} color="amber" />
      </div>

      {/* Bandwidth */}
      <div className="glass-card p-5 space-y-3">
        <h2 className="text-sm font-semibold text-muted-foreground">Bandwidth Breakdown</h2>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <p className="text-xs text-muted-foreground mb-1">Sent</p>
            <div className="h-3 bg-secondary rounded-full overflow-hidden">
              <div className="h-full bg-primary rounded-full transition-all duration-1000" style={{ width: `${(data.bytes_sent + data.bytes_received) > 0 ? (data.bytes_sent / (data.bytes_sent + data.bytes_received)) * 100 : 50}%` }} />
            </div>
            <p className="text-sm font-mono text-primary mt-1">{formatBytes(data.bytes_sent)}</p>
          </div>
          <div>
            <p className="text-xs text-muted-foreground mb-1">Received</p>
            <div className="h-3 bg-secondary rounded-full overflow-hidden">
              <div className="h-full bg-cyan-light rounded-full transition-all duration-1000" style={{ width: `${(data.bytes_sent + data.bytes_received) > 0 ? (data.bytes_received / (data.bytes_sent + data.bytes_received)) * 100 : 50}%` }} />
            </div>
            <p className="text-sm font-mono text-cyan-light mt-1">{formatBytes(data.bytes_received)}</p>
          </div>
        </div>
      </div>

      {/* Top Users */}
      <div className="glass-card p-5">
        <h2 className="text-sm font-semibold text-muted-foreground mb-3">Top Users (24h)</h2>
        <Table>
          <TableHeader>
            <TableRow className="border-border/50">
              <TableHead className="w-12">#</TableHead>
              <TableHead>User</TableHead>
              <TableHead className="text-right">Bandwidth</TableHead>
              <TableHead className="text-right">Connections</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {(data.top_users_24h || []).map((u: any, i: number) => (
              <TableRow key={u.user_id} className="border-border/30">
                <TableCell className="font-mono text-muted-foreground">{i + 1}</TableCell>
                <TableCell>
                  <Link to={`/users/${u.user_id}`} className="text-primary hover:underline font-mono">User #{u.user_id}</Link>
                </TableCell>
                <TableCell className="text-right font-mono text-sm">{formatBytes(u.bandwidth)}</TableCell>
                <TableCell className="text-right font-mono text-sm">{formatNumber(u.connections)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
