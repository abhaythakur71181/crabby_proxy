import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { formatBytes, formatNumber } from '@/lib/format';
import { StatCard } from '@/components/StatCard';
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from '@/components/ui/table';
import { Link } from 'react-router-dom';
import { Cable, Wifi, Users, Activity } from 'lucide-react';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Tooltip } from 'chart.js';
import { Bar } from 'react-chartjs-2';
import { Skeleton } from '@/components/ui/skeleton';
import { EmptyState } from '@/components/EmptyState';

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip);

export default function UsageSummary() {
  const { data, isLoading, isError } = useQuery({ queryKey: ['usage-summary'], queryFn: () => api.getUsageSummary() });

  if (isLoading) return <div className="space-y-4"><Skeleton className="h-10 w-64" /><Skeleton className="h-64" /></div>;
  if (isError || !data) return <EmptyState title="Couldn't load usage summary" icon="⚠️" />;

  // Backend `/api/usage/summary` top_users carry { user_id, total_bandwidth,
  // connection_count } and no username, so label rows by user id.
  const topUsers = data.top_users ?? [];
  const chartData = {
    labels: topUsers.map(u => `User #${u.user_id}`),
    datasets: [{
      label: 'Bandwidth',
      data: topUsers.map(u => (u.total_bandwidth ?? 0) / (1024 * 1024)),
      backgroundColor: '#06b6d4',
      borderRadius: 4,
    }],
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Usage & Quotas</h1>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total Connections" value={formatNumber(data.total_connections)} icon={<Cable className="h-5 w-5" />} color="cyan" />
        <StatCard label="Total Bandwidth" value={formatBytes(data.total_bandwidth)} icon={<Wifi className="h-5 w-5" />} color="teal" />
        <StatCard label="Unique Users" value={formatNumber(data.unique_users)} icon={<Users className="h-5 w-5" />} color="purple" />
        <StatCard label="Data Sent" value={formatBytes(data.total_bytes_sent)} icon={<Activity className="h-5 w-5" />} color="blue" />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="glass-card p-5">
          <h2 className="text-sm font-semibold text-muted-foreground mb-3">Top Users by Bandwidth</h2>
          <div className="h-64">
            <Bar data={chartData} options={{
              responsive: true, maintainAspectRatio: false, indexAxis: 'y' as const,
              plugins: { legend: { display: false } },
              scales: {
                x: { ticks: { color: 'hsl(215,20%,55%)', callback: (v) => `${v} MB` }, grid: { color: 'hsl(217,33%,15%)' } },
                y: { ticks: { color: 'hsl(210,40%,70%)' }, grid: { display: false } },
              },
            }} />
          </div>
        </div>

        <div className="glass-card p-5">
          <h2 className="text-sm font-semibold text-muted-foreground mb-3">Top Users Leaderboard</h2>
          <Table>
            <TableHeader><TableRow className="border-border/50">
              <TableHead>#</TableHead><TableHead>User</TableHead><TableHead className="text-right">Bandwidth</TableHead><TableHead className="text-right">Connections</TableHead>
            </TableRow></TableHeader>
            <TableBody>
              {topUsers.map((u, i) => (
                <TableRow key={u.user_id} className="border-border/30">
                  <TableCell className="font-mono text-muted-foreground">{i + 1}</TableCell>
                  <TableCell><Link to={`/users/${u.user_id}`} className="text-primary hover:underline">User #{u.user_id}</Link></TableCell>
                  <TableCell className="text-right font-mono text-sm">{formatBytes(u.total_bandwidth)}</TableCell>
                  <TableCell className="text-right font-mono text-sm">{formatNumber(u.connection_count)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </div>
    </div>
  );
}
