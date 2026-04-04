import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { formatRelativeTime } from '@/lib/format';
import { SearchInput } from '@/components/SearchInput';
import { EmptyState } from '@/components/EmptyState';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from '@/components/ui/table';
import { ChevronLeft, ChevronRight } from 'lucide-react';

export default function AuditLog() {
  const [search, setSearch] = useState('');
  const [offset, setOffset] = useState(0);
  const limit = 10;

  const { data, isLoading } = useQuery({ queryKey: ['audit-log', offset, search], queryFn: () => api.getAuditLog({ limit, offset, action: search || undefined }) });

  const entries = data?.entries || [];
  const total = data?.total || 0;
  const [expanded, setExpanded] = useState<number | null>(null);

  const actionColors: Record<string, string> = {
    'user.create': 'bg-emerald-500/20 text-emerald-400',
    'user.update': 'bg-blue-500/20 text-blue-400',
    'user.delete': 'bg-red-500/20 text-red-400',
    'user.login': 'bg-cyan-500/20 text-cyan-400',
    'config.reload': 'bg-amber-500/20 text-amber-400',
    'approval.create': 'bg-purple-500/20 text-purple-400',
    'approval.terminate': 'bg-orange-500/20 text-orange-400',
    'apikey.create': 'bg-teal-500/20 text-teal-400',
    'tunnel.create': 'bg-indigo-500/20 text-indigo-400',
    'group.create': 'bg-pink-500/20 text-pink-400',
  };

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Audit Log</h1>
      <SearchInput onChange={v => { setSearch(v); setOffset(0); }} placeholder="Filter by action..." className="w-64" />

      {isLoading || !entries.length ? (
        !isLoading ? <EmptyState title="No audit entries" icon="📋" /> : null
      ) : (
        <>
          <div className="glass-card overflow-hidden">
            <Table>
              <TableHeader><TableRow className="border-border/50">
                <TableHead>ID</TableHead><TableHead>User</TableHead><TableHead>Action</TableHead><TableHead>Target</TableHead><TableHead>IP</TableHead><TableHead>Time</TableHead>
              </TableRow></TableHeader>
              <TableBody>
                {entries.map(e => (
                  <>
                    <TableRow key={e.id} className="border-border/30 cursor-pointer hover:bg-secondary/30" onClick={() => setExpanded(expanded === e.id ? null : e.id)}>
                      <TableCell className="font-mono text-muted-foreground">{e.id}</TableCell>
                      <TableCell className="text-sm text-primary">{e.username}</TableCell>
                      <TableCell><span className={`inline-flex px-2 py-0.5 rounded text-xs font-medium ${actionColors[e.action] || 'bg-muted text-muted-foreground'}`}>{e.action}</span></TableCell>
                      <TableCell className="text-xs">{e.target_type}:{e.target_id}</TableCell>
                      <TableCell className="font-mono text-xs">{e.ip_address}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatRelativeTime(e.created_at)}</TableCell>
                    </TableRow>
                    {expanded === e.id && (
                      <TableRow key={`${e.id}-detail`} className="border-border/30">
                        <TableCell colSpan={6} className="bg-secondary/20 text-sm">{e.details}</TableCell>
                      </TableRow>
                    )}
                  </>
                ))}
              </TableBody>
            </Table>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">Showing {offset + 1}–{Math.min(offset + limit, total)} of {total}</span>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))}><ChevronLeft className="h-4 w-4" /></Button>
              <Button variant="outline" size="sm" disabled={offset + limit >= total} onClick={() => setOffset(offset + limit)}><ChevronRight className="h-4 w-4" /></Button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
