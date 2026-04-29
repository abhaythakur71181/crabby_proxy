import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { formatBytes, formatRelativeTime } from '@/lib/format';
import { ProtocolBadge } from '@/components/ProtocolBadge';
import { StatusDot } from '@/components/StatusDot';
import { SearchInput } from '@/components/SearchInput';
import { EmptyState } from '@/components/EmptyState';
import { Badge } from '@/components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from '@/components/ui/table';
import { Skeleton } from '@/components/ui/skeleton';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { CopyButton } from '@/components/CopyButton';
import type { Protocol } from '@/lib/types';
import { truncateUuid } from '@/lib/format';
import { Link } from 'react-router-dom';


export default function Connections() {
  const [search, setSearch] = useState('');
  const [protocolFilter, setProtocolFilter] = useState<string>('all');
  const { data: connections, isLoading } = useQuery({ queryKey: ['connections'], queryFn: api.getConnections, refetchInterval: 5000 });
  const { data: count } = useQuery({ queryKey: ['connection-count'], queryFn: api.getConnectionCount, refetchInterval: 5000 });

  const filtered = (connections || []).filter(c => {
    if (protocolFilter !== 'all' && c.protocol !== protocolFilter) return false;
    if (search) {
      const s = search.toLowerCase();
      return c.client_addr.toLowerCase().includes(s) || c.target_addr.toLowerCase().includes(s) || c.id.toLowerCase().includes(s);
    }
    return true;
  });

  const getUserLabel = (uid: number | null) => uid ? `User #${uid}` : 'Anonymous';

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold">Connections</h1>
          <Badge variant="outline" className="font-mono border-primary/30 text-primary">
            <StatusDot color="green" className="mr-1.5" /> {count ?? '…'}
          </Badge>
        </div>
      </div>

      <div className="flex gap-3 flex-wrap">
        <SearchInput onChange={setSearch} placeholder="Search by IP or target..." className="w-64" />
        <Select value={protocolFilter} onValueChange={setProtocolFilter}>
          <SelectTrigger className="w-36 bg-secondary/50 border-border/50">
            <SelectValue placeholder="Protocol" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Protocols</SelectItem>
            {(['HTTP', 'HTTPS', 'SOCKS4', 'SOCKS5', 'HTTP2'] as Protocol[]).map(p => (
              <SelectItem key={p} value={p}>{p}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {isLoading ? (
        <div className="space-y-2">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-12" />)}</div>
      ) : filtered.length === 0 ? (
        <EmptyState title="No connections found" description="No active connections match your filters." icon="🔌" />
      ) : (
        <div className="glass-card overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="border-border/50">
                <TableHead>ID</TableHead>
                <TableHead>Client</TableHead>
                <TableHead>Target</TableHead>
                <TableHead>Protocol</TableHead>
                <TableHead>State</TableHead>
                <TableHead>User</TableHead>
                <TableHead className="text-right">Sent</TableHead>
                <TableHead className="text-right">Received</TableHead>
                <TableHead className="text-right">Started</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map(c => (
                <TableRow key={c.id} className="border-border/30">
                  <TableCell>
                    <Tooltip>
                      <TooltipTrigger className="font-mono text-xs text-muted-foreground flex items-center gap-1">
                        {truncateUuid(c.id)}
                        <CopyButton text={c.id} />
                      </TooltipTrigger>
                      <TooltipContent className="font-mono text-xs">{c.id}</TooltipContent>
                    </Tooltip>
                  </TableCell>
                  <TableCell className="font-mono text-xs">{c.client_addr}</TableCell>
                  <TableCell className="font-mono text-xs">{c.target_addr}</TableCell>
                  <TableCell><ProtocolBadge protocol={c.protocol} /></TableCell>
                  <TableCell>
                    <span className="inline-flex items-center gap-1.5">
                      <StatusDot color={c.state === 'Active' ? 'green' : 'yellow'} />
                      <span className="text-xs">{c.state}</span>
                    </span>
                  </TableCell>
                  <TableCell>
                    {c.user_id ? (
                      <Link to={`/users/${c.user_id}`} className="text-primary text-sm hover:underline">{getUserLabel(c.user_id)}</Link>
                    ) : (
                      <span className="text-xs text-muted-foreground">Anonymous</span>
                    )}
                  </TableCell>
                  <TableCell className="text-right font-mono text-xs">{formatBytes(c.bytes_sent)}</TableCell>
                  <TableCell className="text-right font-mono text-xs">{formatBytes(c.bytes_received)}</TableCell>
                  <TableCell className="text-right text-xs text-muted-foreground">{formatRelativeTime(c.created_at)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
