import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { formatRelativeTime } from '@/lib/format';
import { EmptyState } from '@/components/EmptyState';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from '@/components/ui/table';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription } from '@/components/ui/dialog';
import { Plus } from 'lucide-react';
import { toast } from 'sonner';

const serviceColors: Record<string, string> = {
  http: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  https: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
  ssh: 'bg-green-500/20 text-green-400 border-green-500/30',
  postgres: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  mysql: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  redis: 'bg-red-500/20 text-red-400 border-red-500/30',
  mongodb: 'bg-green-600/20 text-green-500 border-green-600/30',
};

export default function Tunnels() {
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [closePort, setClosePort] = useState<number | null>(null);
  const [newTunnel, setNewTunnel] = useState({ service_type: 'http', port: '', target_addr: '' });

  const { data, isLoading } = useQuery({ queryKey: ['tunnels'], queryFn: api.getTunnels });

  const createMut = useMutation({
    mutationFn: () => api.createTunnel({ service_type: newTunnel.service_type, port: newTunnel.port ? Number(newTunnel.port) : undefined, target_addr: newTunnel.target_addr || undefined }),
    onSuccess: () => { toast.success('Tunnel created'); setCreateOpen(false); qc.invalidateQueries({ queryKey: ['tunnels'] }); },
  });

  const closeMut = useMutation({
    mutationFn: (port: number) => api.closeTunnel(port),
    onSuccess: () => { toast.success('Tunnel closed'); setClosePort(null); qc.invalidateQueries({ queryKey: ['tunnels'] }); },
  });

  const tunnels = data?.tunnels || [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Tunnels</h1>
        <Button size="sm" onClick={() => setCreateOpen(true)}><Plus className="h-4 w-4 mr-1" /> Create Tunnel</Button>
      </div>

      {isLoading || !tunnels.length ? (
        !isLoading ? <EmptyState title="No tunnels" description="Create a reverse tunnel to expose services." icon="🚇" /> : null
      ) : (
        <div className="glass-card overflow-hidden">
          <Table>
            <TableHeader><TableRow className="border-border/50">
              <TableHead>Port</TableHead><TableHead>Service</TableHead><TableHead>Target</TableHead><TableHead>Status</TableHead><TableHead>Created</TableHead><TableHead></TableHead>
            </TableRow></TableHeader>
            <TableBody>
              {tunnels.map(t => (
                <TableRow key={t.listen_port} className="border-border/30">
                  <TableCell className="font-mono font-bold">{t.listen_port}</TableCell>
                  <TableCell><span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${serviceColors[t.service_type] || 'bg-muted text-muted-foreground border-border'}`}>{t.service_type}</span></TableCell>
                  <TableCell className="font-mono text-xs">{t.target_addr}</TableCell>
                  <TableCell><Badge variant={t.status === 'active' ? 'default' : 'secondary'} className="text-xs">{t.status}</Badge></TableCell>
                  <TableCell className="text-xs text-muted-foreground">{formatRelativeTime(t.created_at)}</TableCell>
                  <TableCell><Button variant="ghost" size="sm" className="text-destructive text-xs" onClick={() => setClosePort(t.listen_port)}>Close</Button></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>Create Tunnel</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Service Type</Label>
              <Select value={newTunnel.service_type} onValueChange={v => setNewTunnel({ ...newTunnel, service_type: v })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {['http', 'https', 'ssh', 'postgres', 'mysql', 'redis', 'mongodb'].map(s => <SelectItem key={s} value={s}>{s}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2"><Label>Port (optional, auto-assigned if empty)</Label><Input type="number" value={newTunnel.port} onChange={e => setNewTunnel({ ...newTunnel, port: e.target.value })} placeholder="10000-10999" /></div>
            <div className="space-y-2"><Label>Target Address</Label><Input value={newTunnel.target_addr} onChange={e => setNewTunnel({ ...newTunnel, target_addr: e.target.value })} placeholder="127.0.0.1:3000" /></div>
          </div>
          <DialogFooter><Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button><Button onClick={() => createMut.mutate()} disabled={createMut.isPending}>Create</Button></DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={closePort !== null} onOpenChange={() => setClosePort(null)}>
        <DialogContent>
          <DialogHeader><DialogTitle>Close Tunnel</DialogTitle><DialogDescription>Close tunnel on port {closePort}?</DialogDescription></DialogHeader>
          <DialogFooter><Button variant="outline" onClick={() => setClosePort(null)}>Cancel</Button><Button variant="destructive" onClick={() => closePort && closeMut.mutate(closePort)}>Close</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
