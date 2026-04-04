import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { formatRelativeTime } from '@/lib/format';
import { EmptyState } from '@/components/EmptyState';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from '@/components/ui/table';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription } from '@/components/ui/dialog';
import { Plus } from 'lucide-react';
import { toast } from 'sonner';

export default function Approvals() {
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [terminateId, setTerminateId] = useState<number | null>(null);
  const [terminateReason, setTerminateReason] = useState('');
  const [newApproval, setNewApproval] = useState({ user_id: '', client_ip: '', duration_hours: '24', reason: '' });

  const { data: approvals, isLoading } = useQuery({ queryKey: ['approvals'], queryFn: api.getApprovals });

  const createMut = useMutation({
    mutationFn: () => api.createApproval({ user_id: Number(newApproval.user_id), client_ip: newApproval.client_ip, duration_hours: Number(newApproval.duration_hours), reason: newApproval.reason }),
    onSuccess: () => { toast.success('Approval created'); setCreateOpen(false); qc.invalidateQueries({ queryKey: ['approvals'] }); },
  });

  const terminateMut = useMutation({
    mutationFn: () => api.terminateApproval(terminateId!, terminateReason),
    onSuccess: () => { toast.success('Approval terminated'); setTerminateId(null); setTerminateReason(''); qc.invalidateQueries({ queryKey: ['approvals'] }); },
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Approvals</h1>
        <Button size="sm" onClick={() => setCreateOpen(true)}><Plus className="h-4 w-4 mr-1" /> Create Approval</Button>
      </div>

      {isLoading || !approvals?.length ? (
        !isLoading ? <EmptyState title="No approvals" icon="✅" /> : null
      ) : (
        <div className="glass-card overflow-hidden">
          <Table>
            <TableHeader><TableRow className="border-border/50">
              <TableHead>ID</TableHead><TableHead>User</TableHead><TableHead>Client IP</TableHead><TableHead>Duration</TableHead><TableHead>Expires</TableHead><TableHead>Reason</TableHead><TableHead></TableHead>
            </TableRow></TableHeader>
            <TableBody>
              {approvals.map(a => (
                <TableRow key={a.id} className="border-border/30">
                  <TableCell className="font-mono text-muted-foreground">{a.id}</TableCell>
                  <TableCell className="text-primary text-sm">{a.username}</TableCell>
                  <TableCell className="font-mono text-xs">{a.client_ip}</TableCell>
                  <TableCell className="text-xs">{a.duration_hours}h</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{formatRelativeTime(a.expires_at)}</TableCell>
                  <TableCell className="text-xs max-w-[200px] truncate">{a.reason}</TableCell>
                  <TableCell><Button variant="ghost" size="sm" className="text-destructive text-xs" onClick={() => setTerminateId(a.id)}>Terminate</Button></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>Create Approval</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2"><Label>User ID</Label><Input type="number" value={newApproval.user_id} onChange={e => setNewApproval({ ...newApproval, user_id: e.target.value })} /></div>
            <div className="space-y-2"><Label>Client IP</Label><Input value={newApproval.client_ip} onChange={e => setNewApproval({ ...newApproval, client_ip: e.target.value })} placeholder="203.0.113.50" /></div>
            <div className="space-y-2"><Label>Duration (hours)</Label><Input type="number" value={newApproval.duration_hours} onChange={e => setNewApproval({ ...newApproval, duration_hours: e.target.value })} /></div>
            <div className="space-y-2"><Label>Reason</Label><Textarea value={newApproval.reason} onChange={e => setNewApproval({ ...newApproval, reason: e.target.value })} /></div>
          </div>
          <DialogFooter><Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button><Button onClick={() => createMut.mutate()} disabled={createMut.isPending}>Create</Button></DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={terminateId !== null} onOpenChange={() => setTerminateId(null)}>
        <DialogContent>
          <DialogHeader><DialogTitle>Terminate Approval</DialogTitle><DialogDescription>Please provide a reason for termination.</DialogDescription></DialogHeader>
          <div className="space-y-2"><Label>Reason</Label><Textarea value={terminateReason} onChange={e => setTerminateReason(e.target.value)} placeholder="Reason for termination..." /></div>
          <DialogFooter><Button variant="outline" onClick={() => setTerminateId(null)}>Cancel</Button><Button variant="destructive" onClick={() => terminateMut.mutate()} disabled={terminateMut.isPending || !terminateReason}>Terminate</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
