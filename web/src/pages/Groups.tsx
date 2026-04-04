import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { api } from '@/lib/api';
import { formatRelativeTime } from '@/lib/format';
import { useAuth } from '@/contexts/AuthContext';
import { EmptyState } from '@/components/EmptyState';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from '@/components/ui/table';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription } from '@/components/ui/dialog';
import { Skeleton } from '@/components/ui/skeleton';
import { Textarea } from '@/components/ui/textarea';
import { Plus, Trash2 } from 'lucide-react';
import { toast } from 'sonner';

export default function Groups() {
  const { hasRole } = useAuth();
  const isAdmin = hasRole('admin', 'root_admin');
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [deleteId, setDeleteId] = useState<number | null>(null);
  const [newGroup, setNewGroup] = useState({ name: '', description: '' });

  const { data: groups, isLoading } = useQuery({ queryKey: ['groups'], queryFn: api.getGroups });

  const createMut = useMutation({
    mutationFn: () => api.createGroup(newGroup),
    onSuccess: () => { toast.success('Group created'); setCreateOpen(false); setNewGroup({ name: '', description: '' }); qc.invalidateQueries({ queryKey: ['groups'] }); },
  });

  const deleteMut = useMutation({
    mutationFn: (id: number) => api.deleteGroup(id),
    onSuccess: () => { toast.success('Group deleted'); setDeleteId(null); qc.invalidateQueries({ queryKey: ['groups'] }); },
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Groups</h1>
        {isAdmin && <Button size="sm" onClick={() => setCreateOpen(true)}><Plus className="h-4 w-4 mr-1" /> Create Group</Button>}
      </div>

      {isLoading ? (
        <div className="space-y-2">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-12" />)}</div>
      ) : !groups?.length ? (
        <EmptyState title="No groups" description="Create a group to organize users." icon="📦" action={isAdmin ? { label: 'Create Group', onClick: () => setCreateOpen(true) } : undefined} />
      ) : (
        <div className="glass-card overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="border-border/50">
                <TableHead>ID</TableHead><TableHead>Name</TableHead><TableHead>Description</TableHead><TableHead className="text-right">Members</TableHead><TableHead>Created</TableHead>{isAdmin && <TableHead></TableHead>}
              </TableRow>
            </TableHeader>
            <TableBody>
              {groups.map(g => (
                <TableRow key={g.id} className="border-border/30">
                  <TableCell className="font-mono text-muted-foreground">{g.id}</TableCell>
                  <TableCell><Link to={`/groups/${g.id}`} className="text-primary hover:underline font-medium">{g.name}</Link></TableCell>
                  <TableCell className="text-sm text-muted-foreground">{g.description}</TableCell>
                  <TableCell className="text-right font-mono">{g.member_count}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{formatRelativeTime(g.created_at)}</TableCell>
                  {isAdmin && <TableCell><Button variant="ghost" size="icon" className="h-7 w-7 text-destructive" onClick={() => setDeleteId(g.id)}><Trash2 className="h-3.5 w-3.5" /></Button></TableCell>}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>Create Group</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2"><Label>Name</Label><Input value={newGroup.name} onChange={e => setNewGroup({ ...newGroup, name: e.target.value })} placeholder="Group name" /></div>
            <div className="space-y-2"><Label>Description</Label><Textarea value={newGroup.description} onChange={e => setNewGroup({ ...newGroup, description: e.target.value })} placeholder="Optional description" /></div>
          </div>
          <DialogFooter><Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button><Button onClick={() => createMut.mutate()} disabled={createMut.isPending}>Create</Button></DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={deleteId !== null} onOpenChange={() => setDeleteId(null)}>
        <DialogContent>
          <DialogHeader><DialogTitle>Delete Group</DialogTitle><DialogDescription>Are you sure? This will remove all members from the group.</DialogDescription></DialogHeader>
          <DialogFooter><Button variant="outline" onClick={() => setDeleteId(null)}>Cancel</Button><Button variant="destructive" onClick={() => deleteId && deleteMut.mutate(deleteId)} disabled={deleteMut.isPending}>Delete</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
