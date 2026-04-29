import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { formatRelativeTime } from '@/lib/format';
import { EmptyState } from '@/components/EmptyState';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from '@/components/ui/table';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog';
import { Skeleton } from '@/components/ui/skeleton';
import { ArrowLeft, Plus, Trash2 } from 'lucide-react';
import { toast } from 'sonner';

export default function GroupDetail() {
  const { id } = useParams<{ id: string }>();
  const groupId = Number(id);
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [addOpen, setAddOpen] = useState(false);
  const [newUserId, setNewUserId] = useState('');

  const { data: group, isLoading } = useQuery({ queryKey: ['group', groupId], queryFn: () => api.getGroup(groupId) });
  const { data: membersData } = useQuery({ queryKey: ['group-members', groupId], queryFn: () => api.getGroupMembers(groupId) });

  const addMut = useMutation({
    mutationFn: () => api.addGroupMember(groupId, Number(newUserId)),
    onSuccess: () => { toast.success('Member added'); setAddOpen(false); setNewUserId(''); qc.invalidateQueries({ queryKey: ['group-members', groupId] }); },
  });

  const removeMut = useMutation({
    mutationFn: (userId: number) => api.removeGroupMember(groupId, userId),
    onSuccess: () => { toast.success('Member removed'); qc.invalidateQueries({ queryKey: ['group-members', groupId] }); },
  });

  if (isLoading) return <Skeleton className="h-64" />;
  if (!group) return <EmptyState title="Group not found" icon="❌" />;

  const members = membersData?.members || [];

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" onClick={() => navigate('/groups')}><ArrowLeft className="h-4 w-4" /></Button>
        <div className="flex-1">
          <h1 className="text-2xl font-bold">{group.name}</h1>
          <p className="text-sm text-muted-foreground">{group.description}</p>
        </div>
      </div>

      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="font-semibold">Members ({members.length})</h2>
          <Button size="sm" onClick={() => setAddOpen(true)}><Plus className="h-4 w-4 mr-1" /> Add Member</Button>
        </div>

        {!members.length ? (
          <EmptyState title="No members" description="Add users to this group." icon="👥" />
        ) : (
          <div className="glass-card overflow-hidden">
            <Table>
              <TableHeader><TableRow className="border-border/50">
                <TableHead>User ID</TableHead><TableHead>Username</TableHead><TableHead>Role</TableHead><TableHead>Joined</TableHead><TableHead></TableHead>
              </TableRow></TableHeader>
              <TableBody>
                {members.map(m => (
                  <TableRow key={m.user_id} className="border-border/30">
                    <TableCell className="font-mono text-muted-foreground">{m.user_id}</TableCell>
                    <TableCell className="text-primary">{m.username}</TableCell>
                    <TableCell className="text-xs">{m.role}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{formatRelativeTime(m.joined_at)}</TableCell>
                    <TableCell><Button variant="ghost" size="icon" className="h-7 w-7 text-destructive" onClick={() => removeMut.mutate(m.user_id)}><Trash2 className="h-3.5 w-3.5" /></Button></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>

      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>Add Member</DialogTitle></DialogHeader>
          <div className="space-y-2"><Label>User ID</Label><Input type="number" value={newUserId} onChange={e => setNewUserId(e.target.value)} placeholder="Enter user ID" /></div>
          <DialogFooter><Button variant="outline" onClick={() => setAddOpen(false)}>Cancel</Button><Button onClick={() => addMut.mutate()} disabled={addMut.isPending}>Add</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
