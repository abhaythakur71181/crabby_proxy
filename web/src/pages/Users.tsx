import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { api } from '@/lib/api';
import { formatRelativeTime, formatNumber } from '@/lib/format';
import { SearchInput } from '@/components/SearchInput';
import { EmptyState } from '@/components/EmptyState';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from '@/components/ui/table';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog';
import { Skeleton } from '@/components/ui/skeleton';
import { StatusDot } from '@/components/StatusDot';
import { Plus } from 'lucide-react';
import { toast } from 'sonner';
import type { UserRole } from '@/lib/types';

const roleBadge: Record<UserRole, string> = {
  root_admin: 'bg-red-500/20 text-red-400 border-red-500/30',
  admin: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  user: 'bg-muted text-muted-foreground border-border',
};

export default function UsersPage() {
  const { hasRole } = useAuth();
  const qc = useQueryClient();
  const [search, setSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState('all');
  const [createOpen, setCreateOpen] = useState(false);
  const [newUser, setNewUser] = useState({ username: '', password: '', role: 'user' as UserRole, max_connections: 10, bandwidth_limit_mb: 1000 });

  const { data, isLoading } = useQuery({ queryKey: ['users'], queryFn: () => api.getUsers() });
  const createMut = useMutation({
    mutationFn: () => api.createUser(newUser),
    onSuccess: () => { toast.success('User created'); setCreateOpen(false); qc.invalidateQueries({ queryKey: ['users'] }); },
    onError: (e: Error) => toast.error(e.message),
  });

  const users = (data?.items || []).filter(u => {
    if (roleFilter !== 'all' && u.role !== roleFilter) return false;
    if (search) return u.username.toLowerCase().includes(search.toLowerCase());
    return true;
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Users</h1>
        {hasRole('root_admin') && (
          <Button size="sm" onClick={() => setCreateOpen(true)}><Plus className="h-4 w-4 mr-1" /> Create User</Button>
        )}
      </div>

      <div className="flex gap-3 flex-wrap">
        <SearchInput onChange={setSearch} placeholder="Search by username..." className="w-64" />
        <Select value={roleFilter} onValueChange={setRoleFilter}>
          <SelectTrigger className="w-36 bg-secondary/50 border-border/50"><SelectValue placeholder="Role" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Roles</SelectItem>
            <SelectItem value="root_admin">Root Admin</SelectItem>
            <SelectItem value="admin">Admin</SelectItem>
            <SelectItem value="user">User</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {isLoading ? (
        <div className="space-y-2">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-12" />)}</div>
      ) : users.length === 0 ? (
        <EmptyState title="No users found" description="No users match your search criteria." icon="👥" />
      ) : (
        <div className="glass-card overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="border-border/50">
                <TableHead className="w-12">ID</TableHead>
                <TableHead>Username</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Max Conn.</TableHead>
                <TableHead className="text-right">BW Limit</TableHead>
                <TableHead className="text-right">Last Login</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {users.map(u => (
                <TableRow key={u.id} className="border-border/30">
                  <TableCell className="font-mono text-muted-foreground">{u.id}</TableCell>
                  <TableCell><Link to={`/users/${u.id}`} className="text-primary hover:underline font-medium">{u.username}</Link></TableCell>
                  <TableCell>
                    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${roleBadge[u.role]}`}>{u.role}</span>
                  </TableCell>
                  <TableCell>
                    <span className="inline-flex items-center gap-1.5">
                      <StatusDot color={u.is_active ? 'green' : 'red'} pulse={false} />
                      <span className="text-xs">{u.is_active ? 'Active' : 'Disabled'}</span>
                    </span>
                  </TableCell>
                  <TableCell className="text-right font-mono text-sm">{formatNumber(u.max_connections)}</TableCell>
                  <TableCell className="text-right font-mono text-sm">{u.bandwidth_limit_mb === 0 ? 'Unlimited' : `${formatNumber(u.bandwidth_limit_mb)} MB`}</TableCell>
                  <TableCell className="text-right text-xs text-muted-foreground">{u.last_login_at ? formatRelativeTime(u.last_login_at) : 'Never'}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {/* Create User Dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>Create User</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Username</Label>
              <Input value={newUser.username} onChange={e => setNewUser({ ...newUser, username: e.target.value })} placeholder="username" />
            </div>
            <div className="space-y-2">
              <Label>Password</Label>
              <Input type="password" value={newUser.password} onChange={e => setNewUser({ ...newUser, password: e.target.value })} placeholder="••••••••" />
            </div>
            <div className="space-y-2">
              <Label>Role</Label>
              <Select value={newUser.role} onValueChange={v => setNewUser({ ...newUser, role: v as UserRole })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="user">User</SelectItem>
                  <SelectItem value="admin">Admin</SelectItem>
                  <SelectItem value="root_admin">Root Admin</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Max Connections</Label>
                <Input type="number" value={newUser.max_connections} onChange={e => setNewUser({ ...newUser, max_connections: Number(e.target.value) })} />
              </div>
              <div className="space-y-2">
                <Label>Bandwidth Limit (MB)</Label>
                <Input type="number" value={newUser.bandwidth_limit_mb} onChange={e => setNewUser({ ...newUser, bandwidth_limit_mb: Number(e.target.value) })} />
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
            <Button onClick={() => createMut.mutate()} disabled={createMut.isPending}>
              {createMut.isPending ? 'Creating...' : 'Create User'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
