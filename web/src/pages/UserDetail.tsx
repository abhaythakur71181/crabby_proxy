import { useState } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { formatBytes, formatRelativeTime, formatDuration, formatNumber, truncateUuid } from '@/lib/format';
import { useAuth } from '@/contexts/AuthContext';
import { CircularGauge } from '@/components/CircularGauge';
import { CopyButton } from '@/components/CopyButton';
import { ProtocolBadge } from '@/components/ProtocolBadge';
import { StatusDot } from '@/components/StatusDot';
import { EmptyState } from '@/components/EmptyState';
import { StatCard } from '@/components/StatCard';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from '@/components/ui/table';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { toast } from 'sonner';
import { ArrowLeft, Trash2, Key, BarChart3, Shield, Users, Clock, CheckCircle, Activity, Wifi, Cable } from 'lucide-react';
import type { UserRole, Protocol } from '@/lib/types';

export default function UserDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { hasRole, user: authUser } = useAuth();
  const location = useLocation();
  // If no :id param (e.g. /api-keys route), use the logged-in user's own ID
  const userId = id ? Number(id) : (authUser?.id ?? 0);
  const defaultTab = location.pathname === '/api-keys' ? 'api-keys' : 'profile';
  const qc = useQueryClient();
  const isAdmin = hasRole('root_admin');

  const { data: user, isLoading } = useQuery({ queryKey: ['user', userId], queryFn: () => api.getUser(userId) });
  const { data: apiKeys } = useQuery({ queryKey: ['api-keys', userId], queryFn: () => api.getUserApiKeys(userId) });
  const { data: sessions } = useQuery({ queryKey: ['sessions', userId], queryFn: () => api.getUserSessions(userId) });
  const { data: userGroups } = useQuery({ queryKey: ['user-groups', userId], queryFn: () => api.getUserGroups(userId) });
  const { data: userApprovals } = useQuery({ queryKey: ['user-approvals', userId], queryFn: () => api.getUserApprovals(userId) });

  const [usagePeriod, setUsagePeriod] = useState('30');
  const { data: usage } = useQuery({ queryKey: ['usage', userId, usagePeriod], queryFn: () => usagePeriod === 'all' ? api.getUserAllTimeUsage(userId) : api.getUserUsage(userId, Number(usagePeriod)) });
  const { data: recentUsage } = useQuery({ queryKey: ['recent-usage', userId], queryFn: () => api.getUserRecentUsage(userId) });
  const { data: quota } = useQuery({ queryKey: ['quota', userId], queryFn: () => api.getUserQuota(userId) });

  // Dialogs
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [createKeyOpen, setCreateKeyOpen] = useState(false);
  const [keyRevealOpen, setKeyRevealOpen] = useState(false);
  const [revealedKey, setRevealedKey] = useState('');
  const [newKeyName, setNewKeyName] = useState('');
  const [newKeyExpiry, setNewKeyExpiry] = useState(0);
  const [editOpen, setEditOpen] = useState(false);
  const [editData, setEditData] = useState({ role: '' as UserRole, max_connections: 0, bandwidth_limit_mb: 0, is_active: true });

  const deleteMut = useMutation({
    mutationFn: () => api.deleteUser(userId),
    onSuccess: () => { toast.success('User deleted'); navigate('/users'); },
  });

  const updateMut = useMutation({
    mutationFn: () => api.updateUser(userId, editData),
    onSuccess: () => { toast.success('User updated'); setEditOpen(false); qc.invalidateQueries({ queryKey: ['user', userId] }); },
  });

  const createKeyMut = useMutation({
    mutationFn: () => api.createApiKey(userId, { name: newKeyName, expires_in_days: newKeyExpiry || undefined }),
    onSuccess: (res) => { setRevealedKey(res.key); setCreateKeyOpen(false); setKeyRevealOpen(true); qc.invalidateQueries({ queryKey: ['api-keys', userId] }); },
  });

  const revokeKeyMut = useMutation({
    mutationFn: (keyId: number) => api.revokeApiKey(userId, keyId),
    onSuccess: () => { toast.success('API key revoked'); qc.invalidateQueries({ queryKey: ['api-keys', userId] }); },
  });

  const forceLogoutMut = useMutation({
    mutationFn: () => api.forceLogoutUser(userId),
    onSuccess: () => { toast.success('All sessions terminated'); qc.invalidateQueries({ queryKey: ['sessions', userId] }); },
  });

  if (isLoading) return <div className="space-y-4"><Skeleton className="h-10 w-64" /><Skeleton className="h-64" /></div>;
  if (!user) return <EmptyState title="User not found" icon="❌" />;

  const roleBadge: Record<UserRole, string> = {
    root_admin: 'bg-red-500/20 text-red-400 border-red-500/30',
    admin: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    user: 'bg-muted text-muted-foreground border-border',
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" onClick={() => navigate('/users')}><ArrowLeft className="h-4 w-4" /></Button>
        <div className="flex-1">
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold">{user.username}</h1>
            <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${roleBadge[user.role]}`}>{user.role}</span>
            <StatusDot color={user.is_active ? 'green' : 'red'} />
          </div>
          <p className="text-sm text-muted-foreground">User ID: {user.id} · Created {formatRelativeTime(user.created_at)}</p>
        </div>
        {isAdmin && (
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => { setEditData({ role: user.role, max_connections: user.max_connections, bandwidth_limit_mb: user.bandwidth_limit_mb, is_active: user.is_active }); setEditOpen(true); }}>Edit</Button>
            {authUser?.id !== user.id && <Button variant="destructive" size="sm" onClick={() => setDeleteOpen(true)}><Trash2 className="h-4 w-4" /></Button>}
          </div>
        )}
      </div>

      <Tabs defaultValue={defaultTab}>
        <TabsList className="bg-secondary/50">
          <TabsTrigger value="profile">Profile</TabsTrigger>
          <TabsTrigger value="api-keys"><Key className="h-3.5 w-3.5 mr-1" />API Keys</TabsTrigger>
          <TabsTrigger value="usage"><BarChart3 className="h-3.5 w-3.5 mr-1" />Usage</TabsTrigger>
          <TabsTrigger value="quota"><Shield className="h-3.5 w-3.5 mr-1" />Quota</TabsTrigger>
          <TabsTrigger value="groups"><Users className="h-3.5 w-3.5 mr-1" />Groups</TabsTrigger>
          <TabsTrigger value="sessions"><Clock className="h-3.5 w-3.5 mr-1" />Sessions</TabsTrigger>
          <TabsTrigger value="approvals"><CheckCircle className="h-3.5 w-3.5 mr-1" />Approvals</TabsTrigger>
        </TabsList>

        {/* Profile Tab */}
        <TabsContent value="profile" className="glass-card p-5 mt-4">
          <div className="grid grid-cols-2 gap-6">
            <div><p className="text-xs text-muted-foreground">Username</p><p className="font-mono">{user.username}</p></div>
            <div><p className="text-xs text-muted-foreground">Role</p><p>{user.role}</p></div>
            <div><p className="text-xs text-muted-foreground">Status</p><p>{user.is_active ? 'Active' : 'Disabled'}</p></div>
            <div><p className="text-xs text-muted-foreground">Max Connections</p><p className="font-mono">{formatNumber(user.max_connections)}</p></div>
            <div><p className="text-xs text-muted-foreground">Bandwidth Limit</p><p className="font-mono">{user.bandwidth_limit_mb === 0 ? 'Unlimited' : `${formatNumber(user.bandwidth_limit_mb)} MB`}</p></div>
            <div><p className="text-xs text-muted-foreground">Last Login</p><p>{user.last_login_at ? formatRelativeTime(user.last_login_at) : 'Never'}</p></div>
          </div>
        </TabsContent>

        {/* API Keys Tab */}
        <TabsContent value="api-keys" className="mt-4 space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="font-semibold">API Keys</h3>
            <Button size="sm" onClick={() => setCreateKeyOpen(true)}><Key className="h-4 w-4 mr-1" /> Create Key</Button>
          </div>
          {!apiKeys?.length ? <EmptyState title="No API keys" description="Create an API key to authenticate programmatically." icon="🔑" /> : (
            <div className="glass-card overflow-hidden">
              <Table>
                <TableHeader><TableRow className="border-border/50">
                  <TableHead>Prefix</TableHead><TableHead>Name</TableHead><TableHead>Created</TableHead><TableHead>Last Used</TableHead><TableHead>Expires</TableHead><TableHead>Status</TableHead><TableHead></TableHead>
                </TableRow></TableHeader>
                <TableBody>
                  {apiKeys.map(k => (
                    <TableRow key={k.id} className="border-border/30">
                      <TableCell className="font-mono text-xs">{k.prefix}…</TableCell>
                      <TableCell className="text-sm">{k.name || '—'}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatRelativeTime(k.created_at)}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{k.last_used_at ? formatRelativeTime(k.last_used_at) : 'Never'}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{k.expires_at ? formatRelativeTime(k.expires_at) : 'Never'}</TableCell>
                      <TableCell><Badge variant={k.is_active ? 'default' : 'secondary'} className="text-xs">{k.is_active ? 'Active' : 'Revoked'}</Badge></TableCell>
                      <TableCell>{k.is_active && <Button variant="ghost" size="sm" className="text-destructive text-xs" onClick={() => revokeKeyMut.mutate(k.id)}>Revoke</Button>}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </TabsContent>

        {/* Usage Tab */}
        <TabsContent value="usage" className="mt-4 space-y-4">
          <div className="flex items-center gap-3">
            <h3 className="font-semibold">Usage Statistics</h3>
            <Select value={usagePeriod} onValueChange={setUsagePeriod}>
              <SelectTrigger className="w-32 bg-secondary/50 border-border/50"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="1">1 Day</SelectItem>
                <SelectItem value="7">7 Days</SelectItem>
                <SelectItem value="30">30 Days</SelectItem>
                <SelectItem value="90">90 Days</SelectItem>
                <SelectItem value="all">All Time</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {usage && (
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              <StatCard label="Connections" value={formatNumber(usage.connection_count)} icon={<Cable className="h-5 w-5" />} color="cyan" />
              <StatCard label="Sent" value={formatBytes(usage.bytes_sent)} icon={<Activity className="h-5 w-5" />} color="blue" />
              <StatCard label="Received" value={formatBytes(usage.bytes_received)} icon={<Wifi className="h-5 w-5" />} color="teal" />
              <StatCard label="Total Bandwidth" value={formatBytes(usage.total_bandwidth)} icon={<BarChart3 className="h-5 w-5" />} color="purple" />
            </div>
          )}
          {recentUsage && recentUsage.length > 0 && (
            <div className="glass-card overflow-hidden">
              <Table>
                <TableHeader><TableRow className="border-border/50">
                  <TableHead>Connection</TableHead><TableHead>Client IP</TableHead><TableHead>Target</TableHead><TableHead>Protocol</TableHead><TableHead>Duration</TableHead><TableHead className="text-right">Sent</TableHead><TableHead className="text-right">Recv</TableHead><TableHead>Status</TableHead>
                </TableRow></TableHeader>
                <TableBody>
                  {recentUsage.map(r => (
                    <TableRow key={r.connection_id} className="border-border/30">
                      <TableCell className="font-mono text-xs">{truncateUuid(r.connection_id)}</TableCell>
                      <TableCell className="font-mono text-xs">{r.client_ip}</TableCell>
                      <TableCell className="font-mono text-xs">{r.target_host}</TableCell>
                      <TableCell><ProtocolBadge protocol={r.protocol as Protocol} /></TableCell>
                      <TableCell className="text-xs">{formatDuration(r.duration_seconds)}</TableCell>
                      <TableCell className="text-right font-mono text-xs">{formatBytes(r.bytes_sent)}</TableCell>
                      <TableCell className="text-right font-mono text-xs">{formatBytes(r.bytes_received)}</TableCell>
                      <TableCell>
                        <Badge variant={r.status === 'success' ? 'default' : 'destructive'} className="text-xs">{r.status}</Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </TabsContent>

        {/* Quota Tab */}
        <TabsContent value="quota" className="mt-4">
          {quota && (
            <div className="glass-card p-6 flex flex-col items-center gap-4">
              <div className="relative">
                <CircularGauge percentage={quota.percentage_used} size={160} strokeWidth={12} />
              </div>
              <div className="text-center space-y-1">
                <p className="text-lg font-bold">{quota.quota_bytes ? formatBytes(quota.used_bytes) + ' / ' + formatBytes(quota.quota_bytes) : 'Unlimited'}</p>
                {quota.remaining_bytes !== null && <p className="text-sm text-muted-foreground">{formatBytes(quota.remaining_bytes)} remaining</p>}
              </div>
            </div>
          )}
        </TabsContent>

        {/* Groups Tab */}
        <TabsContent value="groups" className="mt-4">
          {!userGroups?.length ? <EmptyState title="Not in any groups" icon="📦" /> : (
            <div className="glass-card overflow-hidden">
              <Table>
                <TableHeader><TableRow className="border-border/50"><TableHead>Group</TableHead></TableRow></TableHeader>
                <TableBody>
                  {userGroups.map(g => (
                    <TableRow key={g.id} className="border-border/30">
                      <TableCell><a href={`/groups/${g.id}`} className="text-primary hover:underline">{g.name}</a></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </TabsContent>

        {/* Sessions Tab */}
        <TabsContent value="sessions" className="mt-4 space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="font-semibold">Active Sessions</h3>
            {isAdmin && <Button variant="destructive" size="sm" onClick={() => forceLogoutMut.mutate()}>Force Logout All</Button>}
          </div>
          {!sessions?.length ? <EmptyState title="No active sessions" icon="🔒" /> : (
            <div className="glass-card overflow-hidden">
              <Table>
                <TableHeader><TableRow className="border-border/50">
                  <TableHead>Session ID</TableHead><TableHead>Created</TableHead><TableHead>Expires</TableHead><TableHead>IP</TableHead><TableHead>User Agent</TableHead>
                </TableRow></TableHeader>
                <TableBody>
                  {sessions.map(s => (
                    <TableRow key={s.id} className="border-border/30">
                      <TableCell className="font-mono text-xs">{s.id}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatRelativeTime(s.created_at)}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatRelativeTime(s.expires_at)}</TableCell>
                      <TableCell className="font-mono text-xs">{s.ip_address}</TableCell>
                      <TableCell className="text-xs text-muted-foreground max-w-[200px] truncate">{s.user_agent}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </TabsContent>

        {/* Approvals Tab */}
        <TabsContent value="approvals" className="mt-4">
          {!userApprovals?.length ? <EmptyState title="No approvals" icon="✅" /> : (
            <div className="glass-card overflow-hidden">
              <Table>
                <TableHeader><TableRow className="border-border/50">
                  <TableHead>Client IP</TableHead><TableHead>Duration</TableHead><TableHead>Expires</TableHead><TableHead>Reason</TableHead>
                </TableRow></TableHeader>
                <TableBody>
                  {userApprovals.map(a => (
                    <TableRow key={a.id} className="border-border/30">
                      <TableCell className="font-mono text-xs">{a.client_ip}</TableCell>
                      <TableCell className="text-xs">{a.duration_hours}h</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatRelativeTime(a.expires_at)}</TableCell>
                      <TableCell className="text-xs">{a.reason}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </TabsContent>
      </Tabs>

      {/* Delete Dialog */}
      <Dialog open={deleteOpen} onOpenChange={setDeleteOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>Delete User</DialogTitle><DialogDescription>Are you sure you want to delete <strong>{user.username}</strong>? This cannot be undone.</DialogDescription></DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteOpen(false)}>Cancel</Button>
            <Button variant="destructive" onClick={() => deleteMut.mutate()} disabled={deleteMut.isPending}>Delete</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit Dialog */}
      <Dialog open={editOpen} onOpenChange={setEditOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>Edit User</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Role</Label>
              <Select value={editData.role} onValueChange={v => setEditData({ ...editData, role: v as UserRole })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="user">User</SelectItem><SelectItem value="admin">Admin</SelectItem><SelectItem value="root_admin">Root Admin</SelectItem></SelectContent>
              </Select>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2"><Label>Max Connections</Label><Input type="number" value={editData.max_connections} onChange={e => setEditData({ ...editData, max_connections: Number(e.target.value) })} /></div>
              <div className="space-y-2"><Label>Bandwidth Limit (MB)</Label><Input type="number" value={editData.bandwidth_limit_mb} onChange={e => setEditData({ ...editData, bandwidth_limit_mb: Number(e.target.value) })} /></div>
            </div>
          </div>
          <DialogFooter><Button variant="outline" onClick={() => setEditOpen(false)}>Cancel</Button><Button onClick={() => updateMut.mutate()} disabled={updateMut.isPending}>Save</Button></DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Create API Key Dialog */}
      <Dialog open={createKeyOpen} onOpenChange={setCreateKeyOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>Create API Key</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2"><Label>Name (optional)</Label><Input value={newKeyName} onChange={e => setNewKeyName(e.target.value)} placeholder="My Key" /></div>
            <div className="space-y-2"><Label>Expires in (days, 0 = never)</Label><Input type="number" value={newKeyExpiry} onChange={e => setNewKeyExpiry(Number(e.target.value))} /></div>
          </div>
          <DialogFooter><Button variant="outline" onClick={() => setCreateKeyOpen(false)}>Cancel</Button><Button onClick={() => createKeyMut.mutate()} disabled={createKeyMut.isPending}>Create</Button></DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Key Reveal Dialog */}
      <Dialog open={keyRevealOpen} onOpenChange={setKeyRevealOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>🔑 API Key Created</DialogTitle></DialogHeader>
          <div className="space-y-3">
            <div className="p-3 rounded-lg bg-amber/10 border border-amber/30 text-sm text-amber">
              ⚠️ Copy this key now. You won't be able to see it again.
            </div>
            <div className="flex items-center gap-2 p-3 rounded bg-secondary font-mono text-sm break-all">
              {revealedKey}
              <CopyButton text={revealedKey} />
            </div>
          </div>
          <DialogFooter><Button onClick={() => setKeyRevealOpen(false)}>Done</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
