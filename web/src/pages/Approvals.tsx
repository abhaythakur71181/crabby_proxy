import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { formatRelativeTime } from '@/lib/format';
import { useAuth } from '@/contexts/AuthContext';
import { EmptyState } from '@/components/EmptyState';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from '@/components/ui/table';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription } from '@/components/ui/dialog';
import { Plus, Check, X } from 'lucide-react';
import { toast } from 'sonner';

const statusBadge: Record<string, string> = {
  pending: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
  approved: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
  rejected: 'bg-red-500/20 text-red-400 border-red-500/30',
};

export default function Approvals() {
  const { hasRole, user: authUser } = useAuth();
  const isAdmin = hasRole('admin', 'root_admin');
  const qc = useQueryClient();

  // ── Request form state ──
  const [requestOpen, setRequestOpen] = useState(false);
  const [clientIp, setClientIp] = useState('');
  const [durationHours, setDurationHours] = useState('24');
  const [reason, setReason] = useState('');

  // ── Admin: approve/reject dialog ──
  const [decisionId, setDecisionId] = useState<number | null>(null);
  const [decisionAction, setDecisionAction] = useState<'approve' | 'reject'>('approve');
  const [decisionReason, setDecisionReason] = useState('');

  // ── Admin: direct approval dialog ──
  const [createOpen, setCreateOpen] = useState(false);
  const [newApproval, setNewApproval] = useState({ user_id: '', client_ip: '', duration_hours: '24', reason: '' });

  // ── Admin: terminate dialog ──
  const [terminateId, setTerminateId] = useState<number | null>(null);
  const [terminateReason, setTerminateReason] = useState('');

  // ── Queries ──
  const { data: requests } = useQuery({
    queryKey: ['approval-requests'],
    queryFn: () => api.getApprovalRequests(),
  });
  const { data: approvals } = useQuery({
    queryKey: ['approvals'],
    queryFn: api.getApprovals,
    enabled: isAdmin,
  });
  const { data: usersData } = useQuery({
    queryKey: ['users'],
    queryFn: () => api.getUsers(),
    enabled: createOpen && isAdmin,
  });

  // Auto-detect client IP on mount
  useEffect(() => {
    fetch('https://api.ipify.org?format=json')
      .then(r => r.json())
      .then(d => setClientIp(d.ip))
      .catch(() => {});
  }, []);

  // ── Mutations ──
  const requestMut = useMutation({
    mutationFn: () => api.createApprovalRequest({
      client_ip: clientIp,
      duration_hours: Number(durationHours),
      reason: reason || undefined,
    }),
    onSuccess: () => {
      toast.success('Approval request submitted');
      setRequestOpen(false);
      setReason('');
      qc.invalidateQueries({ queryKey: ['approval-requests'] });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const decideMut = useMutation({
    mutationFn: () =>
      decisionAction === 'approve'
        ? api.approveRequest(decisionId!, decisionReason || undefined)
        : api.rejectRequest(decisionId!, decisionReason || undefined),
    onSuccess: () => {
      toast.success(decisionAction === 'approve' ? 'Request approved' : 'Request rejected');
      setDecisionId(null);
      setDecisionReason('');
      qc.invalidateQueries({ queryKey: ['approval-requests'] });
      qc.invalidateQueries({ queryKey: ['approvals'] });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const createMut = useMutation({
    mutationFn: () => api.createApproval({
      user_id: Number(newApproval.user_id),
      client_ip: newApproval.client_ip,
      duration_hours: Number(newApproval.duration_hours),
      reason: newApproval.reason || undefined,
    }),
    onSuccess: () => {
      toast.success('Approval created');
      setCreateOpen(false);
      setNewApproval({ user_id: '', client_ip: '', duration_hours: '24', reason: '' });
      qc.invalidateQueries({ queryKey: ['approvals'] });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const terminateMut = useMutation({
    mutationFn: () => api.terminateApproval(terminateId!, terminateReason),
    onSuccess: () => {
      toast.success('Approval terminated');
      setTerminateId(null);
      setTerminateReason('');
      qc.invalidateQueries({ queryKey: ['approvals'] });
    },
  });

  const pendingRequests = (requests || []).filter(r => r.status === 'pending');
  const decidedRequests = (requests || []).filter(r => r.status !== 'pending');

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Approvals</h1>
        <div className="flex gap-2">
          {!isAdmin && (
            <Button size="sm" onClick={() => setRequestOpen(true)}>
              <Plus className="h-4 w-4 mr-1" /> Request Approval
            </Button>
          )}
          {isAdmin && (
            <Button size="sm" onClick={() => setCreateOpen(true)}>
              <Plus className="h-4 w-4 mr-1" /> Create Approval
            </Button>
          )}
        </div>
      </div>

      {isAdmin ? (
        <Tabs defaultValue="all">
          <TabsList className="bg-secondary/50">
            <TabsTrigger value="all">All Requests</TabsTrigger>
            <TabsTrigger value="pending">
              Pending {pendingRequests.length > 0 && <Badge variant="destructive" className="ml-1.5 h-5 px-1.5 text-[10px]">{pendingRequests.length}</Badge>}
            </TabsTrigger>
            <TabsTrigger value="history">History</TabsTrigger>
            <TabsTrigger value="active">Active Approvals</TabsTrigger>
          </TabsList>

          {/* All Requests */}
          <TabsContent value="all" className="mt-4">
            {!(requests || []).length ? (
              <EmptyState title="No requests" description="No approval requests have been submitted yet." icon="📋" />
            ) : (
              <div className="glass-card overflow-hidden">
                <Table>
                  <TableHeader><TableRow className="border-border/50">
                    <TableHead>ID</TableHead><TableHead>User</TableHead><TableHead>Client IP</TableHead><TableHead>Duration</TableHead><TableHead>Status</TableHead><TableHead>Reason</TableHead><TableHead>Requested</TableHead><TableHead></TableHead>
                  </TableRow></TableHeader>
                  <TableBody>
                    {(requests || []).map(r => (
                      <TableRow key={r.id} className="border-border/30">
                        <TableCell className="font-mono text-muted-foreground">{r.id}</TableCell>
                        <TableCell className="text-primary text-sm">{r.username || `User #${r.user_id}`}</TableCell>
                        <TableCell className="font-mono text-xs">{r.client_ip}</TableCell>
                        <TableCell className="text-xs">{r.duration_hours}h</TableCell>
                        <TableCell>
                          <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${statusBadge[r.status]}`}>{r.status}</span>
                        </TableCell>
                        <TableCell className="text-xs max-w-[200px] truncate">{r.reason || '—'}</TableCell>
                        <TableCell className="text-xs text-muted-foreground">{formatRelativeTime(r.requested_at)}</TableCell>
                        <TableCell>
                          {r.status === 'pending' && (
                            <div className="flex gap-1">
                              <Button variant="ghost" size="icon" className="h-7 w-7 text-emerald-400" onClick={() => { setDecisionId(r.id); setDecisionAction('approve'); }}>
                                <Check className="h-4 w-4" />
                              </Button>
                              <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive" onClick={() => { setDecisionId(r.id); setDecisionAction('reject'); }}>
                                <X className="h-4 w-4" />
                              </Button>
                            </div>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </TabsContent>

          {/* Pending Requests */}
          <TabsContent value="pending" className="mt-4">
            {!pendingRequests.length ? (
              <EmptyState title="No pending requests" description="All approval requests have been processed." icon="✅" />
            ) : (
              <div className="glass-card overflow-hidden">
                <Table>
                  <TableHeader><TableRow className="border-border/50">
                    <TableHead>ID</TableHead><TableHead>User</TableHead><TableHead>Client IP</TableHead><TableHead>Duration</TableHead><TableHead>Reason</TableHead><TableHead>Requested</TableHead><TableHead></TableHead>
                  </TableRow></TableHeader>
                  <TableBody>
                    {pendingRequests.map(r => (
                      <TableRow key={r.id} className="border-border/30">
                        <TableCell className="font-mono text-muted-foreground">{r.id}</TableCell>
                        <TableCell className="text-primary text-sm">{r.username || `User #${r.user_id}`}</TableCell>
                        <TableCell className="font-mono text-xs">{r.client_ip}</TableCell>
                        <TableCell className="text-xs">{r.duration_hours}h</TableCell>
                        <TableCell className="text-xs max-w-[200px] truncate">{r.reason || '—'}</TableCell>
                        <TableCell className="text-xs text-muted-foreground">{formatRelativeTime(r.requested_at)}</TableCell>
                        <TableCell>
                          <div className="flex gap-1">
                            <Button variant="ghost" size="icon" className="h-7 w-7 text-emerald-400" onClick={() => { setDecisionId(r.id); setDecisionAction('approve'); }}>
                              <Check className="h-4 w-4" />
                            </Button>
                            <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive" onClick={() => { setDecisionId(r.id); setDecisionAction('reject'); }}>
                              <X className="h-4 w-4" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </TabsContent>

          {/* Request History */}
          <TabsContent value="history" className="mt-4">
            {!decidedRequests.length ? (
              <EmptyState title="No history" icon="📋" />
            ) : (
              <div className="glass-card overflow-hidden">
                <Table>
                  <TableHeader><TableRow className="border-border/50">
                    <TableHead>ID</TableHead><TableHead>User</TableHead><TableHead>Client IP</TableHead><TableHead>Duration</TableHead><TableHead>Status</TableHead><TableHead>Requested</TableHead><TableHead>Decided</TableHead>
                  </TableRow></TableHeader>
                  <TableBody>
                    {decidedRequests.map(r => (
                      <TableRow key={r.id} className="border-border/30">
                        <TableCell className="font-mono text-muted-foreground">{r.id}</TableCell>
                        <TableCell className="text-primary text-sm">{r.username || `User #${r.user_id}`}</TableCell>
                        <TableCell className="font-mono text-xs">{r.client_ip}</TableCell>
                        <TableCell className="text-xs">{r.duration_hours}h</TableCell>
                        <TableCell>
                          <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${statusBadge[r.status]}`}>{r.status}</span>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">{formatRelativeTime(r.requested_at)}</TableCell>
                        <TableCell className="text-xs text-muted-foreground">{r.decided_at ? formatRelativeTime(r.decided_at) : '—'}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </TabsContent>

          {/* Active Approvals */}
          <TabsContent value="active" className="mt-4">
            {!approvals?.length ? (
              <EmptyState title="No active approvals" icon="✅" />
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
                        <TableCell className="text-primary text-sm">{a.username || `User #${a.user_id}`}</TableCell>
                        <TableCell className="font-mono text-xs">{a.client_ip}</TableCell>
                        <TableCell className="text-xs">{a.duration_hours}h</TableCell>
                        <TableCell className="text-xs text-muted-foreground">{formatRelativeTime(a.expires_at)}</TableCell>
                        <TableCell className="text-xs max-w-[200px] truncate">{a.reason || '—'}</TableCell>
                        <TableCell><Button variant="ghost" size="sm" className="text-destructive text-xs" onClick={() => setTerminateId(a.id)}>Terminate</Button></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </TabsContent>
        </Tabs>
      ) : (
        /* Regular user view: their own requests */
        <div className="space-y-4">
          <h2 className="font-semibold">My Approval Requests</h2>
          {!requests?.length ? (
            <EmptyState title="No requests" description="Request approval to connect through the proxy." icon="🔒" action={{ label: 'Request Approval', onClick: () => setRequestOpen(true) }} />
          ) : (
            <div className="glass-card overflow-hidden">
              <Table>
                <TableHeader><TableRow className="border-border/50">
                  <TableHead>ID</TableHead><TableHead>Client IP</TableHead><TableHead>Duration</TableHead><TableHead>Status</TableHead><TableHead>Requested</TableHead><TableHead>Decision</TableHead>
                </TableRow></TableHeader>
                <TableBody>
                  {requests.map(r => (
                    <TableRow key={r.id} className="border-border/30">
                      <TableCell className="font-mono text-muted-foreground">{r.id}</TableCell>
                      <TableCell className="font-mono text-xs">{r.client_ip}</TableCell>
                      <TableCell className="text-xs">{r.duration_hours}h</TableCell>
                      <TableCell>
                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${statusBadge[r.status]}`}>{r.status}</span>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatRelativeTime(r.requested_at)}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{r.decision_reason || '—'}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </div>
      )}

      {/* Request Approval Dialog (user) */}
      <Dialog open={requestOpen} onOpenChange={setRequestOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>Request Approval</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Client IP</Label>
              <Input value={clientIp} onChange={e => setClientIp(e.target.value)} placeholder="Auto-detected..." />
              <p className="text-xs text-muted-foreground">Your detected public IP is pre-filled.</p>
            </div>
            <div className="space-y-2">
              <Label>Duration (hours)</Label>
              <Input type="number" value={durationHours} onChange={e => setDurationHours(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label>Reason</Label>
              <Textarea value={reason} onChange={e => setReason(e.target.value)} placeholder="Why do you need proxy access?" />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRequestOpen(false)}>Cancel</Button>
            <Button onClick={() => requestMut.mutate()} disabled={requestMut.isPending || !clientIp}>
              {requestMut.isPending ? 'Submitting...' : 'Submit Request'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Approve/Reject Dialog (admin) */}
      <Dialog open={decisionId !== null} onOpenChange={() => setDecisionId(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{decisionAction === 'approve' ? 'Approve' : 'Reject'} Request</DialogTitle>
            <DialogDescription>
              {decisionAction === 'approve'
                ? 'This will create an active approval and allow the user to connect.'
                : 'The user will be notified their request was rejected.'}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label>Reason (optional)</Label>
            <Textarea value={decisionReason} onChange={e => setDecisionReason(e.target.value)} placeholder={decisionAction === 'approve' ? 'Approved because...' : 'Rejected because...'} />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDecisionId(null)}>Cancel</Button>
            <Button
              variant={decisionAction === 'approve' ? 'default' : 'destructive'}
              onClick={() => decideMut.mutate()}
              disabled={decideMut.isPending}
            >
              {decisionAction === 'approve' ? 'Approve' : 'Reject'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Create Approval Dialog (admin direct) */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>Create Approval</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>User</Label>
              <Select value={newApproval.user_id} onValueChange={v => setNewApproval({ ...newApproval, user_id: v })}>
                <SelectTrigger><SelectValue placeholder="Select a user" /></SelectTrigger>
                <SelectContent>
                  {(usersData?.items || []).map((u: any) => (
                    <SelectItem key={u.id} value={String(u.id)}>
                      {u.username} (ID: {u.id})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2"><Label>Client IP</Label><Input value={newApproval.client_ip} onChange={e => setNewApproval({ ...newApproval, client_ip: e.target.value })} placeholder="203.0.113.50" /></div>
            <div className="space-y-2"><Label>Duration (hours)</Label><Input type="number" value={newApproval.duration_hours} onChange={e => setNewApproval({ ...newApproval, duration_hours: e.target.value })} /></div>
            <div className="space-y-2"><Label>Reason</Label><Textarea value={newApproval.reason} onChange={e => setNewApproval({ ...newApproval, reason: e.target.value })} /></div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
            <Button onClick={() => createMut.mutate()} disabled={createMut.isPending || !newApproval.user_id}>Create</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Terminate Dialog (admin) */}
      <Dialog open={terminateId !== null} onOpenChange={() => setTerminateId(null)}>
        <DialogContent>
          <DialogHeader><DialogTitle>Terminate Approval</DialogTitle><DialogDescription>Please provide a reason for termination.</DialogDescription></DialogHeader>
          <div className="space-y-2"><Label>Reason</Label><Textarea value={terminateReason} onChange={e => setTerminateReason(e.target.value)} placeholder="Reason for termination..." /></div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setTerminateId(null)}>Cancel</Button>
            <Button variant="destructive" onClick={() => terminateMut.mutate()} disabled={terminateMut.isPending || !terminateReason}>Terminate</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
