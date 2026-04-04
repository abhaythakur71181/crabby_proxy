import { useQuery, useMutation } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { formatNumber } from '@/lib/format';
import { StatusDot } from '@/components/StatusDot';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription } from '@/components/ui/dialog';
import { useAuth } from '@/contexts/AuthContext';
import { toast } from 'sonner';
import { useState } from 'react';
import { RefreshCw } from 'lucide-react';

export default function Configuration() {
  const { hasRole } = useAuth();
  const [reloadOpen, setReloadOpen] = useState(false);
  const { data: config, isLoading } = useQuery({ queryKey: ['config'], queryFn: api.getConfig });

  const reloadMut = useMutation({
    mutationFn: api.reloadConfig,
    onSuccess: (res) => { toast.success(res.message); setReloadOpen(false); },
    onError: () => toast.error('Failed to reload configuration'),
  });

  if (isLoading || !config) return null;

  const Section = ({ title, children }: { title: string; children: React.ReactNode }) => (
    <div className="glass-card p-5 space-y-3">
      <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">{title}</h2>
      {children}
    </div>
  );

  const Row = ({ label, value }: { label: string; value: React.ReactNode }) => (
    <div className="flex items-center justify-between py-2 border-b border-border/30 last:border-0">
      <span className="text-sm text-muted-foreground">{label}</span>
      <span className="text-sm font-mono">{value}</span>
    </div>
  );

  const Toggle = ({ enabled }: { enabled: boolean }) => (
    <span className="inline-flex items-center gap-1.5"><StatusDot color={enabled ? 'green' : 'red'} pulse={false} /><span className="text-sm">{enabled ? 'Enabled' : 'Disabled'}</span></span>
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Configuration</h1>
        {hasRole('root_admin', 'admin') && (
          <Button size="sm" variant="outline" onClick={() => setReloadOpen(true)}><RefreshCw className="h-4 w-4 mr-1" /> Reload Config</Button>
        )}
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Section title="Server">
          <Row label="Proxy Bind" value={config.server.proxy_bind} />
          <Row label="Admin Bind" value={config.server.admin_bind} />
          <Row label="Max Connections" value={formatNumber(config.server.max_connections)} />
        </Section>
        <Section title="Authentication">
          <Row label="Enabled" value={<Toggle enabled={config.authentication.enabled} />} />
        </Section>
        <Section title="Features">
          <Row label="Connection Approval" value={<Toggle enabled={config.features.connection_approval} />} />
          <Row label="Reverse Tunnels" value={<Toggle enabled={config.features.reverse_tunnels} />} />
        </Section>
      </div>

      <Dialog open={reloadOpen} onOpenChange={setReloadOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>Reload Configuration</DialogTitle><DialogDescription>This will reload the configuration from disk. Current in-memory state will be updated.</DialogDescription></DialogHeader>
          <DialogFooter><Button variant="outline" onClick={() => setReloadOpen(false)}>Cancel</Button><Button onClick={() => reloadMut.mutate()} disabled={reloadMut.isPending}>Reload</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
