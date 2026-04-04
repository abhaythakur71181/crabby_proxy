import { cn } from '@/lib/utils';
import type { Protocol } from '@/lib/types';

const protocolStyles: Record<Protocol, string> = {
  HTTP: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  HTTPS: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
  SOCKS4: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  SOCKS5: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  HTTP2: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
};

export function ProtocolBadge({ protocol, className }: { protocol: Protocol; className?: string }) {
  return (
    <span className={cn(
      'inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium border',
      protocolStyles[protocol] || 'bg-muted text-muted-foreground',
      className,
    )}>
      {protocol}
    </span>
  );
}
