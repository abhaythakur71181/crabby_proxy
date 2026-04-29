import { cn } from '@/lib/utils';

type StatusColor = 'green' | 'yellow' | 'red';

const colorMap: Record<StatusColor, string> = {
  green: 'bg-emerald-500',
  yellow: 'bg-amber-400',
  red: 'bg-red-500',
};

const glowColorMap: Record<StatusColor, string> = {
  green: 'bg-emerald-500/40',
  yellow: 'bg-amber-400/40',
  red: 'bg-red-500/40',
};

export function StatusDot({ color = 'green', pulse = true, className }: { color?: StatusColor; pulse?: boolean; className?: string }) {
  return (
    <span className={cn('relative inline-flex h-2.5 w-2.5', className)}>
      {pulse && (
        <span className={cn(
          'absolute inline-flex h-full w-full rounded-full opacity-75 animate-ping',
          glowColorMap[color],
        )} />
      )}
      <span className={cn('relative inline-flex h-2.5 w-2.5 rounded-full', colorMap[color])} />
    </span>
  );
}
