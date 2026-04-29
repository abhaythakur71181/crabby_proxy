import { useEffect, useState, type ReactNode } from 'react';
import { cn } from '@/lib/utils';

interface StatCardProps {
  label: string;
  value: string | number;
  icon: ReactNode;
  color?: 'cyan' | 'green' | 'blue' | 'teal' | 'purple' | 'amber';
  className?: string;
}

const colorMap = {
  cyan: 'text-cyan',
  green: 'text-success',
  blue: 'text-primary',
  teal: 'text-cyan-light',
  purple: 'text-purple-400',
  amber: 'text-amber',
};

const glowMap = {
  cyan: 'shadow-cyan/10',
  green: 'shadow-success/10',
  blue: 'shadow-primary/10',
  teal: 'shadow-cyan-light/10',
  purple: 'shadow-purple-400/10',
  amber: 'shadow-amber/10',
};

export function StatCard({ label, value, icon, color = 'cyan', className }: StatCardProps) {
  const [show, setShow] = useState(false);
  useEffect(() => { const t = setTimeout(() => setShow(true), 100); return () => clearTimeout(t); }, []);

  return (
    <div className={cn(
      'glass-card-hover p-5 flex flex-col gap-3 shadow-lg',
      glowMap[color],
      className
    )}>
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium text-muted-foreground">{label}</span>
        <span className={cn('opacity-70', colorMap[color])}>{icon}</span>
      </div>
      <div className={cn(
        'text-2xl font-bold tracking-tight transition-all duration-500',
        colorMap[color],
        show ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-2'
      )}>
        {value}
      </div>
    </div>
  );
}
