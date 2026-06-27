import { cn } from "@/lib/utils";

export function PageHeader({
  title,
  subtitle,
  action,
  className,
}: {
  title: string;
  subtitle?: string;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <header className={cn("mb-8 flex items-end justify-between gap-6", className)}>
      <div className="min-w-0">
        <h1 className="text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">{title}</h1>
        {subtitle && <p className="mt-1.5 max-w-2xl text-sm text-muted-foreground">{subtitle}</p>}
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </header>
  );
}