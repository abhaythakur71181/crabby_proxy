import { cn } from "@/lib/utils";
import type { HTMLAttributes } from "react";

export function Mono({ className, ...props }: HTMLAttributes<HTMLSpanElement>) {
  return <span className={cn("font-mono-tight tabular-nums", className)} {...props} />;
}

export function Kbd({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <kbd
      className={cn(
        "inline-flex h-5 min-w-5 items-center justify-center rounded-[5px] border border-white/10 bg-white/[0.04] px-1.5 font-mono-tight text-[10px] text-foreground/70 shadow-[inset_0_-1px_0_rgba(255,255,255,0.04)]",
        className,
      )}
    >
      {children}
    </kbd>
  );
}