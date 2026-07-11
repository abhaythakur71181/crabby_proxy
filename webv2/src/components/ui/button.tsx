import { forwardRef, type ButtonHTMLAttributes } from "react";
import { Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

type Variant = "primary" | "secondary" | "ghost" | "danger" | "outline";
type Size = "sm" | "md" | "lg" | "icon";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
}

const variants: Record<Variant, string> = {
  primary:
    "bg-accent text-bg font-semibold hover:bg-accent-strong shadow-[0_1px_2px_rgb(0_0_0/0.2),inset_0_1px_0_rgb(255_255_255/0.12)] active:scale-[0.98]",
  secondary:
    "bg-surface-3 text-fg hover:bg-surface-3/70 border border-line-strong active:scale-[0.98]",
  outline: "border border-line-strong text-fg hover:bg-surface-2 active:scale-[0.98]",
  ghost: "text-fg-muted hover:text-fg hover:bg-surface-2 active:scale-[0.98]",
  danger:
    "bg-danger-soft text-danger border border-danger/25 hover:bg-danger/20 active:scale-[0.98]",
};

const sizes: Record<Size, string> = {
  sm: "h-7 px-2.5 text-[12.5px] gap-1.5 rounded-md",
  md: "h-8.5 px-3.5 text-[13px] gap-2 rounded-md",
  lg: "h-10 px-5 text-sm gap-2 rounded-lg",
  icon: "h-8.5 w-8.5 rounded-md",
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "secondary", size = "md", loading, disabled, children, ...props }, ref) => (
    <button
      ref={ref}
      disabled={disabled || loading}
      className={cn(
        "inline-flex items-center justify-center whitespace-nowrap font-medium transition-all duration-150",
        "disabled:pointer-events-none disabled:opacity-50 select-none cursor-pointer",
        variants[variant],
        sizes[size],
        className,
      )}
      {...props}
    >
      {loading && <Loader2 className="size-3.5 animate-spin" aria-hidden />}
      {children}
    </button>
  ),
);
Button.displayName = "Button";
