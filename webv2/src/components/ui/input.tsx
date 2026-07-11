import { forwardRef, useId, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from "react";
import { ChevronDown } from "lucide-react";
import { cn } from "@/lib/utils";

const base =
  "w-full rounded-md border border-line-strong bg-surface-1 px-3 text-[13px] text-fg " +
  "placeholder:text-fg-faint transition-colors duration-150 " +
  "hover:border-line-strong focus:border-accent/60 focus:outline-none focus:ring-2 focus:ring-ring/40 " +
  "disabled:opacity-50 disabled:pointer-events-none";

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input ref={ref} className={cn(base, "h-8.5", className)} {...props} />
  ),
);
Input.displayName = "Input";

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(
  ({ className, ...props }, ref) => (
    <textarea ref={ref} className={cn(base, "min-h-20 py-2 resize-y", className)} {...props} />
  ),
);
Textarea.displayName = "Textarea";

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(
  ({ className, children, ...props }, ref) => (
    <div className="relative">
      <select ref={ref} className={cn(base, "h-8.5 appearance-none pr-8 cursor-pointer", className)} {...props}>
        {children}
      </select>
      <ChevronDown
        className="pointer-events-none absolute right-2.5 top-1/2 size-3.5 -translate-y-1/2 text-fg-faint"
        aria-hidden
      />
    </div>
  ),
);
Select.displayName = "Select";

/** Labeled field with proper htmlFor/id wiring + optional hint/error. */
export function Field({
  label,
  hint,
  error,
  children,
  htmlFor,
}: {
  label: string;
  hint?: string;
  error?: string | null;
  children: ReactNode | ((id: string) => ReactNode);
  htmlFor?: string;
}) {
  const gen = useId();
  const id = htmlFor ?? gen;
  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className="block text-[12.5px] font-medium text-fg-muted">
        {label}
      </label>
      {typeof children === "function" ? children(id) : children}
      {error ? (
        <p className="text-[12px] text-danger">{error}</p>
      ) : hint ? (
        <p className="text-[12px] text-fg-faint">{hint}</p>
      ) : null}
    </div>
  );
}
