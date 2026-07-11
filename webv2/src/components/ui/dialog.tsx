// Radix Dialog wrappers with motion — focus trap, Esc, aria come free.
// Modal (centered) and Drawer (right side panel) share one primitive.
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { X } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import { Button } from "./button";

interface BaseProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  description?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
}

function Overlay() {
  return (
    <DialogPrimitive.Overlay asChild forceMount>
      <motion.div
        className="fixed inset-0 z-50 bg-black/45 backdrop-blur-[2px]"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        transition={{ duration: 0.18 }}
      />
    </DialogPrimitive.Overlay>
  );
}

function Header({ title, description }: { title: ReactNode; description?: ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-line px-5 py-4">
      <div>
        <DialogPrimitive.Title className="text-[15px] font-semibold tracking-tight">
          {title}
        </DialogPrimitive.Title>
        {description ? (
          <DialogPrimitive.Description className="mt-0.5 text-[12.5px] text-fg-muted">
            {description}
          </DialogPrimitive.Description>
        ) : (
          <DialogPrimitive.Description className="sr-only">{title}</DialogPrimitive.Description>
        )}
      </div>
      <DialogPrimitive.Close asChild>
        <Button variant="ghost" size="icon" aria-label="Close">
          <X className="size-4" />
        </Button>
      </DialogPrimitive.Close>
    </div>
  );
}

export function Modal({ open, onOpenChange, title, description, children, footer, wide }: BaseProps & { wide?: boolean }) {
  const reduced = useReducedMotion();
  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <AnimatePresence>
        {open && (
          <DialogPrimitive.Portal forceMount>
            <Overlay />
            <div className="fixed inset-0 z-50 grid place-items-center p-4 pointer-events-none">
              <DialogPrimitive.Content asChild forceMount>
                <motion.div
                  className={cn(
                    "pointer-events-auto w-full overflow-hidden rounded-xl border border-line bg-surface-1 shadow-pop",
                    wide ? "max-w-2xl" : "max-w-md",
                  )}
                  initial={reduced ? { opacity: 0 } : { opacity: 0, scale: 0.96, y: 10 }}
                  animate={{ opacity: 1, scale: 1, y: 0 }}
                  exit={reduced ? { opacity: 0 } : { opacity: 0, scale: 0.97, y: 6 }}
                  transition={reduced ? { duration: 0.12 } : { type: "spring", duration: 0.35, bounce: 0.15 }}
                >
                  <Header title={title} description={description} />
                  <div className="px-5 py-4">{children}</div>
                  {footer && (
                    <div className="flex justify-end gap-2 border-t border-line bg-surface-2/50 px-5 py-3.5">
                      {footer}
                    </div>
                  )}
                </motion.div>
              </DialogPrimitive.Content>
            </div>
          </DialogPrimitive.Portal>
        )}
      </AnimatePresence>
    </DialogPrimitive.Root>
  );
}

export function Drawer({ open, onOpenChange, title, description, children, footer }: BaseProps) {
  const reduced = useReducedMotion();
  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <AnimatePresence>
        {open && (
          <DialogPrimitive.Portal forceMount>
            <Overlay />
            <DialogPrimitive.Content asChild forceMount>
              <motion.div
                className="fixed inset-y-0 right-0 z-50 flex w-full max-w-lg flex-col border-l border-line bg-surface-1 shadow-pop max-sm:max-w-full"
                initial={reduced ? { opacity: 0 } : { x: "100%" }}
                animate={reduced ? { opacity: 1 } : { x: 0 }}
                exit={reduced ? { opacity: 0 } : { x: "100%" }}
                transition={reduced ? { duration: 0.12 } : { type: "spring", duration: 0.4, bounce: 0 }}
              >
                <Header title={title} description={description} />
                <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">{children}</div>
                {footer && (
                  <div className="flex justify-end gap-2 border-t border-line bg-surface-2/50 px-5 py-3.5">
                    {footer}
                  </div>
                )}
              </motion.div>
            </DialogPrimitive.Content>
          </DialogPrimitive.Portal>
        )}
      </AnimatePresence>
    </DialogPrimitive.Root>
  );
}

/** Destructive / decision confirm dialog with optional required-reason input. */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel = "Confirm",
  tone = "danger",
  loading,
  onConfirm,
  children,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  title: ReactNode;
  description?: ReactNode;
  confirmLabel?: string;
  tone?: "danger" | "primary";
  loading?: boolean;
  onConfirm: () => void;
  children?: ReactNode;
}) {
  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={title}
      description={description}
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            variant={tone === "danger" ? "danger" : "primary"}
            loading={loading}
            onClick={onConfirm}
          >
            {confirmLabel}
          </Button>
        </>
      }
    >
      {children ?? null}
    </Modal>
  );
}
