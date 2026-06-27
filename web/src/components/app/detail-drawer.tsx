import { AnimatePresence, motion } from "framer-motion";
import { X } from "lucide-react";
import { useEffect } from "react";

export function DetailDrawer({
  open,
  onClose,
  title,
  eyebrow,
  children,
  footer,
  width = 480,
}: {
  open: boolean;
  onClose: () => void;
  title: React.ReactNode;
  eyebrow?: React.ReactNode;
  children: React.ReactNode;
  footer?: React.ReactNode;
  width?: number;
}) {
  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  return (
    <AnimatePresence>
      {open && (
        <>
          <motion.div
            key="bd"
            className="fixed inset-0 z-40 bg-black/40 backdrop-blur-md"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.25 }}
            onClick={onClose}
          />
          <motion.aside
            key="dr"
            className="fixed inset-y-0 right-0 z-50 flex flex-col border-l border-white/10 bg-[var(--surface)] shadow-[0_0_80px_-20px_rgba(0,0,0,0.8)]"
            style={{ width }}
            initial={{ x: width + 40 }}
            animate={{ x: 0 }}
            exit={{ x: width + 40 }}
            transition={{ type: "spring", damping: 30, stiffness: 280, mass: 0.9 }}
          >
            <header className="flex items-start justify-between gap-3 border-b border-white/10 px-6 py-5">
              <div className="min-w-0">
                {eyebrow && (
                  <div className="mb-1 text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
                    {eyebrow}
                  </div>
                )}
                <div className="truncate text-base font-semibold text-foreground">{title}</div>
              </div>
              <button
                aria-label="Close panel"
                onClick={onClose}
                className="grid size-8 shrink-0 place-items-center rounded-lg text-muted-foreground transition hover:bg-white/5 hover:text-foreground"
              >
                <X className="size-4" />
              </button>
            </header>
            <div className="flex-1 overflow-y-auto px-6 py-5">{children}</div>
            {footer && (
              <footer className="border-t border-white/10 bg-white/[0.02] px-6 py-4">{footer}</footer>
            )}
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  );
}