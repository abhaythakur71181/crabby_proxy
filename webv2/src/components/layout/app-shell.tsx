// Authenticated shell: sidebar (desktop rail / mobile sheet) + topbar +
// page outlet with route transitions. Route guards live in app.tsx.
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { AnimatePresence, motion } from "motion/react";
import { Suspense, useEffect, useState } from "react";
import { Outlet, useLocation } from "react-router";
import { cn } from "@/lib/utils";
import { useNavChords } from "@/hooks/use-hotkeys";
import { PageTransition } from "@/components/motion";
import { Skeleton } from "@/components/ui/states";
import { CommandPalette } from "./command-palette";
import { SidebarContent } from "./sidebar";
import { Topbar } from "./topbar";

const COLLAPSE_KEY = "cbpx2_sidebar_collapsed";

export function AppShell() {
  const location = useLocation();
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem(COLLAPSE_KEY) === "1",
  );
  const [mobileOpen, setMobileOpen] = useState(false);
  useNavChords(true);

  // Close the mobile sheet on navigation.
  useEffect(() => setMobileOpen(false), [location.pathname]);

  const toggleCollapse = () => {
    setCollapsed((c) => {
      localStorage.setItem(COLLAPSE_KEY, c ? "0" : "1");
      return !c;
    });
  };

  return (
    <div className="flex min-h-dvh">
      {/* Desktop sidebar */}
      <aside
        className={cn(
          "sticky top-0 hidden h-dvh shrink-0 border-r border-line bg-surface-1/50 transition-[width] duration-200 lg:block",
          collapsed ? "w-16" : "w-60",
        )}
      >
        <SidebarContent collapsed={collapsed} onToggleCollapse={toggleCollapse} />
      </aside>

      {/* Mobile sheet */}
      <DialogPrimitive.Root open={mobileOpen} onOpenChange={setMobileOpen}>
        <AnimatePresence>
          {mobileOpen && (
            <DialogPrimitive.Portal forceMount>
              <DialogPrimitive.Overlay asChild forceMount>
                <motion.div
                  className="fixed inset-0 z-50 bg-black/45 lg:hidden"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                />
              </DialogPrimitive.Overlay>
              <DialogPrimitive.Content asChild forceMount>
                <motion.div
                  className="fixed inset-y-0 left-0 z-50 w-72 border-r border-line bg-surface-1 shadow-pop lg:hidden"
                  initial={{ x: "-100%" }}
                  animate={{ x: 0 }}
                  exit={{ x: "-100%" }}
                  transition={{ type: "spring", duration: 0.35, bounce: 0 }}
                >
                  <DialogPrimitive.Title className="sr-only">Navigation</DialogPrimitive.Title>
                  <SidebarContent onNavigate={() => setMobileOpen(false)} />
                </motion.div>
              </DialogPrimitive.Content>
            </DialogPrimitive.Portal>
          )}
        </AnimatePresence>
      </DialogPrimitive.Root>

      {/* Main */}
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar onOpenMobileNav={() => setMobileOpen(true)} />
        <main className="mx-auto w-full max-w-[1400px] flex-1 px-4 py-6 md:px-6">
          <AnimatePresence mode="wait" initial={false}>
            <PageTransition key={location.pathname}>
              {/* Suspense inside the shell: chrome stays put while a route
                  chunk loads; the page area shows skeletons. */}
              <Suspense
                fallback={
                  <div className="space-y-4" aria-busy>
                    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                      {[0, 1, 2, 3].map((i) => (
                        <Skeleton key={i} className="h-24" />
                      ))}
                    </div>
                    <Skeleton className="h-64" />
                  </div>
                }
              >
                <Outlet />
              </Suspense>
            </PageTransition>
          </AnimatePresence>
        </main>
      </div>

      <CommandPalette />
    </div>
  );
}
