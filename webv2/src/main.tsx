import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router";
import { MotionConfig } from "motion/react";
import { Toaster } from "sonner";
import { App } from "./app";
import { TooltipProvider } from "@/components/ui/misc";
import { RootErrorBoundary } from "@/components/ui/error-boundary";
import "./styles.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5_000,
      retry: (failureCount, error) => {
        // Never retry auth/permission failures; retry network blips twice.
        const status = (error as { status?: number }).status ?? 0;
        if (status === 401 || status === 403 || status === 404) return false;
        return failureCount < 2;
      },
      refetchOnWindowFocus: true,
    },
  },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        {/* reducedMotion="user": when the OS asks for reduced motion, every
            motion component drops transform/layout animation (e.g. the
            sidebar's sliding active pill, the mobile nav sheet). CSS
            animations are handled by the media query in styles.css. */}
        <MotionConfig reducedMotion="user">
          <RootErrorBoundary>
            <TooltipProvider>
              <App />
            </TooltipProvider>
          </RootErrorBoundary>
        </MotionConfig>
        {/* The old UI called toast() everywhere but never mounted a Toaster —
            every piece of action feedback was invisible. Never again. */}
        <Toaster
          position="bottom-right"
          toastOptions={{
            style: {
              background: "var(--surface-3)",
              border: "1px solid var(--border-strong)",
              color: "var(--text)",
            },
          }}
        />
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
