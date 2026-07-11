import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router";
import { Toaster } from "sonner";
import { App } from "./app";
import { TooltipProvider } from "@/components/ui/misc";
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
        <TooltipProvider>
          <App />
        </TooltipProvider>
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
