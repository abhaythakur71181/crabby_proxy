// Render-error containment. Query failures are already handled per panel via
// ErrorState; this catches everything else (a throwing component, a route
// chunk that fails to load after a redeploy) so one bug never white-screens
// the console mid-incident.
import { QueryErrorResetBoundary } from "@tanstack/react-query";
import { RotateCw } from "lucide-react";
import { Component, type ErrorInfo, type ReactNode } from "react";
import { cn } from "@/lib/utils";
import { Button } from "./button";
import { ErrorState } from "./states";

type FallbackRender = (props: { error: Error; reset: () => void }) => ReactNode;

type Props = {
  children: ReactNode;
  fallback: FallbackRender;
  /** When this value changes while showing the fallback, the boundary resets
   * (e.g. the route path, so navigating away recovers). */
  resetKey?: unknown;
  onReset?: () => void;
};

type State = { error: Error | null };

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: unknown): State {
    return { error: error instanceof Error ? error : new Error(String(error)) };
  }

  componentDidCatch(error: unknown, info: ErrorInfo) {
    console.error("Unhandled render error", error, info.componentStack);
  }

  componentDidUpdate(prev: Props) {
    if (this.state.error && !Object.is(prev.resetKey, this.props.resetKey)) this.reset();
  }

  reset = () => {
    this.props.onReset?.();
    this.setState({ error: null });
  };

  render() {
    const { error } = this.state;
    if (error) return this.props.fallback({ error, reset: this.reset });
    return this.props.children;
  }
}

function CrashFallback({ error, reset, className }: { error: Error; reset: () => void; className?: string }) {
  return (
    <div className={cn("space-y-3", className)}>
      <ErrorState
        title="Something went wrong rendering this view"
        detail={error.message || undefined}
        onRetry={reset}
      />
      <div className="flex justify-center">
        <Button variant="ghost" size="sm" onClick={() => window.location.reload()}>
          <RotateCw className="size-3.5" aria-hidden /> Reload page
        </Button>
      </div>
    </div>
  );
}

/** Boundary for the routed page area: resets on navigation and also resets
 * failed queries (QueryErrorResetBoundary) when the user retries. */
export function PageErrorBoundary({ children, resetKey }: { children: ReactNode; resetKey?: unknown }) {
  return (
    <QueryErrorResetBoundary>
      {({ reset: resetQueries }) => (
        <ErrorBoundary
          resetKey={resetKey}
          onReset={resetQueries}
          fallback={({ error, reset }) => <CrashFallback error={error} reset={reset} />}
        >
          {children}
        </ErrorBoundary>
      )}
    </QueryErrorResetBoundary>
  );
}

/** Last-resort boundary around the whole app (login, shell chrome). */
export function RootErrorBoundary({ children }: { children: ReactNode }) {
  return (
    <ErrorBoundary
      fallback={({ error, reset }) => (
        <div className="grid min-h-dvh place-items-center p-6">
          <CrashFallback error={error} reset={reset} className="w-full max-w-md" />
        </div>
      )}
    >
      {children}
    </ErrorBoundary>
  );
}
