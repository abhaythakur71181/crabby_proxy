// Not found — unknown authenticated paths land here instead of silently
// bouncing to the dashboard, so a mistyped or stale link is obvious.
import { Compass } from "lucide-react";
import { Link, useLocation } from "react-router";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/states";

export function NotFoundPage() {
  const { pathname } = useLocation();
  return (
    <EmptyState
      icon={Compass}
      title="Page not found"
      description={`Nothing lives at ${pathname}. The link may be mistyped or out of date.`}
      action={
        // "/" routes each role to its own home (dashboard or account).
        <Link to="/">
          <Button variant="outline" size="sm">
            Back to home
          </Button>
        </Link>
      }
    />
  );
}
