import { useEffect, useState } from "react";

/**
 * Wall-clock time in milliseconds, refreshed every `intervalMs`.
 *
 * Reading `Date.now()` directly during render makes a component impure (the
 * output changes between renders with identical props/state), so components
 * that display relative times or expiry read the clock through this hook.
 */
export function useNow(intervalMs: number): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(t);
  }, [intervalMs]);
  return now;
}
