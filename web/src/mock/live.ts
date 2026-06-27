// Live connection feed — now backed by the real API (polls /api/connections).
// Keeps the original hook signature ({ rows, tick }) so pages are unchanged;
// the `initial` arg seeds the first render before the first fetch resolves.
import { useEffect, useRef, useState } from "react";
import { listConnections } from "@/lib/api";
import type { Connection } from "@/types/crabby";

export function useLiveConnections(initial: Connection[] = [], maxRows = 80) {
  const [rows, setRows] = useState<Connection[]>(initial);
  const [tick, setTick] = useState(0);
  const stopped = useRef(false);

  useEffect(() => {
    stopped.current = false;
    let timer: number;
    async function poll() {
      if (stopped.current) return;
      try {
        const conns = await listConnections();
        if (!stopped.current) {
          setRows(conns.slice(0, maxRows));
          setTick((t) => t + 1);
        }
      } catch {
        /* keep last rows on transient error */
      }
      timer = window.setTimeout(poll, 2500);
    }
    poll();
    return () => {
      stopped.current = true;
      window.clearTimeout(timer);
    };
  }, [maxRows]);

  return { rows, tick };
}

export function useTicker(intervalMs = 1000) {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const id = window.setInterval(() => setTick((t) => t + 1), intervalMs);
    return () => window.clearInterval(id);
  }, [intervalMs]);
  return tick;
}
