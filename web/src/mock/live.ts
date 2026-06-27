// Live connection feed — real WebSocket stream (/api/connections/live),
// authorized by a one-time ticket since the browser can't put a bearer on the
// WS handshake. Falls back to REST polling if the socket can't be established.
// Keeps the original hook signature ({ rows, tick }) so pages are unchanged.
import { useEffect, useRef, useState } from "react";
import {
  adaptConnections,
  issueLiveTicket,
  liveSocketUrl,
  listConnections,
} from "@/lib/api";
import type { Connection } from "@/types/crabby";

export function useLiveConnections(initial: Connection[] = [], maxRows = 80) {
  const [rows, setRows] = useState<Connection[]>(initial);
  const [tick, setTick] = useState(0);
  const stopped = useRef(false);

  useEffect(() => {
    stopped.current = false;
    let socket: WebSocket | null = null;
    let pollTimer: number | undefined;
    let retryTimer: number | undefined;

    const apply = (conns: Connection[]) => {
      if (stopped.current) return;
      setRows(conns.slice(0, maxRows));
      setTick((t) => t + 1);
    };

    // Fallback: REST poll if the WS path fails.
    function startPolling() {
      async function poll() {
        if (stopped.current) return;
        try {
          apply(await listConnections());
        } catch {
          /* keep last rows */
        }
        pollTimer = window.setTimeout(poll, 2500);
      }
      poll();
    }

    async function connect() {
      if (stopped.current) return;
      try {
        const { ticket } = await issueLiveTicket();
        if (stopped.current) return;
        socket = new WebSocket(liveSocketUrl(ticket));
        socket.onmessage = (ev) => {
          try {
            const msg = JSON.parse(ev.data as string);
            if (Array.isArray(msg?.connections)) apply(adaptConnections(msg.connections));
          } catch {
            /* ignore malformed frame */
          }
        };
        socket.onerror = () => socket?.close();
        socket.onclose = () => {
          if (stopped.current) return;
          // Reconnect (re-ticket) with a short backoff.
          retryTimer = window.setTimeout(connect, 3000);
        };
      } catch {
        // Couldn't mint a ticket / open WS — degrade to polling.
        if (!stopped.current) startPolling();
      }
    }

    connect();
    return () => {
      stopped.current = true;
      window.clearTimeout(pollTimer);
      window.clearTimeout(retryTimer);
      socket?.close();
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
