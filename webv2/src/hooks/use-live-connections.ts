// Live connections feed.
//
// The backend WebSocket has a sharp edge: it emits a snapshot every 2s ONLY
// when the connection COUNT changes. Byte counters and states do not stream.
// So this hook runs a hybrid:
//   • WebSocket (one-time 30s ticket → ws) for instant add/remove signals
//   • REST polling every 4s for byte/state refresh (always on; cheap)
// and merges both into one list, keyed by connection id, with client-side
// per-connection transfer rates computed from successive byte deltas.
//
// Reconnect: exponential backoff with jitter (1s → 15s cap). Unlike the old
// UI, a socket that opens-then-drops still keeps the REST poll alive, so the
// page never silently freezes.

import { useEffect, useMemo, useRef, useState } from "react";
import { issueLiveTicket } from "@/api/endpoints";
import { liveSocketUrl } from "@/api/http";
import { useConnections } from "@/hooks/queries";
import type { ConnectionInfo, LiveSnapshotFrame } from "@/api/types";

export type SocketState = "connecting" | "live" | "reconnecting" | "polling";

export interface LiveConnection extends ConnectionInfo {
  /** Client-side estimate, bytes/sec over the last sample window. */
  rate_bps: number;
}

export function useLiveConnections(enabled = true) {
  const [wsRows, setWsRows] = useState<ConnectionInfo[] | null>(null);
  const [socketState, setSocketState] = useState<SocketState>("connecting");
  const [lastEventAt, setLastEventAt] = useState<number | null>(null);

  // REST poll — the steady heartbeat that keeps byte counters honest.
  const poll = useConnections(enabled, 4000);

  const ratesRef = useRef(new Map<string, { bytes: number; at: number; rate: number }>());

  useEffect(() => {
    if (!enabled) return;
    let ws: WebSocket | null = null;
    let closed = false;
    let attempt = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const scheduleReconnect = () => {
      if (closed) return;
      setSocketState("reconnecting");
      const delay = Math.min(1000 * 2 ** attempt, 15_000) * (0.75 + Math.random() * 0.5);
      attempt++;
      timer = setTimeout(connect, delay);
    };

    async function connect() {
      if (closed) return;
      try {
        const { ticket } = await issueLiveTicket();
        if (closed) return;
        ws = new WebSocket(liveSocketUrl(ticket));
        ws.onopen = () => {
          attempt = 0;
          setSocketState("live");
        };
        ws.onmessage = (ev) => {
          try {
            const msg = JSON.parse(ev.data as string) as LiveSnapshotFrame;
            if (msg && Array.isArray(msg.connections)) {
              setWsRows(msg.connections);
              setLastEventAt(Date.now());
            }
          } catch {
            /* ignore malformed frames */
          }
        };
        ws.onerror = () => ws?.close();
        ws.onclose = scheduleReconnect;
      } catch {
        // Ticket mint or socket construction failed — REST poll still runs;
        // reflect degraded mode and keep trying the socket in the background.
        setSocketState("polling");
        scheduleReconnect();
      }
    }

    connect();
    return () => {
      closed = true;
      if (timer) clearTimeout(timer);
      ws?.close();
    };
  }, [enabled]);

  // Merge: REST is the base truth for byte counters; WS wins for membership
  // freshness (instant add/remove between polls).
  const connections = useMemo<LiveConnection[]>(() => {
    const rest = poll.data ?? [];
    const restById = new Map(rest.map((c) => [c.id, c]));
    let list: ConnectionInfo[];
    if (wsRows == null) {
      list = rest;
    } else {
      const wsAge = lastEventAt ? Date.now() - lastEventAt : Infinity;
      const restNewer = poll.dataUpdatedAt > (lastEventAt ?? 0);
      // Prefer whichever source is fresher for membership; enrich WS rows
      // with REST byte counts when REST has newer data for the same id.
      const base = wsAge < 6000 && !restNewer ? wsRows : rest.length || wsAge > 15_000 ? rest : wsRows;
      list = base.map((c) => {
        const r = restById.get(c.id);
        return r && r.bytes_sent + r.bytes_received > c.bytes_sent + c.bytes_received ? r : c;
      });
    }

    // Per-connection rate from byte deltas.
    const now = Date.now();
    const rates = ratesRef.current;
    const out = list.map((c) => {
      const total = c.bytes_sent + c.bytes_received;
      const prev = rates.get(c.id);
      let rate = prev?.rate ?? 0;
      if (prev && now > prev.at) {
        const dt = (now - prev.at) / 1000;
        if (dt >= 1) {
          rate = Math.max(0, (total - prev.bytes) / dt);
          rates.set(c.id, { bytes: total, at: now, rate });
        }
      } else if (!prev) {
        rates.set(c.id, { bytes: total, at: now, rate: 0 });
      }
      return { ...c, rate_bps: rate };
    });
    // Drop rate entries for vanished connections.
    const liveIds = new Set(out.map((c) => c.id));
    for (const id of rates.keys()) if (!liveIds.has(id)) rates.delete(id);
    return out.sort((a, b) => b.created_at - a.created_at);
  }, [poll.data, poll.dataUpdatedAt, wsRows, lastEventAt]);

  return {
    connections,
    socketState,
    isLoading: poll.isLoading && wsRows == null,
    isError: poll.isError && wsRows == null,
    refetch: poll.refetch,
  };
}
