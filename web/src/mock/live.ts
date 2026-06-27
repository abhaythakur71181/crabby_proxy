import { useEffect, useRef, useState } from "react";
import { makeConnection } from "./seed";
import type { Connection } from "@/types/crabby";

let counter = 1000;

export function useLiveConnections(initial: Connection[], maxRows = 80) {
  const [rows, setRows] = useState<Connection[]>(initial);
  const [tick, setTick] = useState(0);
  const ref = useRef(rows);
  ref.current = rows;

  useEffect(() => {
    let stopped = false;
    function loop() {
      if (stopped) return;
      const next = makeConnection(counter++);
      setRows((cur) => {
        const closing = cur.length > maxRows ? cur.slice(0, cur.length - 1) : cur;
        return [next, ...closing];
      });
      setTick((t) => t + 1);
      const delay = 700 + Math.random() * 1500;
      window.setTimeout(loop, delay);
    }
    const id = window.setTimeout(loop, 900);
    return () => {
      stopped = true;
      window.clearTimeout(id);
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