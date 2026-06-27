import { useEffect, useState } from "react";

export function AnimatedCounter({
  value,
  duration = 900,
  format,
}: {
  value: number;
  duration?: number;
  format?: (n: number) => string;
}) {
  const [v, setV] = useState(0);
  useEffect(() => {
    const start = performance.now();
    const from = v;
    const to = value;
    let raf = 0;
    function tick(t: number) {
      const p = Math.min(1, (t - start) / duration);
      const eased = 1 - Math.pow(1 - p, 4);
      setV(from + (to - from) * eased);
      if (p < 1) raf = requestAnimationFrame(tick);
    }
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value, duration]);
  return <>{format ? format(v) : Math.round(v).toLocaleString()}</>;
}