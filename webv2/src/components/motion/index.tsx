// Motion primitives. Everything respects prefers-reduced-motion via
// useReducedMotion — reduced users get instant, opacity-only changes.
import { motion, useReducedMotion, useSpring, useTransform } from "motion/react";
import { useEffect, type ReactNode } from "react";

/** Route-level transition: soft rise + fade. */
export function PageTransition({ children }: { children: ReactNode }) {
  const reduced = useReducedMotion();
  return (
    <motion.div
      initial={reduced ? { opacity: 0 } : { opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25, ease: [0.22, 1, 0.36, 1] }}
    >
      {children}
    </motion.div>
  );
}

/** Staggered reveal container + item for card grids. */
export function Stagger({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <motion.div
      className={className}
      initial="hidden"
      animate="show"
      variants={{ show: { transition: { staggerChildren: 0.05 } } }}
    >
      {children}
    </motion.div>
  );
}

export function StaggerItem({ children, className }: { children: ReactNode; className?: string }) {
  const reduced = useReducedMotion();
  return (
    <motion.div
      className={className}
      variants={{
        hidden: reduced ? { opacity: 0 } : { opacity: 0, y: 10, scale: 0.99 },
        show: {
          opacity: 1,
          y: 0,
          scale: 1,
          transition: { type: "spring", duration: 0.5, bounce: 0.15 },
        },
      }}
    >
      {children}
    </motion.div>
  );
}

/** Spring-tweened numeral — counts toward the target on every change. */
export function AnimatedNumber({
  value,
  format,
  className,
}: {
  value: number;
  format?: (n: number) => string;
  className?: string;
}) {
  const reduced = useReducedMotion();
  const spring = useSpring(value, { stiffness: 90, damping: 24 });
  const display = useTransform(spring, (v) =>
    format ? format(v) : Math.round(v).toLocaleString("en-US"),
  );
  useEffect(() => {
    if (reduced) spring.jump(value);
    else spring.set(value);
  }, [value, spring, reduced]);
  return <motion.span className={className}>{display}</motion.span>;
}
