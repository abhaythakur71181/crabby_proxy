import { createFileRoute } from "@tanstack/react-router";
import { motion } from "framer-motion";
import { Search } from "lucide-react";
import { useMemo, useState } from "react";
import { Panel } from "@/components/app/card";
import { PageHeader } from "@/components/app/page-header";
import { Pill } from "@/components/app/badge";
import { StatusDot } from "@/components/app/status-dot";
import { Mono } from "@/components/app/mono";
import { useAudit, useUserMap } from "@/lib/queries";
import { fmtRelative } from "@/lib/format";

export const Route = createFileRoute("/_authenticated/audit")({
  head: () => ({ meta: [{ title: "Audit Log · Crabby Proxy" }] }),
  component: AuditPage,
});

const OUTCOMES = ["all", "ok", "denied", "error"] as const;

function AuditPage() {
  const [q, setQ] = useState("");
  const [out, setOut] = useState<(typeof OUTCOMES)[number]>("all");
  const { entries } = useAudit(100);
  const nameOf = useUserMap();

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return entries.filter((a) => {
      if (out !== "all" && a.outcome !== out) return false;
      if (!needle) return true;
      return (
        a.actor.toLowerCase().includes(needle) ||
        a.action.toLowerCase().includes(needle) ||
        a.target.toLowerCase().includes(needle) ||
        a.ip.includes(needle)
      );
    });
  }, [q, out, entries]);

  return (
    <div className="mx-auto w-full max-w-[1500px] px-6 py-8 lg:px-10">
      <PageHeader title="Audit Log" subtitle="Every privileged action — actor, target, outcome, and IP." />
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="flex h-10 flex-1 items-center gap-2 rounded-xl border border-white/[0.08] bg-white/[0.03] px-3 focus-within:border-[var(--accent-violet)]/50">
          <Search className="size-4 text-muted-foreground" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search actor, action, target or IP…"
            className="h-full flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground"
          />
        </div>
        <div className="flex h-10 items-center gap-1 rounded-xl border border-white/[0.08] bg-white/[0.02] p-1">
          {OUTCOMES.map((o) => (
            <button
              key={o}
              onClick={() => setOut(o)}
              className={
                "rounded-lg px-3 text-[11px] font-medium uppercase tracking-wider transition " +
                (out === o ? "bg-white/[0.08] text-foreground" : "text-muted-foreground hover:text-foreground")
              }
            >
              {o}
            </button>
          ))}
        </div>
      </div>

      <Panel>
        <div className="grid grid-cols-[140px_120px_180px_1fr_120px_90px] gap-3 border-b border-white/[0.06] px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          <span>When</span><span>Actor</span><span>Action</span><span>Target / details</span><span>IP</span><span>Outcome</span>
        </div>
        <ul className="divide-y divide-white/[0.04]">
          {filtered.slice(0, 50).map((a, i) => (
            <motion.li
              key={a.id}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: Math.min(i * 0.015, 0.4) }}
              className="grid grid-cols-[140px_120px_180px_1fr_120px_90px] items-center gap-3 px-5 py-2.5 text-xs hover:bg-white/[0.03]"
            >
              <span className="text-muted-foreground">{fmtRelative(a.ts)}</span>
              <span className="truncate">{nameOf(a.actor_id)}</span>
              <Mono className="text-[11px] text-foreground/85">{a.action}</Mono>
              <span className="truncate">
                <Mono className="text-[11px] text-foreground/70">{a.target}</Mono>
                <span className="ml-2 text-[10px] text-muted-foreground">{a.details}</span>
              </span>
              <Mono className="text-[11px] text-muted-foreground">{a.ip}</Mono>
              <Pill variant={a.outcome === "ok" ? "success" : a.outcome === "denied" ? "warning" : "danger"}>
                <StatusDot tone={a.outcome === "ok" ? "success" : a.outcome === "denied" ? "warning" : "danger"} pulse={false} /> {a.outcome}
              </Pill>
            </motion.li>
          ))}
        </ul>
      </Panel>
    </div>
  );
}