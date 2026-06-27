import { createFileRoute } from "@tanstack/react-router";
import { motion } from "framer-motion";
import { Check, ShieldCheck, X } from "lucide-react";
import { useMemo, useState } from "react";
import { Panel } from "@/components/app/card";
import { PageHeader } from "@/components/app/page-header";
import { Pill } from "@/components/app/badge";
import { Mono } from "@/components/app/mono";
import { StatusDot } from "@/components/app/status-dot";
import { EmptyState } from "@/components/app/empty";
import { approvals as seed } from "@/mock/seed";
import { fmtRelative } from "@/lib/format";
import type { Approval } from "@/types/crabby";

export const Route = createFileRoute("/_authenticated/approvals")({
  head: () => ({ meta: [{ title: "Approvals · Crabby Proxy" }] }),
  component: ApprovalsPage,
});

const TABS = [
  { id: "pending", label: "Pending" },
  { id: "all", label: "All requests" },
  { id: "active", label: "Active grants" },
  { id: "history", label: "History" },
] as const;
type Tab = (typeof TABS)[number]["id"];

function ApprovalsPage() {
  const [tab, setTab] = useState<Tab>("pending");
  const [list, setList] = useState<Approval[]>(seed);
  const filtered = useMemo(() => {
    if (tab === "pending") return list.filter((a) => a.status === "pending");
    if (tab === "active") return list.filter((a) => a.status === "approved");
    if (tab === "history") return list.filter((a) => a.status !== "pending");
    return list;
  }, [list, tab]);
  const [active, setActive] = useState<Approval | null>(filtered[0] ?? null);
  const sel = filtered.find((a) => a.id === active?.id) ?? filtered[0] ?? null;

  function decide(id: number, ok: boolean) {
    setList((cur) =>
      cur.map((a) =>
        a.id === id
          ? {
              ...a,
              status: ok ? "approved" : "rejected",
              decided_at: new Date().toISOString(),
              decided_by: "root",
            }
          : a,
      ),
    );
  }

  return (
    <div className="mx-auto w-full max-w-[1500px] px-6 py-8 lg:px-10">
      <PageHeader
        title="Approvals"
        subtitle="Time-bound access requests. Decide quickly — the operator's queue."
      />

      <div className="mb-4 inline-flex h-10 items-center gap-1 rounded-xl border border-white/[0.08] bg-white/[0.02] p-1">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={
              "relative rounded-lg px-3 py-1.5 text-xs font-medium transition " +
              (tab === t.id ? "text-foreground" : "text-muted-foreground hover:text-foreground")
            }
          >
            {tab === t.id && (
              <motion.span layoutId="apTab" className="absolute inset-0 rounded-lg bg-white/[0.08]" transition={{ type: "spring", stiffness: 320, damping: 28 }} />
            )}
            <span className="relative">{t.label}</span>
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[420px_1fr]">
        <Panel className="overflow-hidden">
          <div className="border-b border-white/[0.06] px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            {filtered.length} request{filtered.length === 1 ? "" : "s"}
          </div>
          {filtered.length === 0 ? (
            <EmptyState icon={<ShieldCheck className="size-4" />} title="Inbox zero" description="No requests need your attention." className="m-6" />
          ) : (
            <ul className="divide-y divide-white/[0.04]">
              {filtered.map((a) => (
                <li
                  key={a.id}
                  onClick={() => setActive(a)}
                  className={
                    "cursor-pointer px-5 py-4 transition " +
                    (sel?.id === a.id ? "bg-[var(--accent-violet-soft)]" : "hover:bg-white/[0.03]")
                  }
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium">{a.username}</span>
                    <Pill variant={a.status === "pending" ? "warning" : a.status === "approved" ? "success" : "danger"}>
                      <StatusDot tone={a.status === "pending" ? "warning" : a.status === "approved" ? "success" : "danger"} /> {a.status}
                    </Pill>
                  </div>
                  <div className="mt-1 flex items-center gap-3 text-[11px] text-muted-foreground">
                    <Mono>{a.client_ip}</Mono>
                    <span>·</span>
                    <span>{a.duration_hours}h</span>
                    <span>·</span>
                    <span>{fmtRelative(a.requested_at)}</span>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel>
          {sel ? (
            <div className="p-6">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
                    Request #{sel.id}
                  </div>
                  <div className="mt-1 text-xl font-semibold tracking-tight">{sel.username}</div>
                  <div className="mt-1 text-xs text-muted-foreground">
                    asked {fmtRelative(sel.requested_at)} · grant duration <Mono className="text-foreground/80">{sel.duration_hours}h</Mono>
                  </div>
                </div>
                <Pill variant={sel.status === "pending" ? "warning" : sel.status === "approved" ? "success" : "danger"}>
                  <StatusDot tone={sel.status === "pending" ? "warning" : sel.status === "approved" ? "success" : "danger"} /> {sel.status}
                </Pill>
              </div>

              <div className="mt-6 grid grid-cols-2 gap-3">
                <Field label="Client IP" value={<Mono>{sel.client_ip}</Mono>} />
                <Field label="Duration" value={<Mono>{sel.duration_hours}h</Mono>} />
                <Field label="Decided by" value={<span>{sel.decided_by ?? "—"}</span>} />
                <Field label="Decided at" value={<span>{sel.decided_at ? fmtRelative(sel.decided_at) : "—"}</span>} />
              </div>

              <div className="mt-4 rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
                <div className="mb-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
                  Reason
                </div>
                <p className="text-sm leading-relaxed text-foreground/90">
                  {sel.reason || <span className="text-muted-foreground">No reason provided.</span>}
                </p>
              </div>

              {sel.status === "pending" && (
                <div className="mt-6 flex items-center gap-2">
                  <button
                    onClick={() => decide(sel.id, true)}
                    className="inline-flex h-10 items-center gap-2 rounded-xl bg-[var(--success)] px-4 text-sm font-semibold text-black shadow-[0_10px_30px_-10px_var(--success)] hover:brightness-110"
                  >
                    <Check className="size-4" /> Approve
                  </button>
                  <button
                    onClick={() => decide(sel.id, false)}
                    className="inline-flex h-10 items-center gap-2 rounded-xl border border-[var(--danger)]/30 bg-[var(--danger)]/10 px-4 text-sm font-semibold text-[var(--danger)] hover:bg-[var(--danger)]/15"
                  >
                    <X className="size-4" /> Deny
                  </button>
                </div>
              )}
            </div>
          ) : (
            <EmptyState icon={<ShieldCheck className="size-4" />} title="Select a request" className="m-6" />
          )}
        </Panel>
      </div>
    </div>
  );
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
      <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">{label}</div>
      <div className="mt-1 text-sm">{value}</div>
    </div>
  );
}