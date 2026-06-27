import { createFileRoute } from "@tanstack/react-router";
import { AnimatePresence, motion } from "framer-motion";
import { Check, Plus, ShieldCheck, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { Panel } from "@/components/app/card";
import { PageHeader } from "@/components/app/page-header";
import { Pill } from "@/components/app/badge";
import { Mono } from "@/components/app/mono";
import { StatusDot } from "@/components/app/status-dot";
import { EmptyState } from "@/components/app/empty";
import {
  api,
  useApprovalRequests,
  useApprovals,
  useInvalidate,
  useMutation,
  useUsers,
  useUserMap,
} from "@/lib/queries";
import { isAdmin } from "@/lib/auth";
import { fmtRelative } from "@/lib/format";

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
  const [activeId, setActiveId] = useState<number | null>(null);
  const [termReason, setTermReason] = useState("");
  const invalidate = useInvalidate();

  const admin = isAdmin();
  const nameOf = useUserMap();
  const [requestOpen, setRequestOpen] = useState(false);
  const [grantOpen, setGrantOpen] = useState(false);

  const { requests, isLoading: reqLoading } = useApprovalRequests();
  const { approvals, isLoading: grantsLoading } = useApprovals();

  const filtered = useMemo(() => {
    if (tab === "pending") return requests.filter((a) => a.status === "pending");
    if (tab === "active") return approvals;
    if (tab === "history") return requests.filter((a) => a.status !== "pending");
    return requests;
  }, [requests, approvals, tab]);

  const isLoading = tab === "active" ? grantsLoading : reqLoading;
  const sel = filtered.find((a) => a.id === activeId) ?? filtered[0] ?? null;

  const decideMut = useMutation({
    mutationFn: ({ id, ok }: { id: number; ok: boolean }) =>
      ok ? api.approveRequest(id) : api.rejectRequest(id),
    onSuccess: (_d, { ok }) => {
      toast.success(ok ? "Request approved" : "Request rejected");
      invalidate(["approval-requests", "approvals"]);
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Action failed"),
  });

  const terminateMut = useMutation({
    mutationFn: ({ id, reason }: { id: number; reason: string }) =>
      api.terminateApproval(id, reason),
    onSuccess: () => {
      toast.success("Grant terminated");
      setTermReason("");
      invalidate(["approval-requests", "approvals"]);
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Action failed"),
  });

  function decide(id: number, ok: boolean) {
    decideMut.mutate({ id, ok });
  }

  const requestMut = useMutation({
    mutationFn: (body: { client_ip: string; duration_hours: number; reason?: string }) =>
      api.createApprovalRequest(body),
    onSuccess: () => {
      toast.success("Access request submitted");
      setRequestOpen(false);
      invalidate(["approval-requests"]);
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Request failed"),
  });

  const grantMut = useMutation({
    mutationFn: (body: {
      user_id: number;
      client_ip: string;
      duration_hours: number;
      reason?: string;
    }) => api.createApproval(body),
    onSuccess: () => {
      toast.success("Grant created");
      setGrantOpen(false);
      invalidate(["approval-requests", "approvals"]);
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Create grant failed"),
  });

  return (
    <div className="mx-auto w-full max-w-[1500px] px-6 py-8 lg:px-10">
      <PageHeader
        title="Approvals"
        subtitle="Time-bound access requests. Decide quickly — the operator's queue."
        action={
          <div className="flex items-center gap-2">
            <button
              onClick={() => setRequestOpen(true)}
              className="inline-flex h-9 items-center gap-2 rounded-xl border border-white/[0.08] bg-white/[0.03] px-3 text-sm font-medium hover:bg-white/[0.06]"
            >
              <Plus className="size-4" /> Request access
            </button>
            {admin && (
              <button
                onClick={() => setGrantOpen(true)}
                className="inline-flex h-9 items-center gap-2 rounded-xl bg-[var(--accent-violet)] px-3 text-sm font-semibold text-[var(--primary-foreground)] shadow-[0_10px_30px_-10px_var(--accent-violet)] hover:brightness-110"
              >
                <ShieldCheck className="size-4" /> Create grant
              </button>
            )}
          </div>
        }
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
            {isLoading ? "Loading…" : `${filtered.length} request${filtered.length === 1 ? "" : "s"}`}
          </div>
          {isLoading ? (
            <EmptyState icon={<ShieldCheck className="size-4" />} title="Loading…" className="m-6" />
          ) : filtered.length === 0 ? (
            <EmptyState icon={<ShieldCheck className="size-4" />} title="Inbox zero" description="No requests need your attention." className="m-6" />
          ) : (
            <ul className="divide-y divide-white/[0.04]">
              {filtered.map((a) => (
                <li
                  key={a.id}
                  onClick={() => setActiveId(a.id)}
                  className={
                    "cursor-pointer px-5 py-4 transition " +
                    (sel?.id === a.id ? "bg-[var(--accent-violet-soft)]" : "hover:bg-white/[0.03]")
                  }
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium">{nameOf(a.user_id)}</span>
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
                  <div className="mt-1 text-xl font-semibold tracking-tight">{nameOf(sel.user_id)}</div>
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
                    disabled={decideMut.isPending}
                    className="inline-flex h-10 items-center gap-2 rounded-xl bg-[var(--success)] px-4 text-sm font-semibold text-black shadow-[0_10px_30px_-10px_var(--success)] hover:brightness-110 disabled:opacity-50"
                  >
                    <Check className="size-4" /> Approve
                  </button>
                  <button
                    onClick={() => decide(sel.id, false)}
                    disabled={decideMut.isPending}
                    className="inline-flex h-10 items-center gap-2 rounded-xl border border-[var(--danger)]/30 bg-[var(--danger)]/10 px-4 text-sm font-semibold text-[var(--danger)] hover:bg-[var(--danger)]/15 disabled:opacity-50"
                  >
                    <X className="size-4" /> Deny
                  </button>
                </div>
              )}

              {tab === "active" && (
                <div className="mt-6">
                  <div className="mb-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
                    Terminate grant
                  </div>
                  <div className="flex items-center gap-2">
                    <input
                      value={termReason}
                      onChange={(e) => setTermReason(e.target.value)}
                      placeholder="Reason (required)"
                      className="h-10 flex-1 rounded-xl border border-white/[0.08] bg-white/[0.02] px-3 text-sm outline-none placeholder:text-muted-foreground focus:border-white/[0.16]"
                    />
                    <button
                      onClick={() => terminateMut.mutate({ id: sel.id, reason: termReason.trim() })}
                      disabled={!termReason.trim() || terminateMut.isPending}
                      className="inline-flex h-10 items-center gap-2 rounded-xl border border-[var(--danger)]/30 bg-[var(--danger)]/10 px-4 text-sm font-semibold text-[var(--danger)] hover:bg-[var(--danger)]/15 disabled:opacity-50"
                    >
                      <X className="size-4" /> Terminate
                    </button>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <EmptyState icon={<ShieldCheck className="size-4" />} title="Select a request" className="m-6" />
          )}
        </Panel>
      </div>

      <AnimatePresence>
        {requestOpen && (
          <RequestDialog
            pending={requestMut.isPending}
            onClose={() => setRequestOpen(false)}
            onSubmit={(b) => requestMut.mutate(b)}
          />
        )}
        {grantOpen && (
          <GrantDialog
            pending={grantMut.isPending}
            onClose={() => setGrantOpen(false)}
            onSubmit={(b) => grantMut.mutate(b)}
          />
        )}
      </AnimatePresence>
    </div>
  );
}

const DURATIONS = [1, 4, 8, 24, 72, 168];

function useClientIp() {
  const [ip, setIp] = useState("");
  useEffect(() => {
    fetch("https://api.ipify.org?format=json")
      .then((r) => r.json())
      .then((d) => setIp(d.ip))
      .catch(() => {});
  }, []);
  return [ip, setIp] as const;
}

function Modal({ title, children, onClose }: { title: string; children: React.ReactNode; onClose: () => void }) {
  return (
    <motion.div
      className="fixed inset-0 z-50 grid place-items-center bg-black/50 backdrop-blur-sm p-4"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      onClick={onClose}
    >
      <motion.div
        onClick={(e) => e.stopPropagation()}
        initial={{ opacity: 0, scale: 0.96, y: 8 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.97 }}
        transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
        className="w-full max-w-[440px] rounded-2xl border border-white/[0.08] bg-[color-mix(in_oklab,var(--surface)_85%,transparent)] p-6 backdrop-blur-2xl"
      >
        <div className="mb-4 text-sm font-semibold">{title}</div>
        {children}
      </motion.div>
    </motion.div>
  );
}

function DurationPicker({ value, onChange }: { value: number; onChange: (n: number) => void }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {DURATIONS.map((h) => (
        <button
          key={h}
          type="button"
          onClick={() => onChange(h)}
          className={
            "rounded-lg border px-2.5 py-1 text-xs " +
            (value === h
              ? "border-[var(--accent-violet)]/50 bg-[var(--accent-violet-soft)] text-[var(--accent-violet)]"
              : "border-white/[0.08] text-muted-foreground hover:text-foreground")
          }
        >
          {h}h
        </button>
      ))}
    </div>
  );
}

const inputCls =
  "h-10 w-full rounded-xl border border-white/[0.08] bg-white/[0.02] px-3 text-sm outline-none placeholder:text-muted-foreground focus:border-white/[0.16]";
const labelCls = "mb-1.5 block text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground";

function RequestDialog({
  pending,
  onClose,
  onSubmit,
}: {
  pending: boolean;
  onClose: () => void;
  onSubmit: (b: { client_ip: string; duration_hours: number; reason?: string }) => void;
}) {
  const [ip, setIp] = useClientIp();
  const [hours, setHours] = useState(24);
  const [reason, setReason] = useState("");
  return (
    <Modal title="Request access" onClose={onClose}>
      <div className="space-y-4">
        <div>
          <label className={labelCls}>Client IP</label>
          <input className={inputCls} value={ip} onChange={(e) => setIp(e.target.value)} placeholder="auto-detecting…" />
        </div>
        <div>
          <label className={labelCls}>Duration</label>
          <DurationPicker value={hours} onChange={setHours} />
        </div>
        <div>
          <label className={labelCls}>Reason (optional)</label>
          <input className={inputCls} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why do you need access?" />
        </div>
        <button
          disabled={pending || !ip.trim()}
          onClick={() => onSubmit({ client_ip: ip.trim(), duration_hours: hours, reason: reason.trim() || undefined })}
          className="h-10 w-full rounded-xl bg-[var(--accent-violet)] text-sm font-semibold text-[var(--primary-foreground)] hover:brightness-110 disabled:opacity-50"
        >
          Submit request
        </button>
      </div>
    </Modal>
  );
}

function GrantDialog({
  pending,
  onClose,
  onSubmit,
}: {
  pending: boolean;
  onClose: () => void;
  onSubmit: (b: { user_id: number; client_ip: string; duration_hours: number; reason?: string }) => void;
}) {
  const { users } = useUsers();
  const [userId, setUserId] = useState<number | "">("");
  const [ip, setIp] = useState("");
  const [hours, setHours] = useState(24);
  const [reason, setReason] = useState("");
  return (
    <Modal title="Create approved grant" onClose={onClose}>
      <div className="space-y-4">
        <div>
          <label className={labelCls}>User</label>
          <select
            className={inputCls + " appearance-none"}
            value={userId}
            onChange={(e) => setUserId(e.target.value ? Number(e.target.value) : "")}
          >
            <option value="">Select a user…</option>
            {users.map((u) => (
              <option key={u.id} value={u.id}>
                {u.username} ({u.role})
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className={labelCls}>Client IP</label>
          <input className={inputCls} value={ip} onChange={(e) => setIp(e.target.value)} placeholder="e.g. 203.0.113.4" />
        </div>
        <div>
          <label className={labelCls}>Duration</label>
          <DurationPicker value={hours} onChange={setHours} />
        </div>
        <div>
          <label className={labelCls}>Reason (optional)</label>
          <input className={inputCls} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Audit note" />
        </div>
        <button
          disabled={pending || userId === "" || !ip.trim()}
          onClick={() =>
            onSubmit({
              user_id: Number(userId),
              client_ip: ip.trim(),
              duration_hours: hours,
              reason: reason.trim() || undefined,
            })
          }
          className="h-10 w-full rounded-xl bg-[var(--accent-violet)] text-sm font-semibold text-[var(--primary-foreground)] hover:brightness-110 disabled:opacity-50"
        >
          Create grant
        </button>
      </div>
    </Modal>
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