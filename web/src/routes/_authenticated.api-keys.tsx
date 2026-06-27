import { createFileRoute } from "@tanstack/react-router";
import { AnimatePresence, motion } from "framer-motion";
import { Check, Copy, KeyRound, Plus, Trash2, X } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { Panel } from "@/components/app/card";
import { PageHeader } from "@/components/app/page-header";
import { Pill } from "@/components/app/badge";
import { StatusDot } from "@/components/app/status-dot";
import { Mono } from "@/components/app/mono";
import { getSession } from "@/lib/auth";
import { api, useApiKeys, useInvalidate, useMutation, useUsers } from "@/lib/queries";
import { fmtRelative } from "@/lib/format";

export const Route = createFileRoute("/_authenticated/api-keys")({
  head: () => ({ meta: [{ title: "API Keys · Crabby Proxy" }] }),
  component: ApiKeysPage,
});

function ApiKeysPage() {
  const session = getSession();
  const { users } = useUsers();
  const me = users.find((u) => u.username === session?.username);
  const userId = me?.id ?? 0;

  const { keys, isLoading } = useApiKeys(userId, me?.username);
  const invalidate = useInvalidate();

  const [openNew, setOpenNew] = useState(false);
  const [revealed, setRevealed] = useState<string | null>(null);

  const revoke = useMutation({
    mutationFn: (keyId: string) => api.revokeApiKey(userId, keyId),
    onSuccess: () => {
      toast.success("API key revoked");
      invalidate(["api-keys"]);
    },
    onError: (err: Error) => toast.error(err.message),
  });

  return (
    <div className="mx-auto w-full max-w-[1300px] px-6 py-8 lg:px-10">
      <PageHeader
        title="API Keys"
        subtitle="Programmatic access for clients. Keys are write-once — copy them now or rotate."
        action={
          <button
            disabled={!userId}
            onClick={() => setOpenNew(true)}
            className="inline-flex h-10 items-center gap-2 rounded-xl bg-[var(--accent-violet)] px-4 text-sm font-semibold text-[var(--primary-foreground)] hover:brightness-110 disabled:opacity-50"
          >
            <Plus className="size-4" /> Generate key
          </button>
        }
      />
      <Panel>
        <div className="grid grid-cols-[40px_1fr_1.4fr_120px_120px_100px] gap-3 border-b border-white/[0.06] px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          <span>#</span><span>Label</span><span>Token</span><span>Owner</span><span>Last used</span><span>Status</span>
        </div>
        <ul className="divide-y divide-white/[0.04]">
          {isLoading && !keys.length && (
            <li className="px-5 py-8 text-center text-sm text-muted-foreground">Loading API keys…</li>
          )}
          {!isLoading && !keys.length && (
            <li className="px-5 py-8 text-center text-sm text-muted-foreground">No API keys yet.</li>
          )}
          {keys.map((k, i) => (
            <li key={k.id} className="grid grid-cols-[40px_1fr_1.4fr_120px_120px_100px] items-center gap-3 px-5 py-3 text-sm transition hover:bg-white/[0.03]">
              <Mono className="text-[11px] text-muted-foreground">{i + 1}</Mono>
              <div className="flex items-center gap-2"><KeyRound className="size-3.5 text-muted-foreground" /><span className="font-medium">{k.name}</span></div>
              <div className="flex items-center gap-2">
                <Mono className="rounded-md border border-white/10 bg-white/[0.04] px-2 py-1 text-[11px] text-foreground/80">{k.prefix}_{"•".repeat(12)}</Mono>
                <button
                  onClick={() => {
                    void navigator.clipboard.writeText(k.prefix);
                    toast.success("Prefix copied");
                  }}
                  className="grid size-6 place-items-center rounded text-muted-foreground hover:bg-white/5 hover:text-foreground"
                >
                  <Copy className="size-3" />
                </button>
              </div>
              <span className="text-xs">{k.username || me?.username || `User #${k.user_id}`}</span>
              <span className="text-xs text-muted-foreground">{fmtRelative(k.last_used_at)}</span>
              <div className="flex items-center gap-2">
                <Pill variant="success"><StatusDot tone="success" /> active</Pill>
                <button
                  disabled={revoke.isPending}
                  onClick={() => revoke.mutate(k.id)}
                  className="grid size-6 place-items-center rounded text-muted-foreground hover:bg-[var(--danger)]/10 hover:text-[var(--danger)] disabled:opacity-50"
                  title="Revoke key"
                >
                  <Trash2 className="size-3" />
                </button>
              </div>
            </li>
          ))}
        </ul>
      </Panel>

      <GenerateKeyModal
        open={openNew}
        userId={userId}
        onClose={() => setOpenNew(false)}
        onGenerated={(key) => {
          setOpenNew(false);
          setRevealed(key);
        }}
      />

      <RevealKeyModal secret={revealed} onClose={() => setRevealed(null)} />
    </div>
  );
}

function GenerateKeyModal({
  open,
  userId,
  onClose,
  onGenerated,
}: {
  open: boolean;
  userId: number;
  onClose: () => void;
  onGenerated: (key: string) => void;
}) {
  const [name, setName] = useState("");
  const [expires, setExpires] = useState("");
  const invalidate = useInvalidate();

  const create = useMutation({
    mutationFn: () =>
      api.createApiKey(userId, {
        name: name.trim(),
        expires_in_days: expires ? Number(expires) : undefined,
      }),
    onSuccess: (res: { key: string }) => {
      toast.success("API key generated");
      invalidate(["api-keys"]);
      setName("");
      setExpires("");
      onGenerated(res.key);
    },
    onError: (err: Error) => toast.error(err.message),
  });

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          className="fixed inset-0 z-50 grid place-items-center bg-black/55 px-4 backdrop-blur-md"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={onClose}
        >
          <motion.div
            initial={{ opacity: 0, y: 10, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 6, scale: 0.98 }}
            transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-md overflow-hidden rounded-2xl border border-white/10 bg-[var(--surface-2)] shadow-2xl"
          >
            <div className="flex items-center justify-between border-b border-white/10 px-5 py-4">
              <div>
                <div className="text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
                  Provision
                </div>
                <div className="text-base font-semibold">Generate API key</div>
              </div>
              <button onClick={onClose} className="grid size-8 place-items-center rounded-lg text-muted-foreground hover:bg-white/5 hover:text-foreground">
                <X className="size-4" />
              </button>
            </div>
            <div className="space-y-4 px-5 py-5">
              <label className="block">
                <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Label</div>
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="ci-deploy"
                  className="h-10 w-full rounded-xl border border-white/[0.08] bg-white/[0.03] px-3 text-sm outline-none transition focus:border-[var(--accent-violet)]/50 focus:bg-white/[0.05]"
                />
              </label>
              <label className="block">
                <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Expires in (days, optional)</div>
                <input
                  value={expires}
                  onChange={(e) => setExpires(e.target.value)}
                  placeholder="90"
                  className="h-10 w-full rounded-xl border border-white/[0.08] bg-white/[0.03] px-3 text-sm outline-none transition focus:border-[var(--accent-violet)]/50 focus:bg-white/[0.05] font-mono-tight"
                />
              </label>
            </div>
            <div className="flex items-center justify-end gap-2 border-t border-white/10 bg-white/[0.02] px-5 py-3">
              <button onClick={onClose} className="rounded-lg px-3 py-1.5 text-xs text-muted-foreground hover:bg-white/5 hover:text-foreground">
                Cancel
              </button>
              <button
                disabled={!name.trim() || create.isPending}
                onClick={() => create.mutate()}
                className="rounded-lg bg-[var(--accent-violet)] px-4 py-1.5 text-xs font-semibold text-[var(--primary-foreground)] disabled:opacity-50"
              >
                Generate
              </button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

function RevealKeyModal({ secret, onClose }: { secret: string | null; onClose: () => void }) {
  const [copied, setCopied] = useState(false);

  return (
    <AnimatePresence>
      {secret && (
        <motion.div
          className="fixed inset-0 z-50 grid place-items-center bg-black/55 px-4 backdrop-blur-md"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={onClose}
        >
          <motion.div
            initial={{ opacity: 0, y: 10, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 6, scale: 0.98 }}
            transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-md overflow-hidden rounded-2xl border border-white/10 bg-[var(--surface-2)] shadow-2xl"
          >
            <div className="flex items-center justify-between border-b border-white/10 px-5 py-4">
              <div>
                <div className="text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
                  Copy now — shown once
                </div>
                <div className="text-base font-semibold">Your new API key</div>
              </div>
              <button onClick={onClose} className="grid size-8 place-items-center rounded-lg text-muted-foreground hover:bg-white/5 hover:text-foreground">
                <X className="size-4" />
              </button>
            </div>
            <div className="space-y-3 px-5 py-5">
              <div className="flex items-center gap-2">
                <Mono className="flex-1 break-all rounded-md border border-white/10 bg-white/[0.04] px-3 py-2 text-[12px] text-foreground/90">
                  {secret}
                </Mono>
                <button
                  onClick={() => {
                    void navigator.clipboard.writeText(secret);
                    setCopied(true);
                    toast.success("API key copied");
                  }}
                  className="grid size-9 shrink-0 place-items-center rounded-lg border border-white/10 text-muted-foreground hover:bg-white/5 hover:text-foreground"
                >
                  {copied ? <Check className="size-4 text-[var(--success)]" /> : <Copy className="size-4" />}
                </button>
              </div>
              <p className="text-xs text-muted-foreground">
                This secret will not be shown again. Store it somewhere safe.
              </p>
            </div>
            <div className="flex items-center justify-end gap-2 border-t border-white/10 bg-white/[0.02] px-5 py-3">
              <button
                onClick={() => {
                  setCopied(false);
                  onClose();
                }}
                className="rounded-lg bg-[var(--accent-violet)] px-4 py-1.5 text-xs font-semibold text-[var(--primary-foreground)] hover:brightness-110"
              >
                Done
              </button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
