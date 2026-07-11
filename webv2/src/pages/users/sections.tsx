// Shared per-user sections — used by the admin user-detail page and the
// self-service Account page. All identity comes from props, never from the
// admin-only user list, so these work for any role.
import { KeyRound, Plus, ShieldCheck, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { createApiKey, revokeApiKey, updateUserQuota } from "@/api/endpoints";
import { formatBytes, formatDateTime, formatRelative, protocolLabel } from "@/lib/format";
import {
  keys,
  useInvalidate,
  useUserApiKeys,
  useUserApprovals,
  useUserQuota,
  useUserUsage,
  useUserUsageRecent,
} from "@/hooks/queries";
import { Modal, ConfirmDialog } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Panel, PanelHeader } from "@/components/ui/card";
import { Field, Input } from "@/components/ui/input";
import { CopyButton, Mono, Progress } from "@/components/ui/misc";
import { Pill, ProtocolBadge, StatusPill } from "@/components/ui/badge";
import { TableShell, THead, Th, Td, TRow, TableSkeleton } from "@/components/ui/table";
import { EmptyState, ErrorState, Skeleton } from "@/components/ui/states";

// ── Quota ─────────────────────────────────────────────────────────
export function QuotaSection({ userId, canEdit }: { userId: number; canEdit: boolean }) {
  const quota = useUserQuota(userId);
  const invalidate = useInvalidate();
  const [editOpen, setEditOpen] = useState(false);
  const [gb, setGb] = useState("");

  const save = useMutation({
    mutationFn: (bytes: number | null) => updateUserQuota(userId, bytes),
    onSuccess: () => {
      toast.success("Quota updated");
      invalidate(keys.user(userId));
      setEditOpen(false);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const pct = quota.data?.percentage_used ?? null;
  const tone = pct == null ? "accent" : pct >= 95 ? "danger" : pct >= 75 ? "warning" : "accent";

  return (
    <Panel>
      <PanelHeader
        eyebrow="bandwidth"
        title="Quota"
        actions={
          canEdit && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setGb(
                  quota.data?.quota_bytes != null
                    ? String(Math.round(quota.data.quota_bytes / 1024 ** 3))
                    : "",
                );
                setEditOpen(true);
              }}
            >
              Set quota
            </Button>
          )
        }
      />
      <div className="px-4 pb-4">
        {quota.isLoading ? (
          <Skeleton className="h-16" />
        ) : quota.isError ? (
          <ErrorState className="border-0 py-4" onRetry={() => quota.refetch()} />
        ) : quota.data ? (
          <>
            <div className="flex items-baseline justify-between">
              <span className="font-mono num text-[22px] font-semibold">
                {formatBytes(quota.data.used_bytes)}
              </span>
              <span className="text-[12.5px] text-fg-muted">
                of{" "}
                {quota.data.quota_bytes != null ? formatBytes(quota.data.quota_bytes) : "unlimited"}
              </span>
            </div>
            <Progress value={pct ?? (quota.data.used_bytes > 0 ? 4 : 0)} tone={tone} className="mt-2.5" />
            <div className="mt-2 flex justify-between text-[11.5px] text-fg-faint">
              <span>{pct != null ? `${pct.toFixed(1)}% used` : "no cap set"}</span>
              {quota.data.remaining_bytes != null && (
                <span>{formatBytes(quota.data.remaining_bytes)} remaining</span>
              )}
            </div>
          </>
        ) : null}
      </div>

      <Modal
        open={editOpen}
        onOpenChange={setEditOpen}
        title="Set bandwidth quota"
        description="Empty = unlimited. Enforced at connection time."
        footer={
          <>
            <Button variant="ghost" onClick={() => setEditOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              loading={save.isPending}
              onClick={() => save.mutate(gb.trim() === "" ? null : Math.round(Number(gb) * 1024 ** 3))}
            >
              Save
            </Button>
          </>
        }
      >
        <Field label="Quota (GB)" hint="Leave empty for unlimited">
          {(id) => (
            <Input
              id={id}
              type="number"
              min={0}
              step="0.5"
              value={gb}
              onChange={(e) => setGb(e.target.value)}
              placeholder="unlimited"
              autoFocus
            />
          )}
        </Field>
      </Modal>
    </Panel>
  );
}

// ── Usage stats ───────────────────────────────────────────────────
export function UsageStatsSection({ userId }: { userId: number }) {
  const usage = useUserUsage(userId);
  return (
    <Panel>
      <PanelHeader eyebrow="last 30 days" title="Usage" />
      <div className="grid grid-cols-2 gap-3 px-4 pb-4">
        {usage.isLoading ? (
          <>
            <Skeleton className="h-14" />
            <Skeleton className="h-14" />
          </>
        ) : usage.isError ? (
          <ErrorState className="col-span-2 border-0 py-4" onRetry={() => usage.refetch()} />
        ) : (
          <>
            <MiniStat label="Connections" value={usage.data?.connection_count.toLocaleString() ?? "—"} />
            <MiniStat label="Total" value={formatBytes(usage.data?.total_bandwidth)} />
            <MiniStat label="Sent" value={formatBytes(usage.data?.bytes_sent)} />
            <MiniStat label="Received" value={formatBytes(usage.data?.bytes_received)} />
          </>
        )}
      </div>
    </Panel>
  );
}

function MiniStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-line bg-surface-2 px-3 py-2.5">
      <div className="eyebrow">{label}</div>
      <div className="mt-0.5 font-mono num text-[15px] font-semibold">{value}</div>
    </div>
  );
}

// ── API keys ──────────────────────────────────────────────────────
export function ApiKeysSection({
  userId,
  username,
  autoOpenCreate = false,
}: {
  userId: number;
  username: string;
  autoOpenCreate?: boolean;
}) {
  const list = useUserApiKeys(userId);
  const invalidate = useInvalidate();
  const [createOpen, setCreateOpen] = useState(autoOpenCreate);
  const [name, setName] = useState("");
  const [expDays, setExpDays] = useState("0");
  const [revealed, setRevealed] = useState<string | null>(null);
  const [revokeId, setRevokeId] = useState<number | null>(null);

  // The backend's api_keys.name column is NOT NULL, so a name is effectively
  // required — send a real string, never undefined.
  const create = useMutation({
    mutationFn: () =>
      createApiKey(userId, {
        name: name.trim(),
        expires_in_days: Number(expDays) || 0,
      }),
    onSuccess: (r) => {
      setRevealed(r.key);
      setName("");
      invalidate(keys.user(userId));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const revoke = useMutation({
    mutationFn: (keyId: number) => revokeApiKey(userId, keyId),
    onSuccess: () => {
      toast.success("API key revoked");
      setRevokeId(null);
      invalidate(keys.user(userId));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <Panel>
      <PanelHeader
        eyebrow="proxy auth"
        title="API keys"
        actions={
          <Button variant="primary" size="sm" onClick={() => setCreateOpen(true)}>
            <Plus className="size-3.5" /> New key
          </Button>
        }
      />
      {list.isError ? (
        <ErrorState className="mx-4 mb-4 border-0" onRetry={() => list.refetch()} />
      ) : (
        <TableShell>
          <THead>
            <Th>Name</Th>
            <Th>Key</Th>
            <Th>Status</Th>
            <Th>Last used</Th>
            <Th>Expires</Th>
            <Th aria-label="Actions" />
          </THead>
          {list.isLoading ? (
            <TableSkeleton cols={6} rows={3} />
          ) : (
            <tbody>
              {(list.data ?? []).map((k) => (
                <TRow key={k.id}>
                  <Td className="font-medium">{k.name || "(unnamed)"}</Td>
                  <Td>
                    <Mono className="text-fg-muted">{k.prefix}_••••••••</Mono>
                  </Td>
                  <Td>
                    <StatusPill
                      tone={k.is_active ? "success" : "neutral"}
                      label={k.is_active ? "Active" : "Revoked"}
                    />
                  </Td>
                  <Td className="text-fg-faint">{formatRelative(k.last_used_at)}</Td>
                  <Td className="text-fg-faint">
                    {k.expires_at ? formatDateTime(k.expires_at) : "Never"}
                  </Td>
                  <Td className="text-right">
                    <Button
                      variant="ghost"
                      size="sm"
                      aria-label={`Revoke key ${k.name || k.prefix}`}
                      className="text-danger hover:bg-danger-soft"
                      onClick={() => setRevokeId(k.id)}
                    >
                      <Trash2 className="size-3.5" />
                    </Button>
                  </Td>
                </TRow>
              ))}
            </tbody>
          )}
        </TableShell>
      )}
      {!list.isLoading && !list.isError && (list.data?.length ?? 0) === 0 && (
        <EmptyState
          icon={KeyRound}
          title="No API keys"
          description={`Keys authenticate proxy clients as ${username}@<key>.`}
          className="m-4 border-0"
        />
      )}

      {/* Create + one-time reveal */}
      <Modal
        open={createOpen}
        onOpenChange={(o) => {
          setCreateOpen(o);
          if (!o) setRevealed(null);
        }}
        title={revealed ? "Copy your key now" : "Create API key"}
        description={
          revealed
            ? "This is the only time the full key is shown."
            : `Issued to ${username}. Clients authenticate as username@key.`
        }
        footer={
          revealed ? (
            <Button
              variant="primary"
              onClick={() => {
                setCreateOpen(false);
                setRevealed(null);
              }}
            >
              Done
            </Button>
          ) : (
            <>
              <Button variant="ghost" onClick={() => setCreateOpen(false)}>
                Cancel
              </Button>
              <Button
                variant="primary"
                loading={create.isPending}
                disabled={!name.trim()}
                onClick={() => create.mutate()}
              >
                Generate
              </Button>
            </>
          )
        }
      >
        {revealed ? (
          <div className="flex items-center gap-2 rounded-lg border border-accent/30 bg-accent-soft px-3 py-3">
            <Mono className="min-w-0 flex-1 break-all text-[13px]">{revealed}</Mono>
            <CopyButton value={revealed} label="Copy key" />
          </div>
        ) : (
          <div className="space-y-4">
            <Field label="Name" hint="Required — e.g. “ci-runner”">
              {(id) => (
                <Input
                  id={id}
                  autoFocus
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="ci-runner"
                />
              )}
            </Field>
            <Field label="Expires in (days)" hint="0 = never expires">
              {(id) => (
                <Input
                  id={id}
                  type="number"
                  min={0}
                  value={expDays}
                  onChange={(e) => setExpDays(e.target.value)}
                />
              )}
            </Field>
          </div>
        )}
      </Modal>

      <ConfirmDialog
        open={revokeId != null}
        onOpenChange={(o) => !o && setRevokeId(null)}
        title="Revoke API key?"
        description="Clients using this key are rejected immediately."
        confirmLabel="Revoke"
        loading={revoke.isPending}
        onConfirm={() => revokeId != null && revoke.mutate(revokeId)}
      />
    </Panel>
  );
}

// ── Recent usage ──────────────────────────────────────────────────
export function RecentUsageSection({ userId }: { userId: number }) {
  const recent = useUserUsageRecent(userId);
  return (
    <Panel>
      <PanelHeader eyebrow="last 50 connections" title="Recent activity" />
      {recent.isError ? (
        <ErrorState className="mx-4 mb-4 border-0" onRetry={() => recent.refetch()} />
      ) : (
        <TableShell>
          <THead>
            <Th>Target</Th>
            <Th>Protocol</Th>
            <Th>Client IP</Th>
            <Th className="text-right">Transferred</Th>
            <Th>Status</Th>
            <Th>When</Th>
          </THead>
          {recent.isLoading ? (
            <TableSkeleton cols={6} rows={4} />
          ) : (
            <tbody>
              {(recent.data ?? []).slice(0, 12).map((r) => (
                <TRow key={r.id}>
                  <Td className="max-w-56 overflow-hidden text-ellipsis">
                    <Mono>{r.target_host}</Mono>
                  </Td>
                  <Td>
                    <ProtocolBadge protocol={protocolLabel(r.protocol)} />
                  </Td>
                  <Td>
                    <Mono className="text-fg-muted">{r.client_ip}</Mono>
                  </Td>
                  <Td className="text-right">
                    <Mono>{formatBytes(r.bytes_sent + r.bytes_received)}</Mono>
                  </Td>
                  <Td>
                    <Pill tone={r.status === "completed" || r.status === "success" ? "success" : r.status === "active" ? "info" : "neutral"}>
                      {r.status}
                    </Pill>
                  </Td>
                  <Td className="text-fg-faint">{formatRelative(r.started_at)}</Td>
                </TRow>
              ))}
            </tbody>
          )}
        </TableShell>
      )}
      {!recent.isLoading && !recent.isError && (recent.data?.length ?? 0) === 0 && (
        <EmptyState title="No recorded connections" className="m-4 border-0" />
      )}
    </Panel>
  );
}

// ── Approvals (grants for this user) ──────────────────────────────
export function UserApprovalsSection({ userId }: { userId: number }) {
  const approvals = useUserApprovals(userId);
  const now = Math.floor(Date.now() / 1000);
  const rows = useMemo(
    () => (approvals.data ?? []).sort((a, b) => b.approved_at - a.approved_at).slice(0, 8),
    [approvals.data],
  );
  return (
    <Panel>
      <PanelHeader eyebrow="ip grants" title="Approvals" />
      <div className="px-4 pb-4">
        {approvals.isLoading ? (
          <Skeleton className="h-16" />
        ) : approvals.isError ? (
          <ErrorState className="border-0 py-4" onRetry={() => approvals.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={ShieldCheck}
            title="No approval grants"
            className="border-0 py-6"
          />
        ) : (
          <ul className="space-y-2">
            {rows.map((a) => (
              <li
                key={a.id}
                className="flex items-center justify-between gap-3 rounded-md border border-line bg-surface-2 px-3 py-2 text-[12.5px]"
              >
                <Mono>{a.client_ip}</Mono>
                <span className="text-fg-faint">{a.duration_hours}h</span>
                <StatusPill
                  tone={a.expires_at > now ? "success" : "neutral"}
                  label={a.expires_at > now ? `expires ${formatRelative(a.expires_at)}` : "expired"}
                />
              </li>
            ))}
          </ul>
        )}
      </div>
    </Panel>
  );
}
