// Live connections — WS+poll hybrid feed with per-row transfer rates,
// protocol/search filters, a detail drawer, and the terminate action the
// old UI never wired up.
import { AnimatePresence, motion } from "motion/react";
import { Unplug, Waypoints } from "lucide-react";
import { useMemo, useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { terminateConnection } from "@/api/endpoints";
import type { ConnectionInfo } from "@/api/types";
import { formatBytes, formatRate, formatRelative, splitHostPort } from "@/lib/format";
import { cn } from "@/lib/utils";
import { useInvalidate, useUserDirectory, keys } from "@/hooks/queries";
import { useLiveConnections, type LiveConnection } from "@/hooks/use-live-connections";
import { AnimatedNumber } from "@/components/motion";
import { ConfirmDialog, Drawer } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Panel } from "@/components/ui/card";
import { ProtocolBadge, StatusPill } from "@/components/ui/badge";
import { CopyableMono, Mono, SearchInput } from "@/components/ui/misc";
import { TableShell, THead, Th, Td, TRow, TableSkeleton } from "@/components/ui/table";
import { EmptyState, ErrorState } from "@/components/ui/states";

const PROTO_FILTERS = ["ALL", "HTTPS", "HTTP", "HTTP2", "SOCKS5", "SOCKS4", "TCP"] as const;

export function ConnectionsPage() {
  const { connections, socketState, isLoading, isError, refetch } = useLiveConnections();
  const resolveUser = useUserDirectory();
  const invalidate = useInvalidate();
  const [query, setQuery] = useState("");
  const [proto, setProto] = useState<(typeof PROTO_FILTERS)[number]>("ALL");
  const [selected, setSelected] = useState<LiveConnection | null>(null);
  const [confirmKill, setConfirmKill] = useState<ConnectionInfo | null>(null);

  // Track ids we've seen so only genuinely new rows animate in.
  const seenIds = useRef(new Set<string>());
  const newIds = useMemo(() => {
    const fresh = new Set<string>();
    for (const c of connections) {
      if (!seenIds.current.has(c.id)) {
        fresh.add(c.id);
        seenIds.current.add(c.id);
      }
    }
    return fresh;
  }, [connections]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return connections.filter((c) => {
      if (proto !== "ALL" && c.protocol.toUpperCase() !== proto) return false;
      if (!q) return true;
      return (
        c.client_addr.toLowerCase().includes(q) ||
        c.target_addr.toLowerCase().includes(q) ||
        resolveUser(c.user_id).toLowerCase().includes(q) ||
        c.id.toLowerCase().includes(q)
      );
    });
  }, [connections, query, proto, resolveUser]);

  const kill = useMutation({
    mutationFn: (id: string) => terminateConnection(id),
    onSuccess: () => {
      toast.success("Connection terminated");
      setConfirmKill(null);
      setSelected(null);
      invalidate(keys.connections);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const totalRate = filtered.reduce((s, c) => s + c.rate_bps, 0);

  return (
    <div className="space-y-4">
      {/* Header row */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-baseline gap-2">
          <AnimatedNumber value={filtered.length} className="font-mono num text-[22px] font-semibold" />
          <span className="text-[13px] text-fg-muted">active</span>
        </div>
        <StatusPill
          tone={socketState === "live" ? "success" : socketState === "polling" ? "warning" : "info"}
          label={
            socketState === "live"
              ? "live stream"
              : socketState === "reconnecting"
                ? "reconnecting…"
                : socketState === "polling"
                  ? "polling fallback"
                  : "connecting…"
          }
          pulse={socketState === "live"}
        />
        {totalRate > 0 && <Mono className="text-fg-faint">{formatRate(totalRate)} aggregate</Mono>}
        <div className="ml-auto w-full sm:w-64">
          <SearchInput
            placeholder="Filter by IP, target, user…"
            aria-label="Filter connections"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
      </div>

      {/* Protocol chips */}
      <div className="flex flex-wrap gap-1.5" role="group" aria-label="Protocol filter">
        {PROTO_FILTERS.map((p) => (
          <button
            key={p}
            type="button"
            onClick={() => setProto(p)}
            aria-pressed={proto === p}
            className={cn(
              "rounded-full border px-3 py-1 text-[12px] font-medium transition-all",
              proto === p
                ? "border-accent/40 bg-accent-soft text-accent"
                : "border-line-strong text-fg-muted hover:bg-surface-2 hover:text-fg",
            )}
          >
            {p === "ALL" ? "All" : p === "HTTP2" ? "HTTP/2" : p}
          </button>
        ))}
      </div>

      <Panel>
        {isError ? (
          <ErrorState
            title="Couldn't load connections"
            onRetry={() => refetch()}
            className="m-4 border-0"
          />
        ) : (
          <TableShell>
            <THead>
              <Th>Client</Th>
              <Th>Target</Th>
              <Th>Protocol</Th>
              <Th>User</Th>
              <Th className="text-right">Transferred</Th>
              <Th className="text-right">Rate</Th>
              <Th>Age</Th>
              <Th aria-label="Actions" />
            </THead>
            {isLoading ? (
              <TableSkeleton cols={8} />
            ) : (
              <tbody>
                <AnimatePresence initial={false}>
                  {filtered.slice(0, 200).map((c) => {
                    const client = splitHostPort(c.client_addr);
                    const target = splitHostPort(c.target_addr);
                    return (
                      <TRow
                        key={c.id}
                        onActivate={() => setSelected(c)}
                        entering={newIds.has(c.id)}
                      >
                        <Td>
                          <Mono>{client.host}</Mono>
                          <Mono className="text-fg-faint">:{client.port}</Mono>
                        </Td>
                        <Td className="max-w-56 overflow-hidden text-ellipsis">
                          <Mono>{target.host}</Mono>
                          <Mono className="text-fg-faint">:{target.port}</Mono>
                        </Td>
                        <Td>
                          <ProtocolBadge protocol={c.protocol} />
                        </Td>
                        <Td className="text-fg-muted">{resolveUser(c.user_id)}</Td>
                        <Td className="text-right">
                          <Mono>{formatBytes(c.bytes_sent + c.bytes_received)}</Mono>
                        </Td>
                        <Td className="text-right">
                          <Mono className={c.rate_bps > 0 ? "text-accent" : "text-fg-faint"}>
                            {c.rate_bps > 0 ? formatRate(c.rate_bps) : "idle"}
                          </Mono>
                        </Td>
                        <Td className="text-fg-faint">{formatRelative(c.created_at)}</Td>
                        <Td className="text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            aria-label={`Terminate connection to ${target.host}`}
                            onClick={(e) => {
                              e.stopPropagation();
                              setConfirmKill(c);
                            }}
                            className="text-danger hover:bg-danger-soft"
                          >
                            <Unplug className="size-3.5" />
                          </Button>
                        </Td>
                      </TRow>
                    );
                  })}
                </AnimatePresence>
              </tbody>
            )}
          </TableShell>
        )}
        {!isLoading && !isError && filtered.length === 0 && (
          <EmptyState
            icon={Waypoints}
            title={connections.length === 0 ? "No active connections" : "Nothing matches the filter"}
            description={
              connections.length === 0
                ? "Connections appear here in real time as clients use the proxy."
                : "Try a different search or protocol filter."
            }
            className="m-4 border-0"
          />
        )}
      </Panel>

      {/* Detail drawer */}
      <Drawer
        open={selected != null}
        onOpenChange={(o) => !o && setSelected(null)}
        title={selected ? splitHostPort(selected.target_addr).host : ""}
        description="Connection detail"
        footer={
          selected && (
            <Button
              variant="danger"
              onClick={() => setConfirmKill(selected)}
              loading={kill.isPending}
            >
              <Unplug className="size-3.5" /> Terminate connection
            </Button>
          )
        }
      >
        {selected && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <DrawerStat label="Sent" value={formatBytes(selected.bytes_sent)} />
              <DrawerStat label="Received" value={formatBytes(selected.bytes_received)} />
              <DrawerStat
                label="Rate"
                value={selected.rate_bps > 0 ? formatRate(selected.rate_bps) : "idle"}
              />
              <DrawerStat label="State" value={selected.state} />
            </div>
            <dl className="space-y-2.5 border-t border-line pt-4 text-[13px]">
              <DrawerRow label="Connection ID">
                <CopyableMono value={selected.id} display={`${selected.id.slice(0, 13)}…`} />
              </DrawerRow>
              <DrawerRow label="Client">
                <CopyableMono value={selected.client_addr} />
              </DrawerRow>
              <DrawerRow label="Target">
                <CopyableMono value={selected.target_addr} />
              </DrawerRow>
              <DrawerRow label="Protocol">
                <ProtocolBadge protocol={selected.protocol} />
              </DrawerRow>
              <DrawerRow label="User">{resolveUser(selected.user_id)}</DrawerRow>
              <DrawerRow label="Started">{formatRelative(selected.created_at)}</DrawerRow>
            </dl>
          </div>
        )}
      </Drawer>

      {/* Terminate confirm */}
      <ConfirmDialog
        open={confirmKill != null}
        onOpenChange={(o) => !o && setConfirmKill(null)}
        title="Terminate connection?"
        description={
          confirmKill
            ? `${splitHostPort(confirmKill.client_addr).host} → ${confirmKill.target_addr}`
            : undefined
        }
        confirmLabel="Terminate"
        loading={kill.isPending}
        onConfirm={() => confirmKill && kill.mutate(confirmKill.id)}
      >
        <p className="text-[13px] text-fg-muted">
          The relay is severed immediately. The client can reconnect unless you also revoke
          its access.
        </p>
      </ConfirmDialog>
    </div>
  );
}

function DrawerStat({ label, value }: { label: string; value: string }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-lg border border-line bg-surface-2 px-3 py-2.5"
    >
      <div className="eyebrow">{label}</div>
      <div className="mt-1 font-mono num text-[16px] font-semibold">{value}</div>
    </motion.div>
  );
}

function DrawerRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <dt className="text-fg-faint">{label}</dt>
      <dd className="min-w-0 text-right">{children}</dd>
    </div>
  );
}
