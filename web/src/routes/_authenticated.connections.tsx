import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { Cable, Copy, Search } from "lucide-react";
import { Panel } from "@/components/app/card";
import { PageHeader } from "@/components/app/page-header";
import { Pill } from "@/components/app/badge";
import { StatusDot } from "@/components/app/status-dot";
import { Mono } from "@/components/app/mono";
import { DetailDrawer } from "@/components/app/detail-drawer";
import { EmptyState } from "@/components/app/empty";
import { useLiveConnections } from "@/mock/live";
import { useConnections, useUserMap } from "@/lib/queries";
import { fmtBytes, fmtRelative } from "@/lib/format";
import type { Connection } from "@/types/crabby";

export const Route = createFileRoute("/_authenticated/connections")({
  head: () => ({ meta: [{ title: "Connections · Crabby Proxy" }] }),
  component: ConnectionsPage,
});

const PROTOCOLS = ["ALL", "HTTPS", "HTTP", "SOCKS5", "SOCKS4", "H2"] as const;

function ConnectionsPage() {
  const { connections } = useConnections();
  const { rows } = useLiveConnections(connections, 80);
  const nameOf = useUserMap();
  const [q, setQ] = useState("");
  const [proto, setProto] = useState<(typeof PROTOCOLS)[number]>("ALL");
  const [active, setActive] = useState<Connection | null>(null);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return rows.filter((r) => {
      if (proto !== "ALL" && r.protocol !== proto) return false;
      if (!needle) return true;
      return (
        r.client_ip.includes(needle) ||
        r.target_host.toLowerCase().includes(needle) ||
        r.username.toLowerCase().includes(needle)
      );
    });
  }, [rows, q, proto]);

  return (
    <div className="mx-auto w-full max-w-[1500px] px-6 py-8 lg:px-10">
      <PageHeader
        title="Connections"
        subtitle="Every active flow through the proxy, streaming in real time."
        action={
          <Pill variant="success">
            <StatusDot tone="success" /> {rows.length} live
          </Pill>
        }
      />

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="flex h-10 flex-1 items-center gap-2 rounded-xl border border-white/[0.08] bg-white/[0.03] px-3 transition focus-within:border-[var(--accent-violet)]/50">
          <Search className="size-4 text-muted-foreground" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search by IP, target or user…"
            className="h-full flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground"
          />
        </div>
        <div className="flex h-10 items-center gap-1 rounded-xl border border-white/[0.08] bg-white/[0.02] p-1">
          {PROTOCOLS.map((p) => (
            <button
              key={p}
              onClick={() => setProto(p)}
              className={
                "rounded-lg px-3 text-[11px] font-medium uppercase tracking-wider transition " +
                (proto === p
                  ? "bg-white/[0.08] text-foreground"
                  : "text-muted-foreground hover:text-foreground")
              }
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      <Panel className="overflow-hidden">
        <div className="grid grid-cols-[110px_1.2fr_1.6fr_70px_90px_110px_90px_90px] gap-3 border-b border-white/[0.06] px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          <span>ID</span>
          <span>Client</span>
          <span>Target</span>
          <span>Proto</span>
          <span>State</span>
          <span>User</span>
          <span className="text-right">Sent</span>
          <span className="text-right">Recv</span>
        </div>
        {filtered.length === 0 ? (
          <EmptyState
            icon={<Cable className="size-4" />}
            title="No connections match"
            description="Try clearing your filters or wait — the stream is live."
            className="m-6"
          />
        ) : (
          <ul className="divide-y divide-white/[0.04]">
            {filtered.slice(0, 60).map((r) => (
              <li
                key={r.id}
                onClick={() => setActive(r)}
                className="row-enter grid cursor-pointer grid-cols-[110px_1.2fr_1.6fr_70px_90px_110px_90px_90px] items-center gap-3 px-5 py-2.5 text-xs transition hover:bg-white/[0.03]"
              >
                <Mono className="truncate text-[11px] text-muted-foreground">{r.id.slice(0, 10)}</Mono>
                <Mono className="truncate text-[11px] text-foreground/90">
                  {r.client_ip}:{r.client_port}
                </Mono>
                <Mono className="truncate text-[11px] text-foreground/70">
                  {r.target_host}:{r.target_port}
                </Mono>
                <Pill variant="mono">{r.protocol}</Pill>
                <span className="flex items-center gap-1.5 text-[11px]">
                  <StatusDot tone="success" /> active
                </span>
                <span className="truncate text-[11px] text-foreground/80">{nameOf(r.user_id)}</span>
                <Mono className="text-right text-[11px]">{fmtBytes(r.bytes_sent)}</Mono>
                <Mono className="text-right text-[11px]">{fmtBytes(r.bytes_received)}</Mono>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <DetailDrawer
        open={!!active}
        onClose={() => setActive(null)}
        eyebrow="Connection"
        title={active ? `${active.client_ip}:${active.client_port}` : ""}
      >
        {active && (
          <div className="space-y-5">
            <DetailRow label="ID" value={<Mono className="text-xs">{active.id}</Mono>} copy />
            <DetailRow
              label="Target"
              value={<Mono className="text-xs">{active.target_host}:{active.target_port}</Mono>}
            />
            <DetailRow label="Protocol" value={<Pill variant="mono">{active.protocol}</Pill>} />
            <DetailRow label="User" value={<span className="text-sm">{nameOf(active.user_id)}</span>} />
            <DetailRow label="Started" value={<span className="text-sm">{fmtRelative(active.started_at)}</span>} />
            <div className="grid grid-cols-2 gap-3">
              <Metric label="Sent" value={fmtBytes(active.bytes_sent)} />
              <Metric label="Received" value={fmtBytes(active.bytes_received)} />
              <Metric label="Latency" value={`${active.latency_ms} ms`} />
              <Metric label="State" value={active.state} />
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}

function DetailRow({ label, value, copy }: { label: string; value: React.ReactNode; copy?: boolean }) {
  return (
    <div>
      <div className="mb-1 text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
        {label}
      </div>
      <div className="flex items-center justify-between gap-2">
        {value}
        {copy && (
          <button className="grid size-6 place-items-center rounded text-muted-foreground hover:bg-white/5 hover:text-foreground">
            <Copy className="size-3" />
          </button>
        )}
      </div>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
      <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
        {label}
      </div>
      <Mono className="mt-1 text-sm">{value}</Mono>
    </div>
  );
}