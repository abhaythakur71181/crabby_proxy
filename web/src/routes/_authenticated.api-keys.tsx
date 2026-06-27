import { createFileRoute } from "@tanstack/react-router";
import { Copy, KeyRound, Plus } from "lucide-react";
import { Panel } from "@/components/app/card";
import { PageHeader } from "@/components/app/page-header";
import { Pill } from "@/components/app/badge";
import { StatusDot } from "@/components/app/status-dot";
import { Mono } from "@/components/app/mono";
import { apiKeys } from "@/mock/seed";
import { fmtRelative } from "@/lib/format";

export const Route = createFileRoute("/_authenticated/api-keys")({
  head: () => ({ meta: [{ title: "API Keys · Crabby Proxy" }] }),
  component: ApiKeysPage,
});

function ApiKeysPage() {
  return (
    <div className="mx-auto w-full max-w-[1300px] px-6 py-8 lg:px-10">
      <PageHeader
        title="API Keys"
        subtitle="Programmatic access for clients. Keys are write-once — copy them now or rotate."
        action={
          <button className="inline-flex h-10 items-center gap-2 rounded-xl bg-[var(--accent-violet)] px-4 text-sm font-semibold text-[var(--primary-foreground)] hover:brightness-110">
            <Plus className="size-4" /> Generate key
          </button>
        }
      />
      <Panel>
        <div className="grid grid-cols-[40px_1fr_1.4fr_120px_120px_100px] gap-3 border-b border-white/[0.06] px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          <span>#</span><span>Label</span><span>Token</span><span>Owner</span><span>Last used</span><span>Status</span>
        </div>
        <ul className="divide-y divide-white/[0.04]">
          {apiKeys.map((k, i) => (
            <li key={k.id} className="grid grid-cols-[40px_1fr_1.4fr_120px_120px_100px] items-center gap-3 px-5 py-3 text-sm transition hover:bg-white/[0.03]">
              <Mono className="text-[11px] text-muted-foreground">{i + 1}</Mono>
              <div className="flex items-center gap-2"><KeyRound className="size-3.5 text-muted-foreground" /><span className="font-medium">{k.name}</span></div>
              <div className="flex items-center gap-2">
                <Mono className="rounded-md border border-white/10 bg-white/[0.04] px-2 py-1 text-[11px] text-foreground/80">{k.prefix}_{"•".repeat(12)}</Mono>
                <button className="grid size-6 place-items-center rounded text-muted-foreground hover:bg-white/5 hover:text-foreground"><Copy className="size-3" /></button>
              </div>
              <span className="text-xs">{k.username}</span>
              <span className="text-xs text-muted-foreground">{fmtRelative(k.last_used_at)}</span>
              <Pill variant="success"><StatusDot tone="success" /> active</Pill>
            </li>
          ))}
        </ul>
      </Panel>
    </div>
  );
}
