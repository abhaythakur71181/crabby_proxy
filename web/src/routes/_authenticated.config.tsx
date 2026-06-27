import { createFileRoute } from "@tanstack/react-router";
import { motion } from "framer-motion";
import { RefreshCw, Save } from "lucide-react";
import { Panel, PanelHeader } from "@/components/app/card";
import { PageHeader } from "@/components/app/page-header";
import { api, useConfig, useMutation } from "@/lib/queries";
import { toast } from "sonner";

export const Route = createFileRoute("/_authenticated/config")({
  head: () => ({ meta: [{ title: "Configuration · Crabby Proxy" }] }),
  component: ConfigPage,
});

function ConfigPage() {
  const { data } = useConfig();

  const reloadMutation = useMutation({
    mutationFn: () => api.reloadConfig(),
    onSuccess: (r) => toast.success(r?.message || "Configuration reloaded"),
    onError: (e) => toast.error(e instanceof Error ? e.message : "Failed to reload config"),
  });
  const reloading = reloadMutation.isPending;

  const configSections = [
    {
      id: "server",
      title: "Server",
      description: "Listeners and connection limits.",
      fields: [
        { key: "server.proxy_bind", label: "Proxy bind", value: data?.server?.proxy_bind ?? "—", type: "text" },
        { key: "server.admin_bind", label: "Admin bind", value: data?.server?.admin_bind ?? "—", type: "text" },
        { key: "server.max_connections", label: "Max connections", value: String(data?.server?.max_connections ?? "—"), type: "number" },
      ],
    },
    {
      id: "auth",
      title: "Authentication",
      description: "Identity and access controls.",
      fields: [
        { key: "authentication.enabled", label: "Authentication enabled", value: String(data?.authentication?.enabled ?? false), type: "switch" },
      ],
    },
    {
      id: "features",
      title: "Features",
      description: "Optional runtime capabilities.",
      fields: [
        { key: "features.connection_approval", label: "Connection approval", value: String(data?.features?.connection_approval ?? false), type: "switch" },
        { key: "features.reverse_tunnels", label: "Reverse tunnels", value: String(data?.features?.reverse_tunnels ?? false), type: "switch" },
      ],
    },
  ];

  return (
    <div className="mx-auto w-full max-w-[1200px] px-6 py-8 lg:px-10">
      <PageHeader
        title="Configuration"
        subtitle="Live runtime settings. Changes are validated, then applied on reload."
        action={
          <div className="flex items-center gap-2">
            <button
              onClick={() => reloadMutation.mutate()}
              disabled={reloading}
              className="inline-flex h-10 items-center gap-2 rounded-xl border border-white/10 bg-white/[0.04] px-4 text-sm font-medium text-foreground hover:bg-white/[0.08]"
            >
              <RefreshCw className={"size-4 " + (reloading ? "animate-spin" : "")} />
              {reloading ? "Reloading…" : "Reload config"}
            </button>
            <button
              disabled
              className="inline-flex h-10 items-center gap-2 rounded-xl bg-[var(--accent-violet)] px-4 text-sm font-semibold text-[var(--primary-foreground)] opacity-50 cursor-not-allowed"
            >
              <Save className="size-4" /> Save changes
            </button>
          </div>
        }
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {configSections.map((s, idx) => (
          <motion.div key={s.id} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: idx * 0.05 }}>
            <Panel>
              <PanelHeader title={s.title} hint={s.description} />
              <div className="space-y-3 p-5">
                {s.fields.map((f) => (
                  <FieldRow key={f.key} field={f} />
                ))}
              </div>
            </Panel>
          </motion.div>
        ))}
      </div>
    </div>
  );
}

function FieldRow({ field }: { field: { key: string; label: string; value: string; type: string } }) {
  const val = field.value;
  if (field.type === "switch") {
    const on = val === "true";
    return (
      <div className="flex items-center justify-between gap-4 py-1">
        <div>
          <div className="text-sm">{field.label}</div>
          <div className="text-[10px] font-mono-tight text-muted-foreground">{field.key}</div>
        </div>
        <button
          aria-pressed={on}
          disabled
          className={
            "relative h-6 w-11 cursor-not-allowed rounded-full border transition " +
            (on ? "border-[var(--accent-violet)] bg-[var(--accent-violet)]/30" : "border-white/10 bg-white/[0.04]")
          }
        >
          <motion.span
            layout
            transition={{ type: "spring", stiffness: 500, damping: 30 }}
            className={
              "absolute top-0.5 size-5 rounded-full bg-white shadow " +
              (on ? "right-0.5" : "left-0.5")
            }
          />
        </button>
      </div>
    );
  }
  return (
    <label className="block">
      <div className="mb-1 flex items-center justify-between">
        <span className="text-xs text-foreground">{field.label}</span>
        <span className="font-mono-tight text-[10px] text-muted-foreground">{field.key}</span>
      </div>
      <input
        value={val}
        readOnly
        className="h-10 w-full rounded-xl border border-white/[0.08] bg-white/[0.03] px-3 font-mono-tight text-sm outline-none transition focus:border-[var(--accent-violet)]/50 focus:bg-white/[0.05]"
      />
    </label>
  );
}