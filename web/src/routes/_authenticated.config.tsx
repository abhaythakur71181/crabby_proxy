import { createFileRoute } from "@tanstack/react-router";
import { motion } from "framer-motion";
import { RefreshCw, Save } from "lucide-react";
import { useState } from "react";
import { Panel, PanelHeader } from "@/components/app/card";
import { PageHeader } from "@/components/app/page-header";
import { configSections } from "@/mock/seed";

export const Route = createFileRoute("/_authenticated/config")({
  head: () => ({ meta: [{ title: "Configuration · Crabby Proxy" }] }),
  component: ConfigPage,
});

function ConfigPage() {
  const [reloading, setReloading] = useState(false);

  async function reload() {
    setReloading(true);
    await new Promise((r) => setTimeout(r, 1200));
    setReloading(false);
  }

  return (
    <div className="mx-auto w-full max-w-[1200px] px-6 py-8 lg:px-10">
      <PageHeader
        title="Configuration"
        subtitle="Live runtime settings. Changes are validated, then applied on reload."
        action={
          <div className="flex items-center gap-2">
            <button
              onClick={reload}
              disabled={reloading}
              className="inline-flex h-10 items-center gap-2 rounded-xl border border-white/10 bg-white/[0.04] px-4 text-sm font-medium text-foreground hover:bg-white/[0.08]"
            >
              <RefreshCw className={"size-4 " + (reloading ? "animate-spin" : "")} />
              {reloading ? "Reloading…" : "Reload config"}
            </button>
            <button className="inline-flex h-10 items-center gap-2 rounded-xl bg-[var(--accent-violet)] px-4 text-sm font-semibold text-[var(--primary-foreground)] hover:brightness-110">
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
  const [val, setVal] = useState(field.value);
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
          onClick={() => setVal(on ? "false" : "true")}
          className={
            "relative h-6 w-11 rounded-full border transition " +
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
        onChange={(e) => setVal(e.target.value)}
        className="h-10 w-full rounded-xl border border-white/[0.08] bg-white/[0.03] px-3 font-mono-tight text-sm outline-none transition focus:border-[var(--accent-violet)]/50 focus:bg-white/[0.05]"
      />
    </label>
  );
}