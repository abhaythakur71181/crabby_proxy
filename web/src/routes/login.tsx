import { createFileRoute, useRouter } from "@tanstack/react-router";
import { motion } from "framer-motion";
import { Eye, EyeOff, Loader2 } from "lucide-react";
import { useState } from "react";
import { signIn } from "@/lib/auth";
import { Mono } from "@/components/app/mono";

export const Route = createFileRoute("/login")({
  head: () => ({
    meta: [
      { title: "Sign in · Crabby Proxy" },
      { name: "description", content: "Sign in to the Crabby Proxy control plane." },
    ],
  }),
  component: LoginPage,
});

function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("root");
  const [password, setPassword] = useState("crabby");
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await signIn(username, password);
      router.navigate({ to: "/dashboard" });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign in failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="relative grid min-h-dvh place-items-center overflow-hidden px-4">
      <BackgroundFx />
      <motion.div
        initial={{ opacity: 0, y: 16, scale: 0.98 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
        className="relative z-10 w-full max-w-[420px] overflow-hidden rounded-3xl border border-white/[0.08] bg-[color-mix(in_oklab,var(--surface)_70%,transparent)] p-8 shadow-[0_40px_80px_-20px_rgba(0,0,0,0.7)] backdrop-blur-2xl"
      >
        <div className="absolute inset-0 -z-10 bg-[radial-gradient(120%_60%_at_50%_-10%,var(--accent-violet-soft),transparent_70%)]" />

        <div className="flex items-center gap-3">
          <motion.div
            animate={{ rotate: [0, -6, 6, -3, 0] }}
            transition={{ duration: 1.8, repeat: Infinity, repeatDelay: 4 }}
            className="grid size-11 place-items-center rounded-2xl bg-gradient-to-br from-[var(--accent-violet)] to-[oklch(0.55_0.22_300)] text-lg shadow-[0_10px_30px_-8px_var(--accent-violet)]"
          >
            🦀
          </motion.div>
          <div>
            <h1 className="text-base font-semibold tracking-tight">Crabby Proxy</h1>
            <div className="text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
              Control Plane
            </div>
          </div>
        </div>

        <p className="mt-6 text-[13px] text-muted-foreground">
          Sign in to manage users, observe live traffic, and gate egress.
        </p>

        <form onSubmit={onSubmit} className="mt-6 space-y-4">
          <Field label="Username">
            <input
              autoFocus
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full bg-transparent text-sm font-mono-tight outline-none placeholder:text-muted-foreground"
              placeholder="root_admin"
            />
          </Field>

          <Field label="Password">
            <div className="flex w-full items-center gap-2">
              <input
                type={show ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="flex-1 bg-transparent text-sm font-mono-tight outline-none placeholder:text-muted-foreground"
                placeholder="••••••••"
              />
              <button
                type="button"
                aria-label={show ? "Hide password" : "Show password"}
                onClick={() => setShow((s) => !s)}
                className="grid size-7 place-items-center rounded-md text-muted-foreground hover:bg-white/5 hover:text-foreground"
              >
                {show ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
              </button>
            </div>
          </Field>

          <motion.button
            whileTap={{ scale: 0.98 }}
            disabled={busy}
            className="group relative mt-2 flex h-11 w-full items-center justify-center gap-2 overflow-hidden rounded-xl bg-[var(--accent-violet)] text-sm font-semibold text-[var(--primary-foreground)] shadow-[0_10px_30px_-8px_var(--accent-violet)] transition hover:brightness-110 disabled:opacity-80"
          >
            <span className="absolute inset-0 -translate-x-full bg-gradient-to-r from-transparent via-white/30 to-transparent transition-transform duration-700 group-hover:translate-x-full" />
            {busy ? (
              <>
                <Loader2 className="size-4 animate-spin" />
                <span>Authenticating…</span>
              </>
            ) : (
              <span>Sign in</span>
            )}
          </motion.button>

          {error && (
            <motion.p
              initial={{ opacity: 0, x: [-6, 6, -4, 4, 0] }}
              animate={{ opacity: 1, x: 0 }}
              className="text-center text-[12px] text-[var(--accent-rose,#f43f5e)]"
              role="alert"
            >
              {error}
            </motion.p>
          )}
        </form>

        <div className="mt-6 flex items-center justify-between text-[11px] text-muted-foreground">
          <span>
            Try <Mono className="text-foreground/80">root</Mono> /{" "}
            <Mono className="text-foreground/80">crabby</Mono>
          </span>
          <span className="font-mono-tight text-[10px] uppercase tracking-widest">
            v0.1.0
          </span>
        </div>
      </motion.div>

      <div className="absolute bottom-6 z-10 text-[11px] text-muted-foreground">
        Powered by <span className="text-foreground/70">Rust 🦀</span>
      </div>
    </main>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
        {label}
      </div>
      <div className="flex h-11 items-center rounded-xl border border-white/[0.08] bg-white/[0.03] px-3 transition focus-within:border-[var(--accent-violet)]/50 focus-within:bg-white/[0.05]">
        {children}
      </div>
    </label>
  );
}

function BackgroundFx() {
  return (
    <>
      <div className="absolute inset-0 -z-10 bg-[radial-gradient(80rem_50rem_at_50%_-20%,oklch(0.68_0.22_295/0.18),transparent_60%)]" />
      <div className="absolute inset-0 -z-10 [background-image:linear-gradient(transparent_95%,oklch(1_0_0/0.04)_95%),linear-gradient(90deg,transparent_95%,oklch(1_0_0/0.04)_95%)] [background-size:48px_48px] [mask-image:radial-gradient(60rem_40rem_at_50%_30%,#000,transparent_70%)]" />
    </>
  );
}