// Login — split hero. Left: brand panel with animated gradient mesh.
// Right: the form. No pre-filled credentials (the old UI shipped
// root/crabby in the inputs), proper labels + autocomplete.
import { motion, useReducedMotion } from "motion/react";
import { Eye, EyeOff } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router";
import { login } from "@/api/endpoints";
import { isAdminRole, sessionFromToken, setSession } from "@/lib/auth";
import { useSession } from "@/hooks/queries";
import { Field, Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

export function LoginPage() {
  const session = useSession();
  const navigate = useNavigate();
  const location = useLocation();
  const reduced = useReducedMotion();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (session) {
    return <Navigate to={isAdminRole(session.role) ? "/dashboard" : "/account"} replace />;
  }

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const res = await login(username.trim(), password);
      const s = sessionFromToken(res.token, res.role);
      if (!s) throw new Error("Received a malformed token");
      setSession(s);
      const from = (location.state as { from?: string } | null)?.from;
      navigate(from ?? (isAdminRole(s.role) ? "/dashboard" : "/account"), { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
      setBusy(false);
    }
  };

  return (
    <div className="grid min-h-dvh lg:grid-cols-[1.1fr_1fr]">
      {/* Brand panel */}
      <div className="relative hidden overflow-hidden border-r border-line lg:block">
        <div
          aria-hidden
          className="absolute inset-0"
          style={{
            background:
              "radial-gradient(800px 500px at 20% 20%, var(--accent-soft), transparent 60%)," +
              "radial-gradient(700px 500px at 80% 80%, var(--brand-soft), transparent 55%)",
          }}
        />
        <motion.div
          aria-hidden
          className="absolute -right-24 -top-24 size-96 rounded-full bg-accent-soft blur-3xl"
          animate={reduced ? undefined : { y: [0, 24, 0], x: [0, -12, 0] }}
          transition={{ duration: 14, repeat: Infinity, ease: "easeInOut" }}
        />
        <div className="relative flex h-full flex-col justify-between p-10">
          <div className="flex items-center gap-3">
            <div className="grid size-9 place-items-center rounded-xl bg-brand-soft text-lg">🦀</div>
            <span className="text-[15px] font-semibold tracking-tight">Crabby Proxy</span>
          </div>
          <div className="max-w-md">
            <motion.h1
              initial={reduced ? { opacity: 0 } : { opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
              className="text-[34px] font-semibold leading-tight tracking-tight"
            >
              Control every byte
              <br />
              that leaves your network.
            </motion.h1>
            <motion.p
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.15, duration: 0.5 }}
              className="mt-3 text-[14px] leading-relaxed text-fg-muted"
            >
              Multi-protocol egress proxy with per-user policy, live observability
              and a complete audit trail — HTTP, HTTPS, SOCKS4 and SOCKS5 on one port.
            </motion.p>
          </div>
          <div className="flex gap-6 text-[12px] text-fg-faint">
            <span>HTTP · HTTPS · SOCKS4 · SOCKS5</span>
            <span>RBAC</span>
            <span>Quotas</span>
            <span>Live feed</span>
          </div>
        </div>
      </div>

      {/* Form */}
      <div className="flex items-center justify-center p-6">
        <motion.div
          initial={reduced ? { opacity: 0 } : { opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
          className="w-full max-w-sm"
        >
          <div className="mb-8 lg:hidden">
            <div className="mb-3 grid size-10 place-items-center rounded-xl bg-brand-soft text-xl">🦀</div>
            <h1 className="text-xl font-semibold tracking-tight">Crabby Proxy</h1>
          </div>

          <h2 className="text-[20px] font-semibold tracking-tight">Welcome back</h2>
          <p className="mt-1 text-[13px] text-fg-muted">Sign in to the control plane.</p>

          <form onSubmit={onSubmit} className="mt-7 space-y-4" noValidate>
            <Field label="Username">
              {(id) => (
                <Input
                  id={id}
                  name="username"
                  autoComplete="username"
                  autoFocus
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="username"
                />
              )}
            </Field>
            <Field label="Password">
              {(id) => (
                <div className="relative">
                  <Input
                    id={id}
                    name="password"
                    type={showPw ? "text" : "password"}
                    autoComplete="current-password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    className="pr-9"
                  />
                  <button
                    type="button"
                    aria-label={showPw ? "Hide password" : "Show password"}
                    onClick={() => setShowPw((v) => !v)}
                    className="absolute right-2 top-1/2 grid size-6 -translate-y-1/2 place-items-center rounded text-fg-faint hover:text-fg"
                  >
                    {showPw ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
                  </button>
                </div>
              )}
            </Field>

            {error && (
              <motion.div
                initial={reduced ? { opacity: 0 } : { opacity: 0, x: -6 }}
                animate={reduced ? { opacity: 1 } : { opacity: 1, x: [0, -6, 6, -3, 3, 0] }}
                transition={{ duration: 0.4 }}
                role="alert"
                className="rounded-md border border-danger/25 bg-danger-soft px-3 py-2 text-[12.5px] text-danger"
              >
                {error}
              </motion.div>
            )}

            <Button
              type="submit"
              variant="primary"
              size="lg"
              className="w-full"
              disabled={!username || !password}
              loading={busy}
            >
              {busy ? "Signing in…" : "Sign in"}
            </Button>
          </form>

          <p className="mt-6 text-center text-[11.5px] text-fg-faint">
            Rate-limited · Sessions expire automatically
          </p>
        </motion.div>
      </div>
    </div>
  );
}
