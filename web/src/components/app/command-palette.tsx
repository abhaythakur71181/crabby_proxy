import { Command } from "cmdk";
import { AnimatePresence, motion } from "framer-motion";
import {
  BarChart3,
  Cable,
  Cog,
  FolderTree,
  HeartPulse,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Plus,
  RefreshCw,
  ScrollText,
  Search,
  ShieldCheck,
  Users,
  Waypoints,
} from "lucide-react";
import { useEffect } from "react";
import { useRouter } from "@tanstack/react-router";
import { useUsers } from "@/lib/queries";
import { isAdmin } from "@/lib/auth";
import { Kbd } from "./mono";
import { signOut } from "@/lib/auth";
import { useSyncExternalStore } from "react";

type PaletteState = {
  isOpen: boolean;
  open: () => void;
  close: () => void;
  toggle: () => void;
};

let state = { isOpen: false };
const listeners = new Set<() => void>();
function emit() {
  listeners.forEach((l) => l());
}
const api: PaletteState = {
  get isOpen() {
    return state.isOpen;
  },
  open: () => {
    state = { isOpen: true };
    emit();
  },
  close: () => {
    state = { isOpen: false };
    emit();
  },
  toggle: () => {
    state = { isOpen: !state.isOpen };
    emit();
  },
};

function subscribe(l: () => void) {
  listeners.add(l);
  return () => listeners.delete(l);
}

function useCommandPaletteImpl<T = PaletteState>(
  selector: (s: PaletteState) => T = (s) => s as unknown as T,
): T {
  return useSyncExternalStore(
    subscribe,
    () => selector(api),
    () => selector(api),
  );
}
export const useCommandPalette = Object.assign(useCommandPaletteImpl, {
  getState: () => api,
});

export function CommandPalette() {
  const isOpen = useCommandPalette((s) => s.isOpen);
  const close = useCommandPalette((s) => s.close);
  const router = useRouter();
  // Real users for fuzzy jump (admins only — non-admins can't list users).
  const admin = isAdmin();
  const { users } = useUsers();
  const userResults = admin ? users : [];

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        useCommandPalette.getState().toggle();
      }
      if (e.key === "Escape") useCommandPalette.getState().close();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const go = (to: string) => {
    close();
    router.navigate({ to });
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          className="fixed inset-0 z-[60] grid place-items-start justify-center bg-black/50 px-4 pt-[14vh] backdrop-blur-md"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.18 }}
          onClick={close}
        >
          <motion.div
            initial={{ opacity: 0, scale: 0.96, y: -6 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.97, y: -4 }}
            transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
            className="w-full max-w-xl overflow-hidden rounded-2xl border border-white/10 bg-[color-mix(in_oklab,var(--surface-2)_92%,transparent)] shadow-[0_30px_80px_-10px_rgba(0,0,0,0.7)] backdrop-blur-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <Command label="Command Menu">
              <div className="flex items-center gap-3 border-b border-white/10 px-4">
                <Search className="size-4 text-muted-foreground" />
                <Command.Input
                  autoFocus
                  placeholder="Jump to a page, find a user, run an action…"
                  className="h-12 w-full bg-transparent text-sm text-foreground placeholder:text-muted-foreground focus:outline-none"
                />
                <Kbd>esc</Kbd>
              </div>
              <Command.List className="max-h-[440px] overflow-y-auto p-2">
                <Command.Empty className="px-4 py-10 text-center text-sm text-muted-foreground">
                  No results.
                </Command.Empty>
                <CmdGroup heading="Navigation">
                  <CmdItem icon={LayoutDashboard} onSelect={() => go("/dashboard")}>Dashboard</CmdItem>
                  <CmdItem icon={Cable} onSelect={() => go("/connections")}>Connections</CmdItem>
                  <CmdItem icon={Users} onSelect={() => go("/users")}>Users</CmdItem>
                  <CmdItem icon={FolderTree} onSelect={() => go("/groups")}>Groups</CmdItem>
                  <CmdItem icon={KeyRound} onSelect={() => go("/api-keys")}>API Keys</CmdItem>
                  <CmdItem icon={BarChart3} onSelect={() => go("/usage")}>Usage & Quotas</CmdItem>
                  <CmdItem icon={ShieldCheck} onSelect={() => go("/approvals")}>Approvals</CmdItem>
                  <CmdItem icon={Waypoints} onSelect={() => go("/tunnels")}>Tunnels</CmdItem>
                  <CmdItem icon={ScrollText} onSelect={() => go("/audit")}>Audit Log</CmdItem>
                  <CmdItem icon={HeartPulse} onSelect={() => go("/health")}>System Health</CmdItem>
                  <CmdItem icon={Cog} onSelect={() => go("/config")}>Configuration</CmdItem>
                </CmdGroup>
                <CmdGroup heading="Actions">
                  <CmdItem icon={Plus} onSelect={() => go("/users?new=1")}>Create user…</CmdItem>
                  <CmdItem icon={Plus} onSelect={() => go("/api-keys?new=1")}>Create API key…</CmdItem>
                  <CmdItem icon={RefreshCw} onSelect={() => go("/config")}>Reload configuration</CmdItem>
                  <CmdItem icon={LogOut} onSelect={() => { signOut(); go("/login"); }}>Sign out</CmdItem>
                </CmdGroup>
                <CmdGroup heading="Users">
                  {userResults.map((u) => (
                    <CmdItem key={u.id} icon={Users} onSelect={() => go(`/users?id=${u.id}`)}>
                      <span className="text-foreground">{u.username}</span>
                      <span className="ml-2 text-[10px] uppercase tracking-wider text-muted-foreground">
                        {u.role}
                      </span>
                    </CmdItem>
                  ))}
                </CmdGroup>
              </Command.List>
              <div className="flex items-center justify-between border-t border-white/10 bg-white/[0.02] px-4 py-2 text-[10px] uppercase tracking-wider text-muted-foreground">
                <span className="flex items-center gap-2">
                  <Kbd>↑</Kbd>
                  <Kbd>↓</Kbd>
                  navigate
                </span>
                <span className="flex items-center gap-2">
                  <Kbd>↵</Kbd>
                  select
                </span>
              </div>
            </Command>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

function CmdGroup({ heading, children }: { heading: string; children: React.ReactNode }) {
  return (
    <Command.Group
      heading={heading}
      className="px-1 py-1 text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground [&_[cmdk-group-heading]]:px-3 [&_[cmdk-group-heading]]:py-2"
    >
      {children}
    </Command.Group>
  );
}

function CmdItem({
  icon: Icon,
  children,
  onSelect,
}: {
  icon: React.ComponentType<{ className?: string }>;
  children: React.ReactNode;
  onSelect: () => void;
}) {
  return (
    <Command.Item
      onSelect={onSelect}
      className="group flex cursor-pointer items-center gap-3 rounded-lg px-3 py-2 text-sm text-foreground/80 transition data-[selected=true]:bg-[var(--accent-violet-soft)] data-[selected=true]:text-foreground"
    >
      <Icon className="size-4 text-muted-foreground group-data-[selected=true]:text-[var(--accent-violet)]" />
      <span className="flex-1 truncate text-sm">{children}</span>
    </Command.Item>
  );
}