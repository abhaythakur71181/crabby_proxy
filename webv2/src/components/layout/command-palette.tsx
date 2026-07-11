// ⌘K command palette (cmdk). Navigation, actions with WORKING deep links
// (pages read the ?new=1 search param), user jump for admins, theme.
import { Command } from "cmdk";
import {
  Activity,
  ArrowLeftRight,
  BarChart3,
  Cable,
  CircleUser,
  FileClock,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Moon,
  Plus,
  RefreshCw,
  Settings2,
  ShieldCheck,
  Sun,
  UserRound,
  UsersRound,
  Waypoints,
} from "lucide-react";
import { useEffect, useState, useSyncExternalStore } from "react";
import { useNavigate } from "react-router";
import { toast } from "sonner";
import { reloadConfig } from "@/api/endpoints";
import { clearSession } from "@/lib/auth";
import { useIsAdmin, useUsers } from "@/hooks/queries";
import { useTheme } from "@/hooks/use-theme";
import { RoleBadge } from "@/components/ui/badge";

// Tiny external store so any component (topbar) can open the palette.
let isOpen = false;
const listeners = new Set<() => void>();
export function openPalette() {
  isOpen = true;
  listeners.forEach((l) => l());
}
function setOpen(v: boolean) {
  isOpen = v;
  listeners.forEach((l) => l());
}
function usePaletteOpen() {
  return useSyncExternalStore(
    (l) => {
      listeners.add(l);
      return () => listeners.delete(l);
    },
    () => isOpen,
  );
}

const PAGES = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard, admin: true },
  { to: "/connections", label: "Connections", icon: Waypoints, admin: true },
  { to: "/tunnels", label: "Tunnels", icon: Cable, admin: true },
  { to: "/usage", label: "Usage analytics", icon: BarChart3, admin: true },
  { to: "/users", label: "Users", icon: UsersRound, admin: true },
  { to: "/groups", label: "Groups", icon: ArrowLeftRight, admin: true },
  { to: "/approvals", label: "Approvals", icon: ShieldCheck, admin: false },
  { to: "/audit", label: "Audit log", icon: FileClock, admin: true },
  { to: "/system-health", label: "System health", icon: Activity, admin: true },
  { to: "/config", label: "Configuration", icon: Settings2, admin: true },
  { to: "/account", label: "My account", icon: CircleUser, admin: false },
];

export function CommandPalette() {
  const open = usePaletteOpen();
  const [query, setQuery] = useState("");
  const navigate = useNavigate();
  const isAdmin = useIsAdmin();
  const { setTheme } = useTheme();
  // Only fetch the user directory when the palette is open and admin.
  const users = useUsers(200, 0, isAdmin && open);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen(!isOpen);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    if (!open) setQuery("");
  }, [open]);

  const go = (fn: () => void) => {
    setOpen(false);
    fn();
  };

  return (
    <Command.Dialog
      open={open}
      onOpenChange={setOpen}
      label="Command palette"
      className="fixed left-1/2 top-[18vh] z-[70] w-[min(600px,calc(100vw-2rem))] -translate-x-1/2 overflow-hidden rounded-xl border border-line glass shadow-pop"
      overlayClassName="fixed inset-0 z-[65] bg-black/40 backdrop-blur-[2px]"
    >
      <Command.Input
        value={query}
        onValueChange={setQuery}
        placeholder="Type a command or search…"
        className="h-12 w-full border-b border-line bg-transparent px-4 text-[14px] text-fg placeholder:text-fg-faint focus:outline-none"
      />
      <Command.List className="max-h-[50vh] overflow-y-auto p-1.5 [&_[cmdk-group-heading]]:px-2.5 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-[10.5px] [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-[0.08em] [&_[cmdk-group-heading]]:text-fg-faint">
        <Command.Empty className="px-3 py-6 text-center text-[13px] text-fg-muted">
          No results.
        </Command.Empty>

        <Command.Group heading="Go to">
          {PAGES.filter((p) => !p.admin || isAdmin).map((p) => (
            <Item key={p.to} onSelect={() => go(() => navigate(p.to))}>
              <p.icon className="size-4 text-fg-faint" />
              {p.label}
            </Item>
          ))}
        </Command.Group>

        <Command.Group heading="Actions">
          {isAdmin && (
            <Item onSelect={() => go(() => navigate("/users?new=1"))}>
              <Plus className="size-4 text-fg-faint" /> Create user…
            </Item>
          )}
          <Item onSelect={() => go(() => navigate("/account?new-key=1"))}>
            <KeyRound className="size-4 text-fg-faint" /> Create API key…
          </Item>
          <Item onSelect={() => go(() => navigate("/approvals?request=1"))}>
            <ShieldCheck className="size-4 text-fg-faint" /> Request access…
          </Item>
          {isAdmin && (
            <Item
              onSelect={() =>
                go(() => {
                  toast.promise(reloadConfig(), {
                    loading: "Reloading configuration…",
                    success: (r) => r.message,
                    error: (e: Error) => e.message,
                  });
                })
              }
            >
              <RefreshCw className="size-4 text-fg-faint" /> Reload configuration
            </Item>
          )}
          <Item onSelect={() => go(() => setTheme("dark"))}>
            <Moon className="size-4 text-fg-faint" /> Dark theme
          </Item>
          <Item onSelect={() => go(() => setTheme("light"))}>
            <Sun className="size-4 text-fg-faint" /> Light theme
          </Item>
          <Item
            onSelect={() =>
              go(() => {
                clearSession();
                navigate("/login");
              })
            }
          >
            <LogOut className="size-4 text-fg-faint" /> Sign out
          </Item>
        </Command.Group>

        {isAdmin && query.length > 0 && (users.data?.items.length ?? 0) > 0 && (
          <Command.Group heading="Users">
            {users.data!.items.slice(0, 8).map((u) => (
              <Item key={u.id} value={`user-${u.username}`} onSelect={() => go(() => navigate(`/users/${u.id}`))}>
                <UserRound className="size-4 text-fg-faint" />
                {u.username}
                <span className="ml-auto">
                  <RoleBadge role={u.role} />
                </span>
              </Item>
            ))}
          </Command.Group>
        )}
      </Command.List>
    </Command.Dialog>
  );
}

function Item({
  children,
  onSelect,
  value,
}: {
  children: React.ReactNode;
  onSelect: () => void;
  value?: string;
}) {
  return (
    <Command.Item
      value={value}
      onSelect={onSelect}
      className="flex cursor-pointer items-center gap-2.5 rounded-md px-2.5 py-2 text-[13px] outline-none data-[selected=true]:bg-accent-soft data-[selected=true]:text-fg"
    >
      {children}
    </Command.Item>
  );
}
