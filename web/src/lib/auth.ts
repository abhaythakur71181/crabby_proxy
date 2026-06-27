import type { Role } from "@/types/crabby";
import { login as apiLogin } from "./api";

const KEY = "cbpx_session";

export interface Session {
  username: string;
  role: Role;
  token: string;
  loggedInAt: string;
}

export function getSession(): Session | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return null;
    return JSON.parse(raw) as Session;
  } catch {
    return null;
  }
}

export function getToken(): string | null {
  return getSession()?.token ?? null;
}

export function isAdmin(): boolean {
  const r = getSession()?.role;
  return r === "admin" || r === "root_admin";
}

/// Routes only admins (admin/root_admin) may see. Everything else (approvals,
/// own api-keys) is available to any authenticated user. Backend enforces this
/// too (403s non-admins); this keeps the UI from showing admin pages/nav.
export const ADMIN_ONLY_PREFIXES = [
  "/dashboard",
  "/connections",
  "/tunnels",
  "/users",
  "/groups",
  "/usage",
  "/audit",
  "/health",
  "/config",
];

export function isAdminPath(pathname: string): boolean {
  return ADMIN_ONLY_PREFIXES.some((p) => pathname === p || pathname.startsWith(p + "/"));
}

/// Authenticate against the backend and persist the session (JWT + role).
export async function signIn(username: string, password: string): Promise<Session> {
  const res = await apiLogin(username.trim(), password);
  const session: Session = {
    username: username.trim(),
    role: res.role,
    token: res.token,
    loggedInAt: new Date().toISOString(),
  };
  window.localStorage.setItem(KEY, JSON.stringify(session));
  return session;
}

export function clearSession() {
  if (typeof window !== "undefined") window.localStorage.removeItem(KEY);
}

export function signOut() {
  clearSession();
}
