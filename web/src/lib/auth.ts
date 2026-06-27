import type { Role } from "@/types/crabby";

const KEY = "cbpx_session";

export interface Session {
  username: string;
  role: Role;
  loggedInAt: string;
}

function inferRole(username: string): Role {
  if (username === "root" || username === "root_admin") return "root_admin";
  if (username === "falcon" || username.startsWith("admin")) return "admin";
  return "user";
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

export function signIn(username: string): Session {
  const session: Session = {
    username: username.trim() || "root",
    role: inferRole(username.trim() || "root"),
    loggedInAt: new Date().toISOString(),
  };
  window.localStorage.setItem(KEY, JSON.stringify(session));
  return session;
}

export function signOut() {
  window.localStorage.removeItem(KEY);
}