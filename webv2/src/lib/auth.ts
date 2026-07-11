// Session store. The login response carries no user id, but the JWT does —
// claims are { sub: username, user_id, role, exp, iat }. Decoding the token
// gives every page (including non-admin self-service) a reliable identity
// without needing the admin-only user list, which is what broke the old UI's
// API-keys page for regular users.

export type Role = "root_admin" | "admin" | "user";

export interface Session {
  token: string;
  username: string;
  userId: number;
  role: Role;
  /** Unix seconds when the JWT expires. */
  expiresAt: number;
}

const KEY = "cbpx2_session";

interface JwtClaims {
  sub?: string;
  user_id?: number;
  role?: string;
  exp?: number;
}

function decodeJwt(token: string): JwtClaims | null {
  try {
    const payload = token.split(".")[1];
    if (!payload) return null;
    const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
    return JSON.parse(json) as JwtClaims;
  } catch {
    return null;
  }
}

export function sessionFromToken(token: string, fallbackRole: Role): Session | null {
  const claims = decodeJwt(token);
  if (!claims || claims.user_id == null || !claims.sub) return null;
  const role = (["root_admin", "admin", "user"].includes(claims.role ?? "")
    ? claims.role
    : fallbackRole) as Role;
  return {
    token,
    username: claims.sub,
    userId: claims.user_id,
    role,
    expiresAt: claims.exp ?? Math.floor(Date.now() / 1000) + 3600,
  };
}

type Listener = () => void;
const listeners = new Set<Listener>();
let cached: Session | null | undefined;

function read(): Session | null {
  if (cached !== undefined) return cached;
  try {
    const raw = localStorage.getItem(KEY);
    cached = raw ? (JSON.parse(raw) as Session) : null;
  } catch {
    cached = null;
  }
  return cached;
}

export function getSession(): Session | null {
  const s = read();
  if (s && s.expiresAt * 1000 <= Date.now()) {
    clearSession();
    return null;
  }
  return s;
}

export function getToken(): string | null {
  return getSession()?.token ?? null;
}

export function setSession(s: Session) {
  cached = s;
  localStorage.setItem(KEY, JSON.stringify(s));
  listeners.forEach((l) => l());
}

export function clearSession() {
  cached = null;
  localStorage.removeItem(KEY);
  listeners.forEach((l) => l());
}

/** Subscribe for useSyncExternalStore. */
export function subscribeSession(l: Listener): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

export function isAdminRole(role: Role | undefined | null): boolean {
  return role === "admin" || role === "root_admin";
}
