// Session store.
//
// The credential itself is an HttpOnly, Secure, SameSite=Strict cookie set by
// the admin API at login — script can never read it, so an XSS cannot
// exfiltrate a reusable admin token. What lives here is only the non-secret
// identity the UI needs to render (username, id, role, expiry), plus the
// per-session CSRF token, which is kept in memory only and re-fetched from
// GET /api/session after a reload.
//
// The identity is mirrored to localStorage so that (a) a reload renders
// immediately and (b) other tabs learn about sign-in / sign-out through the
// `storage` event and stay in sync.

export type Role = "root_admin" | "admin" | "user";

export interface Session {
  username: string;
  userId: number;
  role: Role;
  /** Unix seconds when the server-side session expires. */
  expiresAt: number;
}

const KEY = "cbpx2_identity";
/** Pre-cookie versions stored the raw bearer JWT here. Never read it again. */
const LEGACY_KEY = "cbpx2_session";

type Listener = () => void;
const listeners = new Set<Listener>();
let cached: Session | null | undefined;
let csrfToken: string | null = null;

function safeStorage(): Storage | null {
  try {
    return typeof window !== "undefined" ? window.localStorage : null;
  } catch {
    return null;
  }
}

// One-time purge of the old token-bearing entry left by earlier builds.
safeStorage()?.removeItem(LEGACY_KEY);

function parse(raw: string | null): Session | null {
  if (!raw) return null;
  try {
    const s = JSON.parse(raw) as Partial<Session>;
    if (
      typeof s.username !== "string" ||
      typeof s.userId !== "number" ||
      typeof s.expiresAt !== "number" ||
      !["root_admin", "admin", "user"].includes(s.role as string)
    ) {
      return null;
    }
    return s as Session;
  } catch {
    return null;
  }
}

function read(): Session | null {
  if (cached !== undefined) return cached;
  cached = parse(safeStorage()?.getItem(KEY) ?? null);
  return cached;
}

function notify() {
  listeners.forEach((l) => l());
}

export function getSession(): Session | null {
  const s = read();
  if (s && s.expiresAt * 1000 <= Date.now()) {
    clearSession();
    return null;
  }
  return s;
}

/** Identity from a login or GET /api/session response. */
export function sessionFromServer(r: {
  user_id: number;
  username: string;
  role: string;
  expires_at?: number;
}): Session {
  const role = (["root_admin", "admin", "user"].includes(r.role) ? r.role : "user") as Role;
  return {
    username: r.username,
    userId: r.user_id,
    role,
    expiresAt: r.expires_at ?? Math.floor(Date.now() / 1000) + 3600,
  };
}

export function setSession(s: Session, csrf?: string | null) {
  cached = s;
  if (csrf !== undefined) csrfToken = csrf;
  safeStorage()?.setItem(KEY, JSON.stringify(s));
  notify();
}

/** Forget the session locally (does not contact the server; see signOut). */
export function clearSession() {
  const had = cached !== null;
  cached = null;
  csrfToken = null;
  safeStorage()?.removeItem(KEY);
  if (had) notify();
}

export function getCsrfToken(): string | null {
  return csrfToken;
}

// Cross-tab sync: another tab signed in, out, or switched user. Drop the
// cached identity and the CSRF token (it belongs to whichever session the
// shared cookie now carries) and re-render.
if (typeof window !== "undefined") {
  window.addEventListener("storage", (e) => {
    if (e.key !== KEY && e.key !== null) return; // null = storage.clear()
    cached = undefined;
    csrfToken = null;
    notify();
  });
}

/** Subscribe for useSyncExternalStore. */
export function subscribeSession(l: Listener): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

export function isAdminRole(role: Role | undefined | null): boolean {
  return role === "admin" || role === "root_admin";
}
