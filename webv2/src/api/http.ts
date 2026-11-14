// Fetch core. Base URL from VITE_API_BASE_URL (scheme auto-prepended) or
// same-origin. Authentication is the HttpOnly session cookie set by the admin
// API (sent via `credentials: "include"`); this module never sees a token.
// State-changing requests carry the per-session CSRF token in X-CSRF-Token.
// A 401 clears the session and sends the router to /login (soft navigation
// via a registered handler, not a hard reload, so app state and the toast
// survive).

import {
  clearSession,
  getCsrfToken,
  getSession,
  sessionFromServer,
  setSession,
} from "@/lib/auth";

function normalizeBase(raw: string | undefined): string {
  const v = (raw ?? "").trim().replace(/\/+$/, "");
  if (!v) return "";
  if (/^https?:\/\//i.test(v)) return v;
  // Default a scheme-less base to https:// — never downgrade the session cookie
  // to cleartext. Warn in dev so the missing scheme is caught before deploy.
  if (import.meta.env.DEV) {
    console.warn(
      `VITE_API_BASE_URL "${v}" has no scheme; defaulting to https://. Set an explicit scheme.`,
    );
  }
  return `https://${v}`;
}

export const API_BASE = normalizeBase(import.meta.env.VITE_API_BASE_URL as string | undefined);

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

let onUnauthorized: (() => void) | null = null;
/** The router registers a soft-redirect here at boot. */
export function registerUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn;
}

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

interface SessionWire {
  user_id: number;
  username: string;
  role: string;
  expires_at?: number;
  csrf_token?: string;
}

let refreshing: Promise<boolean> | null = null;

/**
 * Re-read the session from the server (GET /api/session): refreshes the
 * identity and recovers the in-memory CSRF token after a reload or a sign-in
 * in another tab. Resolves false (and clears local state) when the cookie is
 * missing or revoked.
 */
export function refreshSession(): Promise<boolean> {
  refreshing ??= (async () => {
    try {
      const res = await fetch(`${API_BASE}/api/session`, {
        credentials: "include",
        cache: "no-store",
      });
      if (!res.ok) {
        if (res.status === 401) clearSession();
        return false;
      }
      const body = (await res.json()) as SessionWire;
      setSession(sessionFromServer(body), body.csrf_token ?? null);
      return true;
    } catch {
      return false;
    } finally {
      refreshing = null;
    }
  })();
  return refreshing;
}

/** Revoke the server session, clear the cookie, and forget it locally. */
export async function signOut(): Promise<void> {
  // Clear locally first so the UI (and, via the storage event, other tabs)
  // leaves the app immediately; the HttpOnly cookie still rides along on the
  // logout request below.
  clearSession();
  try {
    await fetch(`${API_BASE}/api/logout`, { method: "POST", credentials: "include" });
  } catch {
    // Offline: the server session still expires on its own.
  }
}

async function send(path: string, init: RequestInit): Promise<Response> {
  const method = (init.method ?? "GET").toUpperCase();
  const headers: Record<string, string> = {
    ...(init.body ? { "Content-Type": "application/json" } : {}),
    ...(init.headers as Record<string, string> | undefined),
  };
  if (!SAFE_METHODS.has(method)) {
    if (!getCsrfToken() && getSession() && !path.startsWith("/api/login")) {
      await refreshSession();
    }
    const csrf = getCsrfToken();
    if (csrf) headers["X-CSRF-Token"] = csrf;
  }
  try {
    return await fetch(`${API_BASE}${path}`, { ...init, headers, credentials: "include" });
  } catch {
    throw new ApiError(0, "Network error — is the admin API reachable?");
  }
}

export async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  let res = await send(path, init);

  // A stale CSRF token (e.g. another tab signed in again, replacing the shared
  // cookie) gets one transparent refresh-and-retry.
  const method = (init.method ?? "GET").toUpperCase();
  if (res.status === 403 && !SAFE_METHODS.has(method) && !path.startsWith("/api/login")) {
    const before = getCsrfToken();
    if ((await refreshSession()) && getCsrfToken() !== before) {
      res = await send(path, init);
    }
  }

  if (res.status === 401 && !path.startsWith("/api/login")) {
    clearSession();
    onUnauthorized?.();
    throw new ApiError(401, "Session expired — sign in again");
  }

  if (!res.ok) {
    // Error body is {error, detail} everywhere except /api/login (plain text).
    let msg = `Request failed (${res.status})`;
    const text = await res.text().catch(() => "");
    if (text) {
      try {
        const body = JSON.parse(text) as { error?: string; detail?: string };
        msg = body.error ?? body.detail ?? text;
      } catch {
        msg = text;
      }
    }
    throw new ApiError(res.status, msg);
  }

  if (res.status === 204) return undefined as T;
  const text = await res.text();
  if (!text) return undefined as T;
  return JSON.parse(text) as T;
}

export const get = <T>(path: string) => request<T>(path);
export const post = <T>(path: string, body?: unknown) =>
  request<T>(path, { method: "POST", ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
export const put = <T>(path: string, body: unknown) =>
  request<T>(path, { method: "PUT", body: JSON.stringify(body) });
export const del = <T>(path: string, body?: unknown) =>
  request<T>(path, { method: "DELETE", ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });

/** ws(s):// URL for the live feed from a one-time ticket. */
export function liveSocketUrl(ticket: string): string {
  const origin = API_BASE || window.location.origin;
  return `${origin.replace(/^http/, "ws")}/api/connections/live?ticket=${encodeURIComponent(ticket)}`;
}
