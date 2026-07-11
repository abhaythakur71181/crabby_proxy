// Fetch core. Base URL from VITE_API_BASE_URL (scheme auto-prepended) or
// same-origin. Bearer token attached from the session store; a 401 clears the
// session and sends the router to /login (soft navigation via a registered
// handler, not a hard reload, so app state and the toast survive).

import { clearSession, getToken } from "@/lib/auth";

function normalizeBase(raw: string | undefined): string {
  const v = (raw ?? "").trim().replace(/\/+$/, "");
  if (!v) return "";
  if (/^https?:\/\//i.test(v)) return v;
  return `http://${v}`;
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

export async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = {
    ...(init.body ? { "Content-Type": "application/json" } : {}),
    ...(init.headers as Record<string, string> | undefined),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, { ...init, headers });
  } catch {
    throw new ApiError(0, "Network error — is the admin API reachable?");
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
