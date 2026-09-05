export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/**
 * Resolve the control-plane base URL.
 * Development may use localhost. Production / non-local hosts fail closed
 * when NEXT_PUBLIC_API_URL is missing (no silent localhost fallback).
 */
export function getApiUrl(): string {
  const configured = process.env.NEXT_PUBLIC_API_URL?.trim();
  if (configured) {
    return configured.replace(/\/$/, "");
  }

  const vercelEnv = process.env.NEXT_PUBLIC_VERCEL_ENV ?? process.env.VERCEL_ENV;
  const onVercelProduction = vercelEnv === "production";
  const onBrowserRemote =
    typeof window !== "undefined" &&
    window.location.hostname !== "localhost" &&
    window.location.hostname !== "127.0.0.1";

  if (onVercelProduction || onBrowserRemote) {
    throw new ApiError(
      503,
      "API_URL_MISSING",
      "NEXT_PUBLIC_API_URL is required in production. Set it to the Railway HTTPS API URL.",
    );
  }

  return "http://127.0.0.1:8080";
}

export function getSession() {
  if (typeof window === "undefined") return null;
  const token = localStorage.getItem("btos.token");
  const tenantId = localStorage.getItem("btos.tenant");
  if (!token || !tenantId) return null;
  return { token, tenantId };
}

export function setSession(token: string, tenantId: string) {
  localStorage.setItem("btos.token", token);
  localStorage.setItem("btos.tenant", tenantId);
}

export function clearSession() {
  localStorage.removeItem("btos.token");
  localStorage.removeItem("btos.tenant");
}

export async function api<T>(path: string, init: RequestInit = {}, authed = true): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");
  if (authed) {
    const session = getSession();
    if (!session) throw new ApiError(401, "UNAUTHORIZED", "Not signed in");
    headers.set("Authorization", `Bearer ${session.token}`);
    headers.set("X-Tenant-ID", session.tenantId);
  }
  const response = await fetch(`${getApiUrl()}${path}`, { ...init, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new ApiError(
      response.status,
      data?.error?.code ?? "HTTP_ERROR",
      data?.error?.message ?? response.statusText,
    );
  }
  return data as T;
}
