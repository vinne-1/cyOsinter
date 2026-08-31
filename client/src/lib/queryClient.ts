import { QueryClient, QueryFunction } from "@tanstack/react-query";

const API_BASE = (typeof import.meta !== "undefined" && import.meta.env?.VITE_API_BASE) || "";

/** Extract a human-readable message from an API error response.
 * Handles both { error: "..." } and { message: "..." } JSON envelopes.
 */
export function parseApiError(status: number, text: string): string {
  try {
    const json = JSON.parse(text);
    if (json && typeof json === "object") {
      const msg = (json as Record<string, unknown>).error ?? (json as Record<string, unknown>).message;
      if (typeof msg === "string" && msg.length > 0) return msg;
    }
  } catch {
    // not JSON — use raw text
  }
  return text || `Request failed (${status})`;
}

/**
 * An API failure that keeps its HTTP status.
 *
 * The UI has to tell a wrong password (401) from a locked account or a rate
 * limit (429) — they need completely different wording, and one of them needs a
 * countdown. A bare Error message string cannot carry that.
 */
export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    /** Seconds until the caller may retry, from the RateLimit-Reset header. */
    readonly retryAfterSeconds?: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

function retryAfterFrom(res: Response): number | undefined {
  // Retry-After is seconds; RateLimit-Reset is also seconds under the
  // standardHeaders draft. Either is fine, both are optional.
  const raw = res.headers.get("retry-after") ?? res.headers.get("ratelimit-reset");
  if (!raw) return undefined;
  const n = Number(raw);
  // Zero means "no wait known", not "retry in 0 seconds" — a limiter that is
  // not the thing blocking you still stamps its own window reset on the
  // response, and RateLimit-Reset: 0 is what that looks like.
  return Number.isFinite(n) && n > 0 ? Math.ceil(n) : undefined;
}

async function throwIfResNotOk(res: Response) {
  if (!res.ok) {
    const text = (await res.text()) || res.statusText;
    throw new ApiError(parseApiError(res.status, text), res.status, retryAfterFrom(res));
  }
}

function authHeaders(): Record<string, string> {
  const token = localStorage.getItem("auth_token");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export function buildUrl(path: string): string {
  const base = API_BASE.replace(/\/$/, "");
  const p = path.startsWith("/") ? path : `/${path}`;
  return base ? `${base}${p}` : p;
}

export interface ApiRequestOptions {
  /** Timeout in ms. For long-running requests (e.g. AI insights), use 360000 (6 min). */
  timeoutMs?: number;
}

export async function apiRequest(
  method: string,
  url: string,
  data?: unknown | undefined,
  options?: ApiRequestOptions,
): Promise<Response> {
  const fullUrl = buildUrl(url);
  const { timeoutMs } = options ?? {};
  const controller = timeoutMs ? new AbortController() : undefined;
  const timeoutId = controller && timeoutMs ? setTimeout(() => controller.abort(), timeoutMs) : undefined;
  let res: Response;
  try {
    res = await fetch(fullUrl, {
      method,
      headers: { ...authHeaders(), ...(data ? { "Content-Type": "application/json" } : {}) },
      body: data ? JSON.stringify(data) : undefined,
      credentials: "include",
      signal: controller?.signal,
    });
  } catch (err) {
    if (timeoutId) clearTimeout(timeoutId);
    const msg = err instanceof Error ? err.message : String(err);
    const isAbort = err instanceof Error && err.name === "AbortError";
    if (isAbort || msg.toLowerCase().includes("aborted")) {
      throw new Error(
        "Request timed out. AI insights can take up to 30 minutes. Ensure Ollama is running and try again.",
      );
    }
    if (msg.includes("fetch") || msg.includes("network") || msg.includes("Failed to fetch")) {
      throw new Error(
        "Connection failed. Ensure the server is running. If the request was running for a while, it may have timed out—AI insights can take up to 30 minutes.",
      );
    }
    throw err;
  }
  if (timeoutId) clearTimeout(timeoutId);
  await throwIfResNotOk(res);
  return res;
}

/**
 * Download a server-generated file (CSV/XLSX/DOCX export) with authentication.
 * A plain <a href> navigation cannot send the Authorization header, so those
 * downloads would 401; this fetches the file with auth, then triggers a
 * client-side download from the blob.
 */
export async function downloadAuthed(path: string, filename: string, options?: ApiRequestOptions): Promise<void> {
  const res = await apiRequest("GET", path, undefined, options);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Use for endpoints where we must not parse the body as JSON (e.g. purge). Consumes body and throws if it looks like HTML. */
export async function apiRequestNoParse(
  method: string,
  url: string,
  data?: unknown | undefined,
): Promise<void> {
  const fullUrl = buildUrl(url);
  let res: Response;
  try {
    res = await fetch(fullUrl, {
      method,
      headers: { ...authHeaders(), ...(data ? { "Content-Type": "application/json" } : {}) },
      body: data ? JSON.stringify(data) : undefined,
      credentials: "include",
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes("fetch") || msg.includes("network") || msg.includes("Failed to fetch")) {
      throw new Error("Network error. Ensure the server is running and reachable.");
    }
    throw err;
  }
  await throwIfResNotOk(res);
  const text = await res.text();
  if (text.trimStart().toLowerCase().startsWith("<!")) {
    throw new Error("Server returned a page instead of the API. Rebuild and restart the app.");
  }
}

let sessionExpiryHandled = false;
/**
 * On session expiry (a 401 while a token is stored), clear the stale token and
 * redirect to the sign-in page once. No-op if no token was present (e.g. a
 * warmup probe) or already on the auth page, so it never interferes with login.
 */
function handleSessionExpiry(): void {
  if (typeof window === "undefined" || sessionExpiryHandled) return;
  const hadToken = !!localStorage.getItem("auth_token");
  if (!hadToken || window.location.pathname.startsWith("/auth")) return;
  sessionExpiryHandled = true;
  localStorage.removeItem("auth_token");
  localStorage.removeItem("refresh_token");
  window.location.assign("/auth?expired=1");
}

type UnauthorizedBehavior = "returnNull" | "throw";
export const getQueryFn: <T>(options: {
  on401: UnauthorizedBehavior;
}) => QueryFunction<T> =
  ({ on401: unauthorizedBehavior }) =>
  async ({ queryKey }) => {
    const baseUrl = queryKey[0] as string;
    const params = queryKey[1] as Record<string, string | undefined> | undefined;
    let path = baseUrl;
    if (params && typeof params === "object") {
      const searchParams = new URLSearchParams();
      for (const [key, value] of Object.entries(params)) {
        if (value !== undefined && value !== null) {
          searchParams.set(key, value);
        }
      }
      const qs = searchParams.toString();
      if (qs) path = `${baseUrl}?${qs}`;
    }
    const url = buildUrl(path);
    const res = await fetch(url, {
      headers: authHeaders(),
      credentials: "include",
    });

    if (res.status === 401) {
      // A data query 401 while we hold a token means the session expired — send
      // the user to sign-in instead of silently rendering blank empty states.
      handleSessionExpiry();
      if (unauthorizedBehavior === "returnNull") return null;
    }

    await throwIfResNotOk(res);
    const text = await res.text();
    if (!text || text.trim() === "") {
      return [];
    }
    try {
      const json = JSON.parse(text);
      // Auto-unwrap paginated envelope: { data: [...], total, limit, offset }
      if (json && typeof json === "object" && Array.isArray(json.data) && "total" in json && "offset" in json) {
        return json.data;
      }
      return json;
    } catch {
      throw new Error(`Invalid JSON from ${url}`);
    }
  };

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      queryFn: getQueryFn({ on401: "throw" }),
      refetchInterval: false,
      refetchOnWindowFocus: false,
      staleTime: 30000,
      retry: false,
    },
    mutations: {
      retry: false,
    },
  },
});
