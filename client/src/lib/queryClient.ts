import { QueryClient, QueryFunction } from "@tanstack/react-query";

const API_BASE = (typeof import.meta !== "undefined" && import.meta.env?.VITE_API_BASE) || "";

async function throwIfResNotOk(res: Response) {
  if (!res.ok) {
    const text = (await res.text()) || res.statusText;
    throw new Error(`${res.status}: ${text}`);
  }
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
      headers: data ? { "Content-Type": "application/json" } : {},
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
      headers: data ? { "Content-Type": "application/json" } : {},
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
      credentials: "include",
    });

    if (unauthorizedBehavior === "returnNull" && res.status === 401) {
      return null;
    }

    await throwIfResNotOk(res);
    const text = await res.text();
    if (!text || text.trim() === "") {
      return [];
    }
    try {
      return JSON.parse(text);
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
