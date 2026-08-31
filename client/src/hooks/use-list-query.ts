import { useQuery, type UseQueryOptions } from "@tanstack/react-query";
import { buildUrl } from "@/lib/queryClient";

/**
 * The envelope every paginated list endpoint returns.
 * See `PaginatedResult` in server/storage.ts.
 */
export interface ListEnvelope<T> {
  data: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface ListResult<T> {
  /** The rows on this page — at most `limit` of them. */
  items: T[];
  /**
   * The number of rows that match the query on the server, which is NOT
   * `items.length` once the result exceeds one page. Always use this for a
   * displayed count; using `items.length` silently reports the page size.
   */
  total: number;
  /** True when the server holds more rows than this page returned. */
  truncated: boolean;
  limit: number;
  offset: number;
  isLoading: boolean;
  isError: boolean;
  error: Error | null;
}

/** Normalizes both the paginated envelope and a bare array into one shape. */
export function normalizeList<T>(payload: unknown): ListEnvelope<T> {
  if (Array.isArray(payload)) {
    return { data: payload as T[], total: payload.length, limit: payload.length, offset: 0 };
  }
  if (payload && typeof payload === "object") {
    const env = payload as Partial<ListEnvelope<T>>;
    if (Array.isArray(env.data)) {
      const data = env.data;
      return {
        data,
        total: typeof env.total === "number" ? env.total : data.length,
        limit: typeof env.limit === "number" ? env.limit : data.length,
        offset: typeof env.offset === "number" ? env.offset : 0,
      };
    }
  }
  return { data: [], total: 0, limit: 0, offset: 0 };
}

/**
 * Fetches a paginated list endpoint and preserves the server's `total`.
 *
 * The default query function in `queryClient` unwraps the envelope down to the
 * array, which loses `total` — so a page rendering `items.length` as a count
 * reports the page size (500) rather than the real number of rows. This hook
 * keeps both, and callers should render `total`.
 */
export function useListQuery<T>(
  path: string | null,
  options?: Omit<UseQueryOptions<ListEnvelope<T>, Error>, "queryKey" | "queryFn">,
): ListResult<T> {
  const query = useQuery<ListEnvelope<T>, Error>({
    ...options,
    queryKey: [path ?? "__disabled__"],
    enabled: (options?.enabled ?? true) && !!path,
    queryFn: async () => {
      const token = localStorage.getItem("auth_token");
      const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};
      const res = await fetch(buildUrl(path!), { headers, credentials: "include" });
      if (!res.ok) throw new Error(`Request failed (${res.status})`);
      const text = await res.text();
      if (!text.trim()) return { data: [], total: 0, limit: 0, offset: 0 };
      return normalizeList<T>(JSON.parse(text));
    },
  });

  const env = query.data ?? { data: [], total: 0, limit: 0, offset: 0 };
  return {
    items: env.data,
    total: env.total,
    truncated: env.total > env.data.length + env.offset,
    limit: env.limit,
    offset: env.offset,
    isLoading: query.isLoading,
    isError: query.isError,
    error: query.error ?? null,
  };
}
