/**
 * The list-envelope unwrap in `getQueryFn`.
 *
 * This codebase has TWO pagination conventions, and the unwrap originally named
 * only one. `parsePagination` produces `{ data, total, limit, offset }`;
 * `parsePageParams` — which the findings inbox uses — produces
 * `{ data, total, page, pageSize, totalPages }` with no `offset`. Requiring
 * `offset` handed that second shape to the component as an OBJECT, and the
 * first thing a list page does with it is `.filter`.
 *
 * The symptom is not a bad list. It is `x.filter is not a function` thrown
 * during render, which the error boundary turns into a full-page
 * "Something went wrong" — every other working thing on the page gone with it.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import { getQueryFn } from "../../../client/src/lib/queryClient";

const store = new Map<string, string>();
const originalFetch = globalThis.fetch;

beforeEach(() => {
  store.clear();
  (globalThis as { localStorage?: unknown }).localStorage = {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, v),
    removeItem: (k: string) => void store.delete(k),
  };
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  vi.restoreAllMocks();
});

/** Drives the real query function against a stubbed response body. */
async function fetchWith(body: unknown): Promise<unknown> {
  globalThis.fetch = vi.fn(async () => ({
    status: 200,
    ok: true,
    text: async () => JSON.stringify(body),
  })) as unknown as typeof fetch;

  const fn = getQueryFn<unknown>({ on401: "throw" });
  return fn({ queryKey: ["/api/whatever"] } as never);
}

const ROWS = [{ id: "a" }, { id: "b" }];

describe("paginated envelope unwrapping", () => {
  it("unwraps the limit/offset convention", async () => {
    const out = await fetchWith({ data: ROWS, total: 2, limit: 500, offset: 0 });
    expect(out).toEqual(ROWS);
  });

  /**
   * The regression. `/api/workspaces/:id/findings?page=1&pageSize=50` returns
   * this shape, and it reached components unwrapped.
   */
  it("unwraps the page/pageSize convention, which has no offset", async () => {
    const out = await fetchWith({ data: ROWS, total: 2, page: 1, pageSize: 50, totalPages: 1 });
    expect(out).toEqual(ROWS);
    expect(Array.isArray(out)).toBe(true);
  });

  it("returns a bare array untouched", async () => {
    expect(await fetchWith(ROWS)).toEqual(ROWS);
  });

  /**
   * The unwrap must stay narrow. `GET /findings/export-data` answers
   * `{ findings, modules, workspaceName }` and a scan answers an object with a
   * `summary`; unwrapping anything with a `data` key would silently replace a
   * domain object with whichever array it happened to carry.
   */
  it("does NOT unwrap a domain object that merely has a data field", async () => {
    const payload = { data: ROWS, workspaceName: "acme" };
    expect(await fetchWith(payload)).toEqual(payload);
  });

  it("does not unwrap an object with pagination keys but no data array", async () => {
    const payload = { total: 7, page: 1 };
    expect(await fetchWith(payload)).toEqual(payload);
  });

  it("passes a plain object through", async () => {
    const payload = { id: "x", status: "running" };
    expect(await fetchWith(payload)).toEqual(payload);
  });

  it("treats an empty body as an empty list", async () => {
    globalThis.fetch = vi.fn(async () => ({
      status: 200, ok: true, text: async () => "",
    })) as unknown as typeof fetch;
    const fn = getQueryFn<unknown>({ on401: "throw" });
    expect(await fn({ queryKey: ["/api/whatever"] } as never)).toEqual([]);
  });
});
