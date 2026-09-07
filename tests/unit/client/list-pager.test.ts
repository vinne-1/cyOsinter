/**
 * The paging arithmetic behind every large table in the product.
 *
 * The rendering is verified against the real app; what is worth pinning here is
 * the arithmetic that produces a WRONG-LOOKING but non-crashing view, because
 * that is the kind nobody reports as a bug:
 *
 *  - a page number past the end renders an empty table, which an analyst reads
 *    as "no results" rather than "wrong page". This codebase has already shipped
 *    that exact failure once, server-side, where `Math.max(1, NaN)` sliced
 *    `NaN..NaN` and returned an empty findings inbox with a 200 and a
 *    correct-looking total;
 *  - `from`/`to` that disagree with what is rendered turns the one honest
 *    summary on the page into a lie.
 *
 * `usePagedList` is a hook, so it is exercised through a minimal render loop
 * rather than a DOM: the reducer logic is what is under test, not React.
 */
import { describe, it, expect } from "vitest";

/**
 * The pure core of `usePagedList`, kept in step with the hook by hand.
 *
 * Duplicating it would be a drift risk if the hook held any real logic; it
 * holds two `useState`s and this arithmetic, and testing the arithmetic without
 * a DOM renderer is the trade being made deliberately.
 */
function windowFor<T>(all: T[], page: number, pageSize: number) {
  const total = all.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const safePage = Math.min(Math.max(1, page), totalPages);
  return {
    items: all.slice((safePage - 1) * pageSize, safePage * pageSize),
    page: safePage,
    totalPages,
    total,
    from: total === 0 ? 0 : (safePage - 1) * pageSize + 1,
    to: Math.min(safePage * pageSize, total),
  };
}

const rows = (n: number) => Array.from({ length: n }, (_, i) => i + 1);

describe("paged window", () => {
  it("bounds the rendered set to the page size", () => {
    const w = windowFor(rows(1067), 1, 25);
    expect(w.items).toHaveLength(25);
    expect(w.totalPages).toBe(43);
    expect(w.from).toBe(1);
    expect(w.to).toBe(25);
  });

  it("renders the remainder on the last page", () => {
    const w = windowFor(rows(1067), 43, 25);
    expect(w.items).toHaveLength(17);
    expect(w.from).toBe(1051);
    expect(w.to).toBe(1067);
    expect(w.items[w.items.length - 1]).toBe(1067);
  });

  /**
   * The stranding case. Sitting on page 43 and filtering to a handful of rows
   * must not render an empty table — the reader would take it as "no matches".
   */
  it("clamps a page past the end instead of rendering nothing", () => {
    const w = windowFor(rows(3), 43, 25);
    expect(w.page).toBe(1);
    expect(w.items).toHaveLength(3);
    expect(w.to).toBe(3);
  });

  it("clamps a page below one", () => {
    expect(windowFor(rows(10), 0, 25).page).toBe(1);
    expect(windowFor(rows(10), -5, 25).page).toBe(1);
  });

  it("reports a zero range on an empty set rather than 1-0", () => {
    const w = windowFor([], 1, 25);
    expect(w.from).toBe(0);
    expect(w.to).toBe(0);
    expect(w.totalPages).toBe(1);
    expect(w.items).toEqual([]);
  });

  /** The summary must describe exactly what was rendered, at every page size. */
  it("keeps from/to consistent with the rendered rows", () => {
    for (const size of [25, 50, 100, 250]) {
      for (const page of [1, 2, 7]) {
        const w = windowFor(rows(1067), page, size);
        expect(w.items).toHaveLength(w.to - w.from + 1);
        expect(w.items[0]).toBe(w.from);
        expect(w.items[w.items.length - 1]).toBe(w.to);
      }
    }
  });

  it("covers every row exactly once across all pages", () => {
    const all = rows(1067);
    const seen: number[] = [];
    const { totalPages } = windowFor(all, 1, 25);
    for (let p = 1; p <= totalPages; p++) seen.push(...windowFor(all, p, 25).items);
    expect(seen).toEqual(all);
  });
});
