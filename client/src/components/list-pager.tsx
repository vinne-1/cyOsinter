/**
 * Client-side paging for lists that are already fully loaded.
 *
 * These pages fetch the whole set on purpose — they filter, sort and count in
 * the browser, so a server page would change the ANSWERS (see the EASM asset
 * fix in CLAUDE.md). But "fetch it all" and "render it all" are different
 * decisions, and conflating them is how a table ends up emitting 1,067 rows:
 * slow to paint, impossible to scan, and every row past the first twenty is
 * scrolled past rather than read.
 *
 * So the data stays complete and the VIEW is paged. Filtering still searches
 * every row; only the rendered window is bounded.
 *
 * The reset-on-change behaviour is the part worth keeping. Filtering while on
 * page 8 of 12 leaves the reader on a page that no longer exists, and an empty
 * table after typing a search term reads as "no matches" rather than "wrong
 * page" — a bug this codebase has already seen in its server pagination
 * (`Math.max(1, NaN)` returning an empty inbox with a correct-looking total).
 */
import { useEffect, useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from "lucide-react";

/** Page sizes offered. 25 is the default: it fits a screen without scrolling. */
export const PAGE_SIZES = [25, 50, 100, 250] as const;

export interface PagedList<T> {
  /** The rows to render for the current page. */
  items: T[];
  page: number;
  pageSize: number;
  setPage: (p: number) => void;
  setPageSize: (n: number) => void;
  total: number;
  totalPages: number;
  /** 1-based index of the first row shown, for "showing 51–100 of 1,067". */
  from: number;
  to: number;
  /** True when the list is short enough that paging controls add nothing. */
  singlePage: boolean;
}

/**
 * @param all       the complete, already-filtered list
 * @param resetKey  any value whose change should send the reader back to page 1
 *                  (a search string, an active filter). Changing the filter
 *                  while deep in the list is the classic way to land on an
 *                  empty page and read it as "no results".
 */
export function usePagedList<T>(
  all: T[],
  resetKey: unknown = null,
  initialPageSize: number = 25,
): PagedList<T> {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(initialPageSize);

  useEffect(() => {
    setPage(1);
  }, [resetKey, pageSize]);

  const total = all.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  // Clamp rather than trust: `all` can shrink under a stable resetKey (a row
  // deleted, a poll returning fewer rows), which would otherwise strand the
  // reader past the end with nothing rendered and no explanation.
  const safePage = Math.min(Math.max(1, page), totalPages);

  const items = useMemo(
    () => all.slice((safePage - 1) * pageSize, safePage * pageSize),
    [all, safePage, pageSize],
  );

  return {
    items,
    page: safePage,
    pageSize,
    setPage,
    setPageSize,
    total,
    totalPages,
    from: total === 0 ? 0 : (safePage - 1) * pageSize + 1,
    to: Math.min(safePage * pageSize, total),
    singlePage: total <= pageSize,
  };
}

/**
 * The controls. Rendered only when there is more than one page — a pager under
 * a four-row table is noise that makes the page look more complicated than it is.
 */
export function ListPager<T>({
  paged,
  label = "items",
  className = "",
}: {
  paged: PagedList<T>;
  /** Plural noun for the range summary: "1–25 of 1,067 assets". */
  label?: string;
  className?: string;
}) {
  const { page, totalPages, total, from, to, setPage, pageSize, setPageSize } = paged;

  if (total === 0) return null;

  const fmt = (n: number) => n.toLocaleString();

  return (
    <div
      className={`flex flex-wrap items-center justify-between gap-3 border-t pt-3 ${className}`}
      data-testid="list-pager"
    >
      {/* Announced politely: the count changes as the reader filters, and a
          screen-reader user gets no other signal that the set shrank. */}
      <p className="text-xs text-muted-foreground" role="status" aria-live="polite">
        Showing <span className="font-medium text-foreground">{fmt(from)}–{fmt(to)}</span> of{" "}
        <span className="font-medium text-foreground">{fmt(total)}</span> {label}
      </p>

      <div className="flex items-center gap-2">
        <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <span className="hidden sm:inline">Rows</span>
          <Select value={String(pageSize)} onValueChange={(v) => setPageSize(Number(v))}>
            <SelectTrigger className="h-8 w-[72px]" aria-label="Rows per page" data-testid="pager-page-size">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {PAGE_SIZES.map((n) => (
                <SelectItem key={n} value={String(n)}>{n}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </label>

        {totalPages > 1 && (
          <div className="flex items-center gap-1">
            <Button
              variant="outline" size="icon" className="h-8 w-8"
              onClick={() => setPage(1)} disabled={page === 1}
              aria-label="First page" data-testid="pager-first"
            >
              <ChevronsLeft className="h-4 w-4" aria-hidden="true" />
            </Button>
            <Button
              variant="outline" size="icon" className="h-8 w-8"
              onClick={() => setPage(page - 1)} disabled={page === 1}
              aria-label="Previous page" data-testid="pager-prev"
            >
              <ChevronLeft className="h-4 w-4" aria-hidden="true" />
            </Button>
            <span className="px-1 text-xs tabular-nums text-muted-foreground" data-testid="pager-position">
              {fmt(page)} / {fmt(totalPages)}
            </span>
            <Button
              variant="outline" size="icon" className="h-8 w-8"
              onClick={() => setPage(page + 1)} disabled={page === totalPages}
              aria-label="Next page" data-testid="pager-next"
            >
              <ChevronRight className="h-4 w-4" aria-hidden="true" />
            </Button>
            <Button
              variant="outline" size="icon" className="h-8 w-8"
              onClick={() => setPage(totalPages)} disabled={page === totalPages}
              aria-label="Last page" data-testid="pager-last"
            >
              <ChevronsRight className="h-4 w-4" aria-hidden="true" />
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}
