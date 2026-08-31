import React from "react";
import { cn } from "@/lib/utils";

/**
 * Bento grid primitives.
 *
 * The dashboard previously used a rigid row of five equal-sized cards, which is
 * the documented failure mode for dense enterprise dashboards: every metric is
 * given the same visual weight, so the layout tells the reader nothing about
 * what matters. Eye-tracking work behind the bento pattern finds users fixate
 * roughly 2.6x longer on larger tiles — so tile SIZE is the cheapest hierarchy
 * signal available, and leaving it uniform wastes it.
 *
 * Rules encoded here, from the pattern's practical guidance:
 *  - 4 columns on desktop, 2 on tablet, 1 on mobile — reordered by importance
 *    rather than by desktop position.
 *  - Consistent gutters (inconsistent spacing is the most common way a bento
 *    grid falls apart).
 *  - Padding scales with tile size: a hero tile needs more breathing room than
 *    a stat chip, and using one padding value for both is what makes a grid
 *    read as a spreadsheet.
 */

export type BentoSpan = 1 | 2 | 3 | 4;
export type BentoRows = 1 | 2;

export function BentoGrid({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        // 16px gutter at every breakpoint keeps the rhythm identical as tiles
        // reflow, which is what stops the grid looking accidental.
        "grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4",
        // Rows size to their content. A fixed minimum made every row as tall as
        // the hero needed, so a two-line stat tile ended up half empty with its
        // label pinned to the top and its value to the bottom. The hero sets its
        // own height instead (see BentoTile rows=2), and the rows it spans
        // inherit that; the rest hug their content.
        "lg:auto-rows-auto",
        className,
      )}
    >
      {children}
    </div>
  );
}

const COL_SPAN: Record<BentoSpan, string> = {
  1: "lg:col-span-1",
  2: "md:col-span-2 lg:col-span-2",
  3: "md:col-span-2 lg:col-span-3",
  4: "md:col-span-2 lg:col-span-4",
};

const ROW_SPAN: Record<BentoRows, string> = {
  1: "lg:row-span-1",
  // The two-row tile is the one that needs real height; it defines the rows it
  // spans rather than every row being padded up to match it.
  2: "lg:row-span-2 lg:min-h-[20rem]",
};

/** Padding scales with the tile's footprint, per the bento sizing guidance. */
const PAD: Record<BentoRows, string> = {
  1: "p-4",
  2: "p-5 lg:p-6",
};

export interface BentoTileProps {
  children: React.ReactNode;
  /** Columns to occupy on desktop. Bigger = more important. */
  span?: BentoSpan;
  rows?: BentoRows;
  /** Accent hairline along the top edge — the tile's only chrome. */
  accent?: string;
  /** Lifts the tile. Reserve for the one thing that needs attention now. */
  emphasis?: boolean;
  /** Removes the default surface so a child can own the whole tile. */
  bare?: boolean;
  className?: string;
  as?: "div" | "section";
  ariaLabel?: string;
}

export function BentoTile({
  children,
  span = 1,
  rows = 1,
  accent,
  emphasis = false,
  bare = false,
  className,
  as: Tag = "div",
  ariaLabel,
}: BentoTileProps) {
  return (
    <Tag
      aria-label={ariaLabel}
      className={cn(
        "relative overflow-hidden rounded-xl",
        COL_SPAN[span],
        ROW_SPAN[rows],
        !bare && "border border-hairline bg-surface-2",
        !bare && PAD[rows],
        emphasis && "shadow-lift ring-1 ring-inset ring-severity-critical/20",
        className,
      )}
    >
      {accent && (
        <span
          aria-hidden="true"
          className="absolute inset-x-0 top-0 h-px opacity-70"
          style={{ background: `linear-gradient(90deg, transparent, ${accent}, transparent)` }}
        />
      )}
      {children}
    </Tag>
  );
}

/**
 * A live-data pulse.
 *
 * Premium monitoring dashboards signal that what you are looking at is current;
 * generic ones look identical whether the data arrived a second or a month ago.
 */
export function LiveIndicator({ label = "Live" }: { label?: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-severity-ok">
      <span className="relative flex h-2 w-2" aria-hidden="true">
        <span className="absolute inline-flex h-full w-full animate-pulse-ring rounded-full bg-severity-ok" />
        <span className="relative inline-flex h-2 w-2 rounded-full bg-severity-ok" />
      </span>
      {label}
    </span>
  );
}
