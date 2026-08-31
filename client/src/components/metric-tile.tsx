import React from "react";
import { cn } from "@/lib/utils";
import { ArrowDownRight, ArrowUpRight, Minus } from "lucide-react";

/**
 * A dense KPI tile: label, a display-weight value, an optional delta against a
 * previous period, and an optional sparkline. Replaces the flat StatCard so the
 * headline numbers carry trend and not just magnitude.
 */

export interface MetricTileProps {
  label: string;
  value: string | number;
  /** Small qualifier under the value, e.g. "3 critical" or "Last: 2h ago". */
  hint?: React.ReactNode;
  icon?: React.ElementType;
  /** Signed change vs. the previous period. Sign, not magnitude, drives colour. */
  delta?: number;
  /** Whether a rise is good ("assets discovered") or bad ("open findings"). */
  deltaGoodDirection?: "up" | "down";
  /** Series for the sparkline, oldest → newest. Fewer than 2 points hides it. */
  series?: number[];
  /** Accent colour (a CSS colour string). Defaults to the primary token. */
  accent?: string;
  /** Raises the tile visually — use for the single most important metric. */
  emphasis?: boolean;
  onClick?: () => void;
  testId?: string;
  className?: string;
}

/**
 * Builds an SVG path for a sparkline normalised into a 100×32 viewBox.
 *
 * Inset on ALL FOUR sides. The stroke is centred on the path and drawn with
 * `non-scaling-stroke`, so a point sitting exactly on x=0 or x=100 has half its
 * width outside the viewBox and gets shaved off by the tile's overflow-hidden —
 * which is what made the first and last segment look cut off at the card edge.
 */
function sparkPath(series: number[]): { line: string; area: string } {
  const w = 100;
  const h = 32;
  const padX = 2;
  const padY = 3;
  const min = Math.min(...series);
  const max = Math.max(...series);
  const span = max - min || 1;
  const usableW = w - padX * 2;
  const step = series.length > 1 ? usableW / (series.length - 1) : 0;

  const pts = series.map((v, i) => {
    const x = padX + i * step;
    const y = h - padY - ((v - min) / span) * (h - padY * 2);
    return [x, y] as const;
  });

  const line = pts.map(([x, y], i) => `${i === 0 ? "M" : "L"}${x.toFixed(2)},${y.toFixed(2)}`).join(" ");
  // The fill may run to the baseline; only the stroked line needs the inset.
  const area = `${line} L${(w - padX).toFixed(2)},${h} L${padX},${h} Z`;
  return { line, area };
}

export function MetricTile({
  label,
  value,
  hint,
  icon: Icon,
  delta,
  deltaGoodDirection = "up",
  series,
  accent = "hsl(var(--primary))",
  emphasis = false,
  onClick,
  testId,
  className,
}: MetricTileProps) {
  const gradientId = React.useId();
  const hasSpark = Array.isArray(series) && series.length >= 2;
  const spark = hasSpark ? sparkPath(series!) : null;

  const hasDelta = typeof delta === "number" && Number.isFinite(delta) && delta !== 0;
  const rising = (delta ?? 0) > 0;
  // "Good" is whichever direction the caller says it is — more assets found is
  // neutral-to-good, more open findings is bad.
  const good = rising === (deltaGoodDirection === "up");
  const DeltaIcon = !hasDelta ? Minus : rising ? ArrowUpRight : ArrowDownRight;

  const Wrapper = onClick ? "button" : "div";

  return (
    <Wrapper
      type={onClick ? "button" : undefined}
      onClick={onClick}
      data-testid={testId}
      className={cn(
        "group relative flex h-full w-full flex-col overflow-hidden rounded-xl border text-left",
        "border-hairline bg-surface-2 p-4",
        "transition-all duration-200",
        onClick && "cursor-pointer hover:border-primary/40 hover:shadow-lift focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        emphasis && "shadow-lift",
        className,
      )}
    >
      {/* Accent hairline along the top edge — the tile's only chrome. */}
      <span
        aria-hidden="true"
        className="absolute inset-x-0 top-0 h-px opacity-60 transition-opacity duration-200 group-hover:opacity-100"
        style={{ background: `linear-gradient(90deg, transparent, ${accent}, transparent)` }}
      />

      <div className="flex items-start justify-between gap-3">
        <p className="text-[0.6875rem] font-medium uppercase tracking-wider text-muted-foreground">
          {label}
        </p>
        {Icon && (
          <Icon
            className="h-4 w-4 shrink-0 opacity-70 transition-opacity group-hover:opacity-100"
            style={{ color: accent }}
            aria-hidden="true"
          />
        )}
      </div>

      <div className="mt-auto flex items-end justify-between gap-3 pt-2">
        <div className="min-w-0">
          <p
            className={cn(
              "font-semibold tabular-nums tracking-tight",
              emphasis ? "text-display" : "text-display-sm",
            )}
            data-testid={testId ? `${testId}-value` : undefined}
          >
            {typeof value === "number" ? value.toLocaleString() : value}
          </p>
          {hint && <p className="mt-1 truncate text-xs text-muted-foreground">{hint}</p>}
        </div>

        {spark && (
          <svg
            viewBox="0 0 100 32"
            preserveAspectRatio="none"
            className="h-9 w-24 shrink-0 self-center opacity-80 transition-opacity group-hover:opacity-100"
            aria-hidden="true"
          >
            <defs>
              <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={accent} stopOpacity="0.28" />
                <stop offset="100%" stopColor={accent} stopOpacity="0" />
              </linearGradient>
            </defs>
            <path d={spark.area} fill={`url(#${gradientId})`} />
            <path
              d={spark.line}
              fill="none"
              stroke={accent}
              strokeWidth="1.75"
              strokeLinecap="round"
              strokeLinejoin="round"
              vectorEffect="non-scaling-stroke"
            />
          </svg>
        )}
      </div>

      {hasDelta && (
        <div
          className={cn(
            "mt-3 inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-medium tabular-nums",
            good ? "bg-severity-ok/12 text-severity-ok" : "bg-severity-critical/12 text-severity-critical",
          )}
        >
          <DeltaIcon className="h-3 w-3" aria-hidden="true" />
          <span>
            {rising ? "+" : ""}
            {delta}
          </span>
          <span className="font-normal opacity-70">vs. previous</span>
        </div>
      )}
    </Wrapper>
  );
}
