import React from "react";
import { Link } from "wouter";
import { cn } from "@/lib/utils";
import { SEVERITY_ORDER, severityMeta, scoreGrade, type Severity } from "@/lib/severity";
import { ArrowRight, ShieldCheck } from "lucide-react";

/**
 * The dashboard's lead surface: one large posture score with a radial gauge,
 * the severity mix that produced it, and the single next action.
 *
 * The gauge is a stroked SVG arc rather than a chart library so it stays crisp
 * at any size, needs no ResponsiveContainer, and animates with pure CSS.
 */

export interface PostureHeroProps {
  /** 0–100 posture score, or null when there is nothing to score yet. */
  score: number | null;
  counts: Record<Severity, number>;
  /** Signed change vs. the previous snapshot, if history exists. */
  delta?: number | null;
  target?: string | null;
  totalAssets: number;
  lastScanLabel?: string | null;
  className?: string;
}

const RADIUS = 78;
const STROKE = 12;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;
/** The gauge is a 270° arc (a full circle minus a 90° gap at the bottom). */
const ARC_FRACTION = 0.75;

export function PostureHero({
  score,
  counts,
  delta,
  target,
  totalAssets,
  lastScanLabel,
  className,
}: PostureHeroProps) {
  const hasScore = typeof score === "number";
  const shown = hasScore ? Math.max(0, Math.min(100, score!)) : 0;
  const { grade, tone, color } = scoreGrade(shown);
  const totalFindings = SEVERITY_ORDER.reduce((n, k) => n + counts[k], 0);

  // Arc geometry: draw ARC_FRACTION of the circle, filled to `shown` percent.
  const trackDash = `${CIRCUMFERENCE * ARC_FRACTION} ${CIRCUMFERENCE}`;
  const valueDash = `${CIRCUMFERENCE * ARC_FRACTION * (shown / 100)} ${CIRCUMFERENCE}`;

  const actionable = counts.critical + counts.high;

  return (
    <section
      aria-label="Security posture"
      className={cn(
        "relative overflow-hidden rounded-2xl border border-hairline bg-surface-2 shadow-lift",
        className,
      )}
    >
      {/* Ambient brand wash — the only decorative element, kept very low contrast. */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -right-24 -top-32 h-80 w-80 rounded-full opacity-[0.14] blur-3xl"
        style={{ background: `radial-gradient(circle, hsl(var(--brand-to)), transparent 70%)` }}
      />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -left-20 bottom--20 h-64 w-64 rounded-full opacity-[0.10] blur-3xl"
        style={{ background: `radial-gradient(circle, hsl(var(--brand-from)), transparent 70%)` }}
      />

      <div className="relative grid gap-8 p-6 lg:grid-cols-[auto_1fr] lg:gap-10 lg:p-8">
        {/* ── Gauge ── */}
        <div className="flex items-center justify-center lg:justify-start">
          <div className="relative h-48 w-48">
            <svg viewBox="0 0 200 200" className="h-full w-full -rotate-[225deg]" role="img"
              aria-label={hasScore ? `Security score ${shown} out of 100, grade ${grade}` : "No security score yet"}>
              <circle
                cx="100" cy="100" r={RADIUS} fill="none"
                stroke="hsl(var(--surface-inset))" strokeWidth={STROKE}
                strokeDasharray={trackDash} strokeLinecap="round"
              />
              {hasScore && (
                <circle
                  cx="100" cy="100" r={RADIUS} fill="none"
                  stroke={color} strokeWidth={STROKE}
                  strokeDasharray={valueDash} strokeLinecap="round"
                  className="transition-[stroke-dasharray] duration-[900ms] ease-out"
                  style={{ filter: `drop-shadow(0 0 8px ${color}55)` }}
                />
              )}
            </svg>

            <div className="absolute inset-0 flex flex-col items-center justify-center">
              {hasScore ? (
                <>
                  <span className="text-display-lg font-semibold tabular-nums" style={{ color }}>
                    {shown}
                  </span>
                  <span className="mt-0.5 text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    Grade {grade} · {tone}
                  </span>
                </>
              ) : (
                <>
                  <ShieldCheck className="h-8 w-8 text-muted-foreground/50" aria-hidden="true" />
                  <span className="mt-2 text-xs text-muted-foreground">Not scored yet</span>
                </>
              )}
            </div>
          </div>
        </div>

        {/* ── Summary ── */}
        <div className="flex min-w-0 flex-col justify-center gap-5">
          <div>
            <h2 className="text-xl font-semibold tracking-tight">
              {target ? <span className="font-mono text-primary">{target}</span> : "Security posture"}
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">
              {totalAssets.toLocaleString()} asset{totalAssets === 1 ? "" : "s"} monitored
              {lastScanLabel ? ` · scanned ${lastScanLabel}` : ""}
            </p>
            {typeof delta === "number" && delta !== 0 && (
              // Its own line: inlined into the sentence above it wrapped
              // mid-phrase ("+71 pts / since last scan") at common widths.
              <p
                className={`mt-1.5 inline-flex w-fit items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-medium tabular-nums ${
                  delta > 0
                    ? "bg-severity-ok/12 text-severity-ok"
                    : "bg-severity-critical/12 text-severity-critical"
                }`}
              >
                {delta > 0 ? "+" : ""}
                {delta} pts since last scan
              </p>
            )}
          </div>

          {/* Severity mix as a single stacked bar — the shape of the risk at a glance. */}
          <div>
            <div className="mb-2 flex items-baseline justify-between">
              <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                Open findings
              </span>
              <span className="text-sm font-semibold tabular-nums">{totalFindings.toLocaleString()}</span>
            </div>
            <div className="flex h-2.5 gap-0.5 overflow-hidden rounded-full bg-surface-inset" role="img"
              aria-label={SEVERITY_ORDER.map((k) => `${counts[k]} ${k}`).join(", ")}>
              {totalFindings === 0
                ? <div className="h-full w-full bg-severity-ok/30" />
                : SEVERITY_ORDER.filter((k) => counts[k] > 0).map((k) => (
                    <div
                      key={k}
                      className={cn("h-full transition-all duration-700", severityMeta(k).solid)}
                      style={{ width: `${(counts[k] / totalFindings) * 100}%` }}
                      title={`${severityMeta(k).label}: ${counts[k]}`}
                    />
                  ))}
            </div>
            <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5">
              {SEVERITY_ORDER.map((k) => {
                const meta = severityMeta(k);
                return (
                  <span key={k} className="inline-flex items-center gap-1.5 text-xs">
                    <span className={cn("h-2 w-2 rounded-full", meta.solid, counts[k] === 0 && "opacity-30")} />
                    <span className="text-muted-foreground">{meta.label}</span>
                    <span className="font-semibold tabular-nums">{counts[k]}</span>
                  </span>
                );
              })}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <Link
              href="/findings"
              className={cn(
                "inline-flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                actionable > 0
                  ? "bg-severity-critical/12 text-severity-critical hover:bg-severity-critical/20"
                  : "bg-surface-3 text-foreground hover:bg-surface-3/70",
              )}
              data-testid="link-posture-triage"
            >
              {actionable > 0
                ? `Triage ${actionable} critical & high`
                : "Review all findings"}
              <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
            </Link>
            <Link
              href="/reports"
              className="inline-flex items-center gap-1.5 rounded-lg border border-hairline px-3 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-surface-3 hover:text-foreground"
            >
              Generate report
            </Link>
          </div>
        </div>
      </div>
    </section>
  );
}
