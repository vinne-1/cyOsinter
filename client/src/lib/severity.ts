/**
 * Single source of truth for finding severity presentation.
 *
 * Colours resolve from the `--sev-*` CSS variables (see index.css), so a badge,
 * a chart slice, a table rail and a gauge segment always agree — and they follow
 * the active theme instead of being hardcoded per component.
 */

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITY_ORDER)[number];

export interface SeverityMeta {
  key: Severity;
  label: string;
  /** CSS var reference — usable in inline `fill`/`stroke` and Recharts props. */
  color: string;
  /** Tailwind classes for a filled chip. */
  chip: string;
  /** Tailwind class for a solid block (severity rails, legend dots). */
  solid: string;
  /** Weight used to rank a mixed list, highest first. */
  weight: number;
}

export const SEVERITY: Record<Severity, SeverityMeta> = {
  critical: {
    key: "critical",
    label: "Critical",
    color: "hsl(var(--sev-critical))",
    chip: "bg-severity-critical/15 text-severity-critical ring-1 ring-inset ring-severity-critical/25",
    solid: "bg-severity-critical",
    weight: 5,
  },
  high: {
    key: "high",
    label: "High",
    color: "hsl(var(--sev-high))",
    chip: "bg-severity-high/15 text-severity-high ring-1 ring-inset ring-severity-high/25",
    solid: "bg-severity-high",
    weight: 4,
  },
  medium: {
    key: "medium",
    label: "Medium",
    color: "hsl(var(--sev-medium))",
    chip: "bg-severity-medium/15 text-severity-medium ring-1 ring-inset ring-severity-medium/25",
    solid: "bg-severity-medium",
    weight: 3,
  },
  low: {
    key: "low",
    label: "Low",
    color: "hsl(var(--sev-low))",
    chip: "bg-severity-low/15 text-severity-low ring-1 ring-inset ring-severity-low/25",
    solid: "bg-severity-low",
    weight: 2,
  },
  info: {
    key: "info",
    label: "Info",
    color: "hsl(var(--sev-info))",
    chip: "bg-severity-info/15 text-severity-info ring-1 ring-inset ring-severity-info/25",
    solid: "bg-severity-info",
    weight: 1,
  },
};

export function severityMeta(severity: string | null | undefined): SeverityMeta {
  return SEVERITY[(severity ?? "info") as Severity] ?? SEVERITY.info;
}

/** Counts findings per severity, always returning every key (zeros included). */
export function countBySeverity<T extends { severity: string }>(
  findings: readonly T[],
): Record<Severity, number> {
  const out = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>;
  for (const f of findings) {
    const key = f.severity as Severity;
    if (key in out) out[key] += 1;
  }
  return out;
}

/**
 * Letter grade for a 0–100 posture score. Mirrors how the score itself is
 * computed in shared/scoring.ts — an A means nothing critical is outstanding.
 */
export function scoreGrade(score: number): { grade: string; tone: string; color: string } {
  if (score >= 90) return { grade: "A", tone: "Strong", color: "hsl(var(--sev-ok))" };
  if (score >= 80) return { grade: "B", tone: "Good", color: "hsl(var(--sev-ok))" };
  if (score >= 65) return { grade: "C", tone: "Fair", color: "hsl(var(--sev-medium))" };
  if (score >= 50) return { grade: "D", tone: "Weak", color: "hsl(var(--sev-high))" };
  return { grade: "F", tone: "Critical", color: "hsl(var(--sev-critical))" };
}
