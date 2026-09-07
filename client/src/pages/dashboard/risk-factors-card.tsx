/**
 * The security rating, decomposed into the areas a reader can act on.
 *
 * Two things here are deliberately unlike a commercial rating report, and both
 * are the point of the card:
 *
 *  1. **A factor nothing assessed shows "Not assessed", never 100.** A rating
 *     vendor's scorecard shows Endpoint Security 100 / 0 issues for a company it
 *     has no endpoint telemetry for. That reads as excellence and is really an
 *     absence of evidence, and it is the "No Data reads as a pass" failure this
 *     product corrects everywhere else.
 *
 *  2. **The headline action is the ceiling, not a per-issue decimal.** Our score
 *     is banded, so fixing one of two open mediums moves it by nothing; the true
 *     statement is that *any* open medium caps the score at 85. That is a target
 *     an engineer can plan around, where "-0.9" is not.
 */
import { useMemo, useState, useId } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { HelpCircle, Target, ChevronRight } from "lucide-react";
import {
  computeFactorScores,
  analyseScoreCeiling,
  assessedCategoriesFromModules,
  type FactorInput,
  type FactorScore,
} from "@shared/risk-factors";
import type { Finding, ReconModule } from "@shared/schema";
import { scoreGrade } from "@/lib/severity";
import { FindingDrilldown, type DrilldownFinding } from "@/components/finding-drilldown";
import { factorForCategory } from "@shared/risk-factors";

/**
 * Grade colour, taken from `scoreGrade` so the badge here and the dashboard hero
 * cannot disagree about what a score looks like.
 *
 * The colour is applied as an inline style rather than an arbitrary Tailwind
 * class: `bg-[--sev-ok]` is not the `var()` form Tailwind needs and produced a
 * silently uncoloured badge, which is exactly how a token-based palette drifts
 * without anything failing.
 */
function gradeStyle(grade: string | null): React.CSSProperties {
  if (!grade) return {};
  // Grades come from scoreGrade's own band table, so any score maps.
  const anchor = { A: 95, B: 85, C: 70, D: 55, F: 30 }[grade] ?? 30;
  const { color } = scoreGrade(anchor);
  return { color, backgroundColor: `color-mix(in srgb, ${color} 15%, transparent)`, borderColor: `color-mix(in srgb, ${color} 35%, transparent)` };
}

function FactorRow({
  factor,
  findings,
}: {
  factor: FactorScore;
  findings: DrilldownFinding[];
}) {
  const notAssessed = factor.state === "not_assessed";
  const [open, setOpen] = useState(false);
  const panelId = useId();

  // Nothing to open when nothing was found — a disclosure that reveals an empty
  // box teaches the reader the control is broken.
  const expandable = findings.length > 0;

  return (
    <div className="py-2.5">
      <div className="flex items-center gap-3">
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5">
          {/* The disclosure is its own button rather than the whole row, because
              the row already contains the help tooltip's button and nesting one
              button inside another is invalid markup that assistive technology
              reads unpredictably. */}
          {expandable ? (
            <button
              type="button"
              onClick={() => setOpen((v) => !v)}
              aria-expanded={open}
              aria-controls={panelId}
              className="flex min-w-0 items-center gap-1 text-left"
              data-testid={`factor-toggle-${factor.id}`}
            >
              <ChevronRight
                className={`h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform ${open ? "rotate-90" : ""}`}
                aria-hidden="true"
              />
              <span className="truncate text-sm font-medium underline-offset-2 hover:underline">
                {factor.title}
              </span>
            </button>
          ) : (
            <span className="truncate pl-[18px] text-sm font-medium">{factor.title}</span>
          )}
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  type="button"
                  aria-label={`What ${factor.title} covers`}
                  className="text-muted-foreground hover:text-foreground"
                >
                  <HelpCircle className="h-3.5 w-3.5" aria-hidden="true" />
                </button>
              </TooltipTrigger>
              <TooltipContent className="max-w-xs">
                <p className="text-xs">{factor.description}</p>
                <p className="mt-1 text-xs text-muted-foreground">{factor.reason}</p>
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        </div>
        {/* The severity is part of the count, not a detail. "3 open findings"
            beside a grade A reads as a contradiction until you know all three
            are informational — and informational findings deduct nothing by
            design, so the grade is right and the label was the problem. */}
        <p className="mt-0.5 text-xs text-muted-foreground">
          {notAssessed
            ? "Not assessed — no check for this area ran"
            : factor.findingCount === 0
              ? "Checked, nothing outstanding"
              : `${factor.findingCount} open finding${factor.findingCount === 1 ? "" : "s"} · worst: ${factor.worstSeverity ?? "info"}`}
        </p>
      </div>

      <div className="w-24 shrink-0">
        {notAssessed ? (
          // A dashed empty track, so the eye reads "no measurement" rather than
          // "a bar at zero" — which would look like the worst possible score.
          <div className="h-1.5 w-full rounded-full border border-dashed border-border" />
        ) : (
          <Progress value={factor.score ?? 0} className="h-1.5" aria-hidden="true" />
        )}
      </div>

      <div className="w-16 shrink-0 text-right">
        {notAssessed ? (
          <span className="text-xs text-muted-foreground">N/A</span>
        ) : (
          <span className="text-sm font-semibold tabular-nums">{factor.score}</span>
        )}
      </div>

      <Badge
        variant="outline"
        className="w-8 shrink-0 justify-center"
        style={gradeStyle(factor.grade)}
      >
        {factor.grade ?? "–"}
      </Badge>
      </div>

      {expandable && open && (
        <div id={panelId} className="mt-1 border-l-2 border-border pl-3">
          <FindingDrilldown findings={findings} />
        </div>
      )}
    </div>
  );
}

export function RiskFactorsCard({
  findings,
  modules,
}: {
  findings: Finding[];
  modules: ReconModule[];
}) {
  const assessed = useMemo(
    () => assessedCategoriesFromModules(modules.map((m) => m.moduleType)),
    [modules],
  );

  const inputs = useMemo(
    () => findings as unknown as FactorInput[],
    [findings],
  );

  const factors = useMemo(
    () => computeFactorScores(inputs, assessed),
    [inputs, assessed],
  );

  const ceiling = useMemo(() => analyseScoreCeiling(inputs), [inputs]);

  // Scored factors first — a reader wants the measured areas before the gaps,
  // and within those the worst first, since that is where the work is.
  const ordered = useMemo(
    () =>
      [...factors].sort((a, b) => {
        if ((a.state === "not_assessed") !== (b.state === "not_assessed")) {
          return a.state === "not_assessed" ? 1 : -1;
        }
        return (a.score ?? 101) - (b.score ?? 101);
      }),
    [factors],
  );

  const notAssessedCount = factors.filter((f) => f.state === "not_assessed").length;

  /**
   * The open findings behind each factor, so a row can show its own evidence.
   *
   * Grouped with the SAME predicate `computeFactorScores` uses to count them —
   * open, kind security, category mapped to this factor — because a row whose
   * drill-down listed a different set from the count beside it would undermine
   * the number rather than explain it.
   */
  const findingsByFactor = useMemo(() => {
    const map = new Map<string, DrilldownFinding[]>();
    for (const f of findings) {
      if (f.status !== "open") continue;
      if ((f.kind ?? "security") !== "security") continue;
      const factorId = f.category ? factorForCategory(f.category) : null;
      if (!factorId) continue;
      const list = map.get(factorId) ?? [];
      list.push({
        id: f.id,
        title: f.title,
        severity: f.severity,
        status: f.status,
        affectedAsset: f.affectedAsset,
        category: f.category,
      });
      map.set(factorId, list);
    }
    return map;
  }, [findings]);

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          Risk factors
          <span className="text-xs font-normal text-muted-foreground">
            {factors.length - notAssessedCount} of {factors.length} assessed
          </span>
        </CardTitle>
      </CardHeader>

      <CardContent className="pt-0">
        {/* The gate, stated first — this is the number to act on. */}
        {ceiling.cappedBy && (
          <div className="mb-3 flex items-start gap-2.5 rounded-lg border bg-muted/40 p-3">
            <Target className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
            <div className="min-w-0">
              {/* Two different regimes, and the wrong wording is actively
                  misleading in each other's. See `binding` in risk-factors.ts. */}
              <p className="text-sm font-medium">
                {ceiling.binding === "ceiling"
                  ? `Score is capped at ${ceiling.currentCeiling} by ${ceiling.blockingCount} ${ceiling.cappedBy} finding${ceiling.blockingCount === 1 ? "" : "s"}`
                  : `${ceiling.blockingCount} open ${ceiling.cappedBy} findings are holding the score at ${ceiling.score}`}
              </p>
              <p className="mt-0.5 text-xs text-muted-foreground">
                Clearing all {ceiling.blockingCount} would raise the score to about{" "}
                {ceiling.ceilingIfCleared}
                {ceiling.gain > 0 ? ` (+${ceiling.gain})` : ""}.{" "}
                {ceiling.binding === "ceiling"
                  ? "Fixing only some of them does not move it — the cap is set by any one remaining."
                  : "Each one fixed helps, so partial progress is worth doing."}
              </p>
            </div>
          </div>
        )}

        <div className="divide-y">
          {ordered.map((f) => (
            <FactorRow key={f.id} factor={f} findings={findingsByFactor.get(f.id) ?? []} />
          ))}
        </div>

        {notAssessedCount > 0 && (
          <p className="mt-3 border-t pt-3 text-xs text-muted-foreground">
            {notAssessedCount} factor{notAssessedCount === 1 ? " is" : "s are"} shown as{" "}
            <span className="font-medium">Not assessed</span> rather than scored. No check capable
            of judging {notAssessedCount === 1 ? "it" : "them"} ran, and reporting that as a perfect
            score would state an assurance this scan did not earn.
          </p>
        )}
      </CardContent>
    </Card>
  );
}
