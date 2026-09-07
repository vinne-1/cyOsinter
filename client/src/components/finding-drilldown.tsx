/**
 * The findings behind a number.
 *
 * Every aggregate in this product — a factor score, a compliance control's
 * "14 findings", a severity count — is derived from specific rows, and until
 * now none of them could be opened. A reader shown "Security Misconfiguration ·
 * Fail · 14 findings" had to go to the inbox and reconstruct which fourteen by
 * guessing at categories. That is the same defect as a count that reports the
 * page size: the number is right and unusable.
 *
 * This is deliberately one component used by both the risk-factor card and the
 * compliance page, so a finding reads identically wherever it is surfaced and
 * the two cannot drift into showing different fields.
 */
import { Link } from "wouter";
import { ExternalLink } from "lucide-react";
import { severityMeta } from "@/lib/severity";

export interface DrilldownFinding {
  id: string;
  title: string;
  severity: string;
  status?: string | null;
  affectedAsset?: string | null;
  category?: string | null;
}

/** How many rows to render before pointing the reader at the full inbox. */
const MAX_ROWS = 12;

export function FindingDrilldown({
  findings,
  emptyLabel = "No findings in this area.",
}: {
  findings: DrilldownFinding[];
  emptyLabel?: string;
}) {
  if (findings.length === 0) {
    return <p className="py-2 text-xs text-muted-foreground">{emptyLabel}</p>;
  }

  // Worst first — the reason someone opened this is to find the work.
  const ordered = [...findings].sort(
    (a, b) => severityMeta(b.severity).weight - severityMeta(a.severity).weight,
  );
  const shown = ordered.slice(0, MAX_ROWS);
  const hidden = ordered.length - shown.length;

  return (
    <ul className="space-y-1 py-1">
      {shown.map((f) => {
        const meta = severityMeta(f.severity);
        return (
          <li key={f.id}>
            <Link
              href={`/findings?finding=${encodeURIComponent(f.id)}`}
              className="group flex items-start gap-2.5 rounded-md px-2 py-1.5 hover:bg-muted/60"
              data-testid={`drilldown-finding-${f.id}`}
            >
              <span
                className={`mt-0.5 shrink-0 rounded px-1.5 py-0.5 text-[10px] font-medium uppercase ${meta.chip}`}
              >
                {meta.label}
              </span>
              <span className="min-w-0 flex-1">
                <span className="block truncate text-xs font-medium underline-offset-2 group-hover:underline">
                  {f.title}
                </span>
                {f.affectedAsset && (
                  <span className="block truncate text-[11px] text-muted-foreground">
                    {f.affectedAsset}
                  </span>
                )}
              </span>
              <ExternalLink
                className="mt-0.5 h-3 w-3 shrink-0 text-muted-foreground opacity-0 group-hover:opacity-100"
                aria-hidden="true"
              />
            </Link>
          </li>
        );
      })}
      {hidden > 0 && (
        <li className="px-2 pt-1 text-[11px] text-muted-foreground">
          + {hidden} more — <Link href="/findings" className="underline">open the findings inbox</Link>
        </li>
      )}
    </ul>
  );
}
