/**
 * What the scan is doing, while it does it.
 *
 * The pipeline already reported itself in detail — `scan-trigger.ts` writes
 * `progressMessage`, `progressPercent` and `currentStep` to the scan row at
 * every phase boundary, and the scanners emit a named step for each of their
 * stages ("enumerate_subdomains", "takeover_check", "secret_scan"). All of that
 * reached the UI as a 1.5px bar and one truncated line of text.
 *
 * So during the part of the product that takes the longest — a Gold scan runs
 * for thirty minutes or more — the operator had no way to tell a scan that was
 * working from one that was wedged, and no idea which of the ~57 modules was
 * responsible for the wait. This surfaces the reporting that already existed.
 *
 * Two decisions worth keeping:
 *
 *  - **Phases come from `currentStep`'s prefix, not from the percentage.**
 *    `scan-trigger` prefixes every message it forwards (`easm_`, `osint_`,
 *    `nuclei_`, `dast_`), which is a fact about which scanner is running.
 *    Inferring the phase from the percent band would be a second, weaker copy
 *    of that mapping, and the two would drift the moment a band is retuned.
 *  - **The activity log is client-side and append-only.** The server keeps only
 *    the CURRENT message — there is no progress history table, and adding one
 *    to write a line per phase would be a table whose only reader is a panel
 *    that is open for a few minutes. Accumulating distinct messages as they
 *    arrive gives the same view for free, and it honestly resets on reload.
 */
import { useEffect, useRef, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Check, Loader2, Circle, Radar } from "lucide-react";

export interface LiveScan {
  id: string;
  type: string;
  target: string;
  status: string;
  startedAt?: string | Date | null;
  findingsCount?: number | null;
  progressMessage?: string | null;
  progressPercent?: number | null;
  currentStep?: string | null;
  estimatedSecondsRemaining?: number | null;
}

interface Phase {
  key: string;
  label: string;
  /** What this phase is for, in a sentence an operator can act on. */
  detail: string;
}

/** The four scanners `scan-trigger` orchestrates, in the order it runs them. */
const PHASES: Phase[] = [
  { key: "easm", label: "Attack surface", detail: "Discovering subdomains, resolving hosts, reading certificates and headers" },
  { key: "osint", label: "OSINT", detail: "DNS and mail authentication, exposed paths, secrets, people and code" },
  { key: "nuclei", label: "Templates", detail: "Running the Nuclei template corpus against confirmed hosts" },
  { key: "dast", label: "Active tests", detail: "Crawling for real endpoints, then testing the ones that take input" },
];

/** Which phases a scan of this type will actually run. */
function phasesFor(type: string): Phase[] {
  const t = (type || "").toLowerCase();
  if (t === "easm") return PHASES.filter((p) => p.key === "easm" || p.key === "dast");
  if (t === "osint" || t === "passive") return PHASES.filter((p) => p.key === "osint");
  return PHASES;
}

type PhaseState = "done" | "active" | "pending";

function stateOf(phase: Phase, active: string | null, order: Phase[]): PhaseState {
  if (!active) return "pending";
  const activeIdx = order.findIndex((p) => p.key === active);
  const myIdx = order.findIndex((p) => p.key === phase.key);
  if (activeIdx < 0) return "pending";
  if (myIdx < activeIdx) return "done";
  if (myIdx === activeIdx) return "active";
  return "pending";
}

/**
 * `easm_takeover_check` → `easm`. The prefix is written by scan-trigger.
 *
 * The fallback is for scan rows written before the step vocabulary was unified,
 * which carry a bare `takeover_check` with no prefix. Guessing from the scan
 * type is right for a single-scanner run and is only reached when the prefix is
 * genuinely absent — showing every phase as "not started" while the scan is
 * plainly running is a worse answer than an inferred one.
 */
function activePhaseKey(
  currentStep: string | null | undefined,
  type: string,
  order: Phase[],
): string | null {
  if (currentStep) {
    const prefix = currentStep.split("_")[0]?.toLowerCase() ?? "";
    if (PHASES.some((p) => p.key === prefix)) return prefix;
  }
  // Untagged step, or none yet: a run with exactly one scanner has only one
  // answer. A full scan has four, so it stays honest and claims none.
  return order.length === 1 ? order[0]!.key : (type || "").toLowerCase() === "easm" ? "easm" : null;
}

function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "—";
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return m > 0 ? `${m}m ${s.toString().padStart(2, "0")}s` : `${s}s`;
}

/** Strips the `[EASM] ` tag — the phase is already shown by the tracker. */
function cleanMessage(msg: string): string {
  return msg.replace(/^\[[^\]]+\]\s*/, "");
}

export function LiveScanView({ scan }: { scan: LiveScan }) {
  const order = phasesFor(scan.type);
  const activeKey = activePhaseKey(scan.currentStep, scan.type, order);
  const percent = Math.max(0, Math.min(100, scan.progressPercent ?? 0));

  // Rolling activity log, appended when the message actually changes.
  const [log, setLog] = useState<Array<{ at: number; text: string }>>([]);
  const lastMessage = useRef<string | null>(null);

  useEffect(() => {
    const msg = scan.progressMessage?.trim();
    if (!msg || msg === lastMessage.current) return;
    lastMessage.current = msg;
    setLog((prev) => [{ at: Date.now(), text: msg }, ...prev].slice(0, 40));
  }, [scan.progressMessage]);

  // Elapsed ticks locally: the scan row only updates at phase boundaries, and a
  // clock frozen between them looks like a stalled scan.
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  const startedMs = scan.startedAt ? new Date(scan.startedAt).getTime() : null;
  const elapsed = startedMs ? (now - startedMs) / 1000 : null;

  return (
    <Card data-testid="live-scan-view">
      <CardHeader className="pb-3">
        <CardTitle className="flex flex-wrap items-center gap-2 text-base">
          <Radar className="h-4 w-4 animate-pulse text-primary" aria-hidden="true" />
          Scanning {scan.target}
          <Badge variant="outline" className="text-[10px] uppercase">{scan.type}</Badge>
          <span className="ml-auto text-sm font-normal tabular-nums text-muted-foreground">
            {percent}%
          </span>
        </CardTitle>
      </CardHeader>

      <CardContent className="space-y-4 pt-0">
        <Progress
          value={percent}
          className="h-2"
          aria-label={`Scan progress: ${percent} percent`}
        />

        {/* Phase tracker */}
        <ol className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {order.map((phase) => {
            const state = stateOf(phase, activeKey, order);
            return (
              <li
                key={phase.key}
                data-testid={`scan-phase-${phase.key}`}
                data-state={state}
                className={`rounded-lg border p-2.5 ${
                  state === "active"
                    ? "border-primary/40 bg-primary/5"
                    : state === "done"
                      ? "border-border bg-muted/30"
                      : "border-dashed border-border"
                }`}
              >
                <div className="flex items-center gap-1.5">
                  {state === "done" && <Check className="h-3.5 w-3.5 shrink-0 text-[hsl(var(--sev-ok))]" aria-hidden="true" />}
                  {state === "active" && <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin text-primary" aria-hidden="true" />}
                  {state === "pending" && <Circle className="h-3.5 w-3.5 shrink-0 text-muted-foreground/50" aria-hidden="true" />}
                  <span className={`truncate text-xs font-medium ${state === "pending" ? "text-muted-foreground" : ""}`}>
                    {phase.label}
                  </span>
                  <span className="sr-only">
                    {state === "done" ? "complete" : state === "active" ? "in progress" : "not started"}
                  </span>
                </div>
                <p className="mt-1 text-[11px] leading-snug text-muted-foreground">{phase.detail}</p>
              </li>
            );
          })}
        </ol>

        {/* Current activity — announced, because this is the live region */}
        <div
          role="status"
          aria-live="polite"
          className="rounded-lg border bg-muted/40 p-3"
        >
          <p className="text-sm font-medium" data-testid="scan-current-activity">
            {scan.progressMessage ? cleanMessage(scan.progressMessage) : "Starting…"}
          </p>
          <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
            {elapsed !== null && <span>Elapsed {formatDuration(elapsed)}</span>}
            {scan.estimatedSecondsRemaining != null && scan.estimatedSecondsRemaining > 0 && (
              <span>~{formatDuration(scan.estimatedSecondsRemaining)} remaining</span>
            )}
            <span>
              {scan.findingsCount ?? 0} finding{(scan.findingsCount ?? 0) === 1 ? "" : "s"} so far
            </span>
          </div>
        </div>

        {/* Activity log */}
        {log.length > 1 && (
          <div>
            <p className="mb-1 text-xs font-medium text-muted-foreground">Activity</p>
            <ul
              className="max-h-44 space-y-0.5 overflow-y-auto rounded-lg border p-2"
              tabIndex={0}
              aria-label="Scan activity log"
            >
              {log.map((entry, i) => (
                <li
                  key={`${entry.at}-${i}`}
                  className={`flex gap-2 text-[11px] ${i === 0 ? "text-foreground" : "text-muted-foreground"}`}
                >
                  {/* A token, never an opacity modifier stacked on already-tinted
                      text — that combination measured 2.39:1 and 4.31:1 in two
                      earlier regressions and is called out in CLAUDE.md. */}
                  <span className="shrink-0 tabular-nums text-muted-foreground">
                    {new Date(entry.at).toLocaleTimeString(undefined, { hour12: false })}
                  </span>
                  <span className="min-w-0 flex-1">{cleanMessage(entry.text)}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
