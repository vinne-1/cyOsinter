import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { Biohazard, Loader2, ShieldCheck, ExternalLink, AlertOctagon } from "lucide-react";
import type { ReconModule } from "@shared/schema";

interface RansomwareMatch {
  victim: string;
  group: string;
  website: string | null;
  country: string | null;
  sector: string | null;
  publishedAt: string | null;
  discoveredAt: string | null;
  postUrl: string | null;
  confidence: "confirmed" | "possible";
  reason: string;
}

interface RansomwareData {
  target: string;
  recordsChecked: number;
  matches: RansomwareMatch[];
  counts: { confirmed: number; possible: number };
  feedFetchedAt: string;
  scannedAt: string;
}

/**
 * Ransomware leak-site exposure for the selected workspace.
 *
 * Deliberately blunt when there is a confirmed hit — this is the highest-signal
 * finding the platform can produce — and equally careful to mark name-only
 * matches as unverified, because a false "you have been ransomed" is worse than
 * no result at all.
 */
export function RansomwarePanel({ workspaceId }: { workspaceId: string | null }) {
  const { toast } = useToast();

  const { data: module, isLoading } = useQuery<ReconModule | null>({
    queryKey: [`/api/workspaces/${workspaceId}/ransomware-exposure`],
    enabled: !!workspaceId,
  });

  const check = useMutation({
    mutationFn: async () => {
      // The corpus is tens of thousands of records; the first fetch is slow.
      const res = await apiRequest(
        "POST",
        `/api/workspaces/${workspaceId}/ransomware-exposure`,
        {},
        { timeoutMs: 180_000 },
      );
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceId}/ransomware-exposure`] });
      toast({ title: "Check complete", description: "Leak-site exposure updated." });
    },
    onError: (err: Error) => {
      toast({ title: "Check failed", description: err.message, variant: "destructive" });
    },
  });

  const data = (module?.data ?? null) as RansomwareData | null;

  return (
    <section className="rounded-xl border border-hairline bg-surface-2">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-hairline p-4">
        <div className="flex items-center gap-2">
          <Biohazard className="h-4 w-4 text-severity-critical" aria-hidden="true" />
          <h2 className="text-sm font-semibold">Ransomware leak sites</h2>
          <span className="text-xs text-muted-foreground">
            Public leak-site postings · no API key required
          </span>
        </div>
        <Button
          size="sm"
          variant="outline"
          onClick={() => check.mutate()}
          disabled={check.isPending || !workspaceId}
          data-testid="button-check-ransomware"
        >
          {check.isPending
            ? <><Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" /> Checking…</>
            : "Check exposure"}
        </Button>
      </div>

      {isLoading ? (
        <div className="p-4"><Skeleton className="h-24 rounded-lg" /></div>
      ) : !data ? (
        <p className="p-8 text-center text-sm text-muted-foreground">
          Not checked yet. This compares your domain against victims published on
          ransomware leak sites.
        </p>
      ) : data.matches.length === 0 ? (
        <div className="flex items-start gap-3 p-5">
          <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-severity-ok" aria-hidden="true" />
          <div>
            <p className="text-sm font-medium">
              No leak-site postings found for{" "}
              <span className="font-mono">{data.target}</span>
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              Checked against {data.recordsChecked.toLocaleString()} published victim records.
              Absence here is not proof of safety — crews post selectively and often late.
            </p>
          </div>
        </div>
      ) : (
        <>
          {data.counts.confirmed > 0 && (
            <div className="flex items-start gap-3 border-b border-severity-critical/25 bg-severity-critical/10 p-4">
              <AlertOctagon className="mt-0.5 h-5 w-5 shrink-0 text-severity-critical" aria-hidden="true" />
              <div>
                <p className="text-sm font-semibold text-severity-critical">
                  {data.counts.confirmed} confirmed leak-site posting
                  {data.counts.confirmed === 1 ? "" : "s"} naming this domain
                </p>
                <p className="mt-1 text-xs text-muted-foreground">
                  Treat as an active incident until disproven: a listing usually means data was
                  already exfiltrated.
                </p>
              </div>
            </div>
          )}

          <ul className="divide-y divide-hairline">
            {data.matches.map((m, i) => (
              <li key={`${m.group}-${m.victim}-${i}`} className="flex flex-wrap items-start gap-x-4 gap-y-2 p-4">
                <span
                  className={cn(
                    "mt-1.5 h-2 w-2 shrink-0 rounded-full",
                    m.confidence === "confirmed" ? "bg-severity-critical" : "bg-severity-medium",
                  )}
                  aria-hidden="true"
                />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="truncate text-sm font-medium">{m.victim}</span>
                    <span className="rounded bg-surface-3 px-1.5 py-0.5 font-mono text-[0.625rem] uppercase tracking-wide">
                      {m.group}
                    </span>
                    {m.sector && <span className="text-xs text-muted-foreground">{m.sector}</span>}
                    {m.country && <span className="text-xs text-muted-foreground">{m.country}</span>}
                  </div>
                  <p className="mt-1 text-xs text-muted-foreground">
                    {m.website && <span className="font-mono">{m.website}</span>}
                    {m.publishedAt && (
                      <> · published {new Date(m.publishedAt).toLocaleDateString()}</>
                    )}
                  </p>
                  <p className="mt-1 text-xs text-muted-foreground">{m.reason}</p>
                </div>

                <span
                  className={cn(
                    "shrink-0 rounded-md px-2 py-0.5 text-xs font-medium",
                    m.confidence === "confirmed"
                      ? "bg-severity-critical/15 text-severity-critical ring-1 ring-inset ring-severity-critical/25"
                      : "bg-severity-medium/15 text-severity-medium ring-1 ring-inset ring-severity-medium/25",
                  )}
                >
                  {m.confidence === "confirmed" ? "Confirmed" : "Unverified"}
                </span>

                {m.postUrl && (
                  // Rendered as text, never a link: these are .onion addresses a
                  // normal browser cannot open, and we must not encourage an
                  // analyst to visit a live extortion site from a work machine.
                  <span
                    className="inline-flex shrink-0 items-center gap-1 text-xs text-muted-foreground"
                    title={m.postUrl}
                  >
                    <ExternalLink className="h-3 w-3" aria-hidden="true" />
                    .onion
                  </span>
                )}
              </li>
            ))}
          </ul>

          <p className="border-t border-hairline p-4 text-xs text-muted-foreground">
            Checked {new Date(data.scannedAt).toLocaleString()} against{" "}
            {data.recordsChecked.toLocaleString()} records.
            {data.counts.possible > 0 && (
              <> {data.counts.possible} match{data.counts.possible === 1 ? "" : "es"} are name-only
                and must be verified — company names are not unique.</>
            )}
          </p>
        </>
      )}
    </section>
  );
}
