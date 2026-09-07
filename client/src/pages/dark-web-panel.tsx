import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import {
  Eye, Loader2, ShieldCheck, ExternalLink, AlertTriangle, Globe,
  KeyRound, MessageSquare, Server,
} from "lucide-react";
import type { ReconModule } from "@shared/schema";

interface DarkWebMention {
  source: string;
  title: string;
  url: string | null;
  snippet: string | null;
  publishedAt: string | null;
  matchedTerm: string;
  confidence: "confirmed" | "possible";
  reason: string;
}

interface DarkWebLeakDump {
  source: string;
  recordCount: number | null;
  dataTypes: string[];
  publishedAt: string | null;
  url: string | null;
  confirmed: boolean;
  matchedTerm: string;
  reason: string;
}

interface DarkWebData {
  target: string;
  mentions: DarkWebMention[];
  leakDumps: DarkWebLeakDump[];
  forumMentions: unknown[];
  counts: {
    confirmedMentions: number;
    possibleMentions: number;
    leakDumps: number;
    forumMentions: number;
  };
  sourcesChecked: string[];
  sourcesFailed: string[];
  torAvailable: boolean;
  scannedAt: string;
}

/**
 * Display names for source ids. `ahmia` and `onion_live` were removed from the
 * scanner (both APIs answer 404) and are removed here too — a stale entry would
 * be harmless only until someone re-added the id, and a MISSING entry is worse:
 * `ransomware_leak_sites` had no label, so a leak-site mention would have
 * rendered its raw snake_case id to the client.
 */
const SOURCE_LABELS: Record<string, string> = {
  ransomware_leak_sites: "Ransomware leak sites",
  dark_paste_sites: "Dark paste sites",
  credential_dumps: "Credential dumps",
};

const SOURCE_ICONS: Record<string, React.ElementType> = {
  ransomware_leak_sites: AlertTriangle,
  dark_paste_sites: KeyRound,
  credential_dumps: Server,
};

/**
 * Dark web monitoring panel for the selected workspace.
 *
 * Checks Tor-dependent and clearnet sources for mentions of the target
 * on dark web marketplaces, paste sites, and credential dumps.
 */
/** Prose form of the source ids, for the sentence in the empty state. */
const SOURCE_PROSE: Record<string, string> = {
  ransomware_leak_sites: "the ransomware leak-site corpus",
  dark_paste_sites: "dark paste sites",
  credential_dumps: "credential-dump aggregators",
};

function sourceList(ids: string[]): string {
  const names = ids.map((i) => SOURCE_PROSE[i] ?? i);
  if (names.length === 0) return "no sources";
  if (names.length === 1) return names[0]!;
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

export function DarkWebPanel({ workspaceId }: { workspaceId: string | null }) {
  const { toast } = useToast();

  const { data: module, isLoading } = useQuery<ReconModule | null>({
    queryKey: [`/api/workspaces/${workspaceId}/dark-web`],
    enabled: !!workspaceId,
  });

  const scan = useMutation({
    mutationFn: async () => {
      // .onion services are slow; generous timeout.
      const res = await apiRequest(
        "POST",
        `/api/workspaces/${workspaceId}/dark-web`,
        {},
        { timeoutMs: 300_000 },
      );
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceId}/dark-web`] });
      toast({ title: "Scan complete", description: "Dark web monitoring results updated." });
    },
    onError: (err: Error) => {
      toast({ title: "Scan failed", description: err.message, variant: "destructive" });
    },
  });

  const data = (module?.data ?? null) as DarkWebData | null;

  const hasCriticalSignal =
    (data?.counts.confirmedMentions ?? 0) > 0 ||
    (data?.counts.leakDumps ?? 0) > 0;

  return (
    <section className="rounded-xl border border-hairline bg-surface-2">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-hairline p-4">
        <div className="flex items-center gap-2">
          <Eye className="h-4 w-4 text-severity-critical" aria-hidden="true" />
          <h2 className="text-sm font-semibold">Dark web monitoring</h2>
          <span className="text-xs text-muted-foreground">
            Mentions on .onion services, paste sites &amp; leak databases
          </span>
        </div>
        <Button
          size="sm"
          variant="outline"
          onClick={() => scan.mutate()}
          disabled={scan.isPending || !workspaceId}
          data-testid="button-scan-dark-web"
        >
          {scan.isPending
            ? <><Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" /> Scanning…</>
            : "Run scan"}
        </Button>
      </div>

      {isLoading ? (
        <div className="p-4"><Skeleton className="h-24 rounded-lg" /></div>
      ) : !data ? (
        <p className="p-8 text-center text-sm text-muted-foreground">
          Not scanned yet. This checks dark web paste sites, .onion services, and
          credential dump aggregators for mentions of your domain and brand.
        </p>
      ) : data.mentions.length === 0 && data.leakDumps.length === 0 ? (
        /*
         * Nothing found is TWO different results, and rendering them the same
         * way is the "No Data reads as a pass" failure this product corrects
         * everywhere else.
         *
         * Seen live: a green shield reading "No dark web mentions found for
         * bigbasket.com" while the small print underneath said Tor was
         * unavailable and 4 of 6 sources had failed. Two sources answered. The
         * headline and the icon asserted a clean bill of health that the same
         * paragraph then contradicted — and a reader takes the green tick, not
         * the footnote.
         *
         * So a run that could not complete gets its own state: amber, and a
         * headline that says the check was incomplete rather than clean.
         */
        (() => {
          const skipped = !data.torAvailable;
          const failed = data.sourcesFailed.length;
          const answered = data.sourcesChecked.length;
          const incomplete = skipped || failed > 0;

          return (
            <div className="flex items-start gap-3 p-5">
              {incomplete ? (
                <AlertTriangle
                  className="mt-0.5 h-5 w-5 shrink-0 text-severity-medium"
                  aria-hidden="true"
                />
              ) : (
                <ShieldCheck
                  className="mt-0.5 h-5 w-5 shrink-0 text-severity-ok"
                  aria-hidden="true"
                />
              )}
              <div>
                <p className="text-sm font-medium">
                  {incomplete ? (
                    <>
                      Dark web check was incomplete for{" "}
                      <span className="font-mono">{data.target}</span>
                    </>
                  ) : (
                    <>
                      No dark web mentions found for{" "}
                      <span className="font-mono">{data.target}</span>
                    </>
                  )}
                </p>
                <p className="mt-1 text-xs text-muted-foreground">
                  {incomplete ? (
                    <>
                      {answered} of {answered + failed} source
                      {answered + failed === 1 ? "" : "s"} answered
                      {answered > 0 ? <> ({sourceList(data.sourcesChecked)})</> : null}, and
                      nothing was found in {answered === 1 ? "it" : "those"}.
                      {skipped && <> The Tor proxy is unavailable, so .onion sources were not checked at all.</>}
                      {failed > 0 && (
                        <> {failed} source{failed === 1 ? "" : "s"} failed to respond ({data.sourcesFailed.join(", ")}).</>
                      )}
                      {" "}This is <strong>not</strong> a clean result — most of the corpus was not
                      searched. Start the Tor proxy and re-run to complete the check.
                    </>
                  ) : (
                    <>
                      {/* Naming the sources matters more than counting them: "all
                          3 answered" is only reassuring if the reader knows which
                          three, and the set changes as dead sources are retired. */}
                      Searched {sourceList(data.sourcesChecked)} — no mention of this domain.
                      Absence is not proof of safety: dark web monitoring is best-effort and
                      covers only publicly reachable sources, not vetted forums or private
                      marketplaces.
                    </>
                  )}
                </p>
              </div>
            </div>
          );
        })()
      ) : (
        <>
          {/* Critical alert banner */}
          {hasCriticalSignal && (
            <div className="flex items-start gap-3 border-b border-severity-critical/25 bg-severity-critical/10 p-4">
              <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-severity-critical" aria-hidden="true" />
              <div>
                <p className="text-sm font-semibold text-severity-critical">
                  {data.counts.confirmedMentions > 0 && (
                    <>{data.counts.confirmedMentions} confirmed dark web mention{data.counts.confirmedMentions === 1 ? "" : "s"}</>
                  )}
                  {data.counts.confirmedMentions > 0 && data.counts.leakDumps > 0 && <> · </>}
                  {data.counts.leakDumps > 0 && (
                    <>{data.counts.leakDumps} credential dump{data.counts.leakDumps === 1 ? "" : "s"} contain{data.counts.leakDumps === 1 ? "s" : ""} your data</>
                  )}
                </p>
                <p className="mt-1 text-xs text-muted-foreground">
                  Treat as an active incident. Rotate any credentials associated with
                  this domain and investigate the source listings.
                </p>
              </div>
            </div>
          )}

          {/* Leak dumps */}
          {data.leakDumps.length > 0 && (
            <div className="border-b border-hairline">
              <div className="flex items-center gap-2 px-4 pt-3">
                <KeyRound className="h-3.5 w-3.5 text-severity-critical" aria-hidden="true" />
                <h3 className="text-xs font-semibold text-severity-critical">
                  Credential dumps ({data.leakDumps.length})
                </h3>
              </div>
              <ul className="divide-y divide-hairline">
                {data.leakDumps.map((dump, i) => (
                  <li key={`${dump.source}-${i}`} className="flex flex-wrap items-start gap-x-4 gap-y-2 p-4">
                    <span
                      className={cn(
                        "mt-1.5 h-2 w-2 shrink-0 rounded-full",
                        dump.confirmed ? "bg-severity-critical" : "bg-severity-medium",
                      )}
                      aria-hidden="true"
                    />
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium">{dump.source}</p>
                      <p className="mt-1 text-xs text-muted-foreground">
                        {dump.dataTypes.join(", ")}
                        {dump.recordCount != null && <> · {dump.recordCount.toLocaleString()} records</>}
                        {dump.publishedAt && <> · {new Date(dump.publishedAt).toLocaleDateString()}</>}
                      </p>
                      <p className="mt-1 text-xs text-muted-foreground">{dump.reason}</p>
                    </div>
                    <span
                      className={cn(
                        "shrink-0 rounded-md px-2 py-0.5 text-xs font-medium",
                        dump.confirmed
                          ? "bg-severity-critical/15 text-severity-critical ring-1 ring-inset ring-severity-critical/25"
                          : "bg-severity-medium/15 text-severity-medium ring-1 ring-inset ring-severity-medium/25",
                      )}
                    >
                      {dump.confirmed ? "Confirmed" : "Unverified"}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Mentions */}
          <ul className="divide-y divide-hairline">
            {data.mentions.map((mention, i) => {
              const SourceIcon = SOURCE_ICONS[mention.source] ?? Globe;
              return (
                <li
                  key={`${mention.source}-${i}`}
                  className="flex flex-wrap items-start gap-x-4 gap-y-2 p-4"
                >
                  <span
                    className={cn(
                      "mt-1.5 h-2 w-2 shrink-0 rounded-full",
                      mention.confidence === "confirmed" ? "bg-severity-critical" : "bg-severity-medium",
                    )}
                    aria-hidden="true"
                  />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <SourceIcon className="h-3 w-3 text-muted-foreground" aria-hidden="true" />
                      <span className="text-xs text-muted-foreground">
                        {SOURCE_LABELS[mention.source] ?? mention.source}
                      </span>
                    </div>
                    <p className="mt-1 truncate text-sm font-medium">{mention.title}</p>
                    {mention.snippet && (
                      <p className="mt-1 line-clamp-2 text-xs text-muted-foreground">
                        {mention.snippet}
                      </p>
                    )}
                    <p className="mt-1 text-xs text-muted-foreground">
                      Matched: <span className="font-mono">{mention.matchedTerm}</span>
                    </p>
                    <p className="mt-1 text-xs text-muted-foreground">{mention.reason}</p>
                  </div>

                  <span
                    className={cn(
                      "shrink-0 rounded-md px-2 py-0.5 text-xs font-medium",
                      mention.confidence === "confirmed"
                        ? "bg-severity-critical/15 text-severity-critical ring-1 ring-inset ring-severity-critical/25"
                        : "bg-severity-medium/15 text-severity-medium ring-1 ring-inset ring-severity-medium/25",
                    )}
                  >
                    {mention.confidence === "confirmed" ? "Confirmed" : "Unverified"}
                  </span>

                  {mention.url && (
                    <span
                      className="inline-flex shrink-0 items-center gap-1 text-xs text-muted-foreground"
                      title={mention.url}
                    >
                      <ExternalLink className="h-3 w-3" aria-hidden="true" />
                      {mention.url.includes(".onion") ? ".onion" : "link"}
                    </span>
                  )}
                </li>
              );
            })}
          </ul>

          {/* Source health */}
          <div className="flex flex-wrap gap-x-6 gap-y-2 border-t border-hairline p-4 text-xs text-muted-foreground">
            <span>
              Scanned {new Date(data.scannedAt).toLocaleString()}
            </span>
            <span>
              {data.sourcesChecked.length} source{data.sourcesChecked.length === 1 ? "" : "s"} checked
            </span>
            {!data.torAvailable && (
              <span className="text-severity-medium">
                Tor proxy unavailable — .onion sources skipped
              </span>
            )}
            {data.sourcesFailed.length > 0 && (
              <span className="text-severity-medium">
                {data.sourcesFailed.length} source{data.sourcesFailed.length === 1 ? "" : "s"} failed
              </span>
            )}
          </div>
        </>
      )}
    </section>
  );
}
