import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Network, Radar, AlertCircle, ShieldCheck } from "lucide-react";
import { ModuleHeader } from "./shared";
import type { ReconModule } from "@shared/schema";

/**
 * Panels for the two discovery-quality modules.
 *
 * Both exist to answer a question the raw counts cannot: how much should the
 * reader trust this inventory? A subdomain total with no stated provenance is a
 * number, not evidence, and a silently rate-limited source is indistinguishable
 * from one that genuinely had nothing to say.
 */

type AsnRow = {
  asn: number;
  name: string;
  description: string;
  attribution: "owned" | "shared" | "unknown";
  reason: string;
};

/**
 * Routed footprint from BGP.
 *
 * The refusals are shown as prominently as the attributions. "We saw AS13335
 * and deliberately did not expand it" is what stops a reader concluding the
 * scan simply missed the organisation's address space.
 */
export function RoutedFootprintPanel({ mod }: { mod: ReconModule }) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const d = mod.data as Record<string, any>;
  const asns = (d.asns ?? []) as AsnRow[];
  const owned = asns.filter((a) => a.attribution === "owned");
  const refused = asns.filter((a) => a.attribution !== "owned");
  const prefixes = (d.ownedPrefixes ?? []) as string[];

  return (
    <Card data-testid="panel-routed-footprint">
      <CardContent className="p-5">
        <ModuleHeader title="Routed Footprint" icon={Network} confidence={mod.confidence ?? 0} generatedAt={mod.generatedAt} />

        {d.unavailable ? (
          <div className="flex items-start gap-2 rounded-md border bg-muted/30 p-3">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
            <p className="text-sm text-muted-foreground">
              Routing data was unavailable, so the organisation&apos;s announced address space could not be checked.
              This is not evidence that it announces none.
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="grid grid-cols-3 gap-3">
              <Stat label="Own ASNs" value={String(owned.length)} />
              <Stat label="Prefixes" value={String(prefixes.length)} />
              <Stat label="IPv4 addresses" value={Number(d.ownedAddressCount ?? 0).toLocaleString()} />
            </div>

            {prefixes.length > 0 && (
              <div className="space-y-2">
                <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Announced prefixes</p>
                <div className="flex flex-wrap gap-1.5">
                  {prefixes.map((p) => (
                    <Badge key={p} variant="outline" className="font-mono text-[10px]">{p}</Badge>
                  ))}
                </div>
              </div>
            )}

            {owned.length > 0 && (
              <div className="space-y-2">
                <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Attributed to this organisation</p>
                {owned.map((a) => (
                  <div key={a.asn} className="rounded-md border bg-muted/30 p-3">
                    <p className="font-mono text-sm font-medium">AS{a.asn} · {a.name || "unnamed"}</p>
                    <p className="mt-1 text-xs text-muted-foreground">{a.reason}</p>
                  </div>
                ))}
              </div>
            )}

            {refused.length > 0 && (
              <div className="space-y-2">
                <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Not expanded ({refused.length})
                </p>
                <p className="text-xs text-muted-foreground">
                  Expanding a provider network would attribute its other customers&apos; address space to you, so these
                  are recorded and deliberately left alone.
                </p>
                {refused.map((a) => (
                  <div key={a.asn} className="rounded-md border bg-muted/30 p-3">
                    <div className="flex items-center gap-2">
                      <p className="font-mono text-sm">AS{a.asn} · {a.name || "unnamed"}</p>
                      <Badge variant="secondary" className="text-[10px]">{a.attribution}</Badge>
                    </div>
                    <p className="mt-1 text-xs text-muted-foreground">{a.reason}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

/**
 * Discovery health: which sources answered, which did not, and how well
 * corroborated the resulting hosts are.
 */
export function DiscoveryHealthPanel({ mod }: { mod: ReconModule }) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const d = mod.data as Record<string, any>;
  const bySource = (d.bySource ?? {}) as Record<string, number>;
  const failed = (d.sourcesFailed ?? []) as string[];
  const tally = (d.confidenceTally ?? {}) as Record<string, number>;
  const best = (d.bestCorroborated ?? []) as Array<{ host: string; sources: string[] }>;
  const crawl = d.crawl as { engine: string; urls: number; parameterised: number; forms: number; truncated: boolean } | null | undefined;
  const permutation = d.permutation as { candidatesTried: number; hostsFound: number; hosts: string[] } | null | undefined;
  const faviconClusters = d.faviconClusters as Array<{ hash: number; hosts: string[] }> | null | undefined;
  const probeCoverage = d.probeCoverage as { discovered: number; probed: number; truncated: boolean } | null | undefined;

  return (
    <Card data-testid="panel-discovery-health">
      <CardContent className="p-5">
        <ModuleHeader title="Discovery Health" icon={Radar} confidence={mod.confidence ?? 0} generatedAt={mod.generatedAt} />

        <div className="space-y-4">
          <div className="grid grid-cols-3 gap-3">
            <Stat label="Hosts found" value={String(d.totalHosts ?? 0)} />
            <Stat label="Sources answered" value={String(d.sourcesAnswered ?? 0)} />
            <Stat label="Sources unavailable" value={String(failed.length)} />
          </div>

          {failed.length > 0 && (
            <div className="flex items-start gap-2 rounded-md border bg-muted/30 p-3">
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
              <div>
                <p className="text-sm font-medium">{failed.length} source(s) did not answer</p>
                <p className="mt-1 text-xs text-muted-foreground">
                  These were rate-limited, offline or timed out. They found nothing because they were never asked —
                  not because there was nothing to find. Coverage below is correspondingly incomplete.
                </p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {failed.map((f) => (
                    <Badge key={f} variant="outline" className="text-[10px]">{f}</Badge>
                  ))}
                </div>
              </div>
            </div>
          )}

          <div className="space-y-2">
            <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Corroboration</p>
            <div className="grid grid-cols-3 gap-3">
              <Stat label="3+ sources" value={String(tally.high ?? 0)} />
              <Stat label="2 sources" value={String(tally.medium ?? 0)} />
              <Stat label="1 source" value={String(tally.low ?? 0)} />
            </div>
            <p className="text-xs text-muted-foreground">
              A host several independent indexes agree on is very likely real. A single-source host may be a parsing
              artefact, and is worth confirming before acting on it.
            </p>
          </div>

          {crawl && (
            <div className="space-y-2">
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Crawl coverage</p>
              <div className="grid grid-cols-3 gap-3">
                <Stat label="Endpoints" value={String(crawl.urls ?? 0)} />
                <Stat label="With parameters" value={String(crawl.parameterised ?? 0)} />
                <Stat label="Forms" value={String(crawl.forms ?? 0)} />
              </div>
              <p className="text-xs text-muted-foreground">
                {crawl.truncated
                  ? "The crawl hit its page limit, so the active tests covered part of the application rather than all of it."
                  : "The crawl ran to completion, so the active tests were aimed at the endpoints the application actually serves."}
                {" "}Engine: {crawl.engine}.
              </p>
            </div>
          )}

          {probeCoverage?.truncated && (
            <div className="space-y-2 rounded border border-hairline p-2.5">
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Probe coverage</p>
              <div className="grid grid-cols-2 gap-3">
                <Stat label="Hosts discovered" value={probeCoverage.discovered.toLocaleString()} />
                <Stat label="Hosts probed" value={probeCoverage.probed.toLocaleString()} />
              </div>
              <p className="text-xs text-muted-foreground">
                More hosts were discovered than this scan profile probes, so findings describe the hosts that were
                probed rather than the whole estate. Raise the profile's probe budget to cover more.
              </p>
            </div>
          )}

          {permutation && (
            <div className="space-y-2">
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Permutation discovery</p>
              <div className="grid grid-cols-2 gap-3">
                <Stat label="Candidates tried" value={String(permutation.candidatesTried ?? 0)} />
                <Stat label="Hosts found" value={String(permutation.hostsFound ?? 0)} />
              </div>
              <p className="text-xs text-muted-foreground">
                {permutation.hostsFound > 0
                  ? "These hosts were generated from your existing naming convention, not read from any public index — so they are assets no certificate log or passive source was advertising."
                  : "No additional hosts were found by permuting the existing names. Passive sources and the wordlist appear to already cover this estate's naming convention."}
              </p>
              {permutation.hosts?.length > 0 && (
                <ul
                  tabIndex={0}
                  aria-label="Hosts found only by permutation"
                  className="max-h-40 space-y-1 overflow-auto rounded border border-border p-2"
                >
                  {permutation.hosts.slice(0, 40).map((h) => (
                    <li key={h} className="font-mono text-[11px]">{h}</li>
                  ))}
                </ul>
              )}
            </div>
          )}

          {faviconClusters && faviconClusters.length > 0 && (
            <div className="space-y-2">
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Applications by favicon</p>
              <p className="text-xs text-muted-foreground">
                Hosts serving the same icon are almost always the same application behind different names. A host
                whose icon nothing else shares is the one worth opening first. Each hash is Shodan-compatible —
                search <code className="font-mono">http.favicon.hash:&lt;value&gt;</code> to find infrastructure this
                scan never touched.
              </p>
              <ul
                tabIndex={0}
                aria-label="Hosts grouped by favicon hash"
                className="max-h-56 space-y-2 overflow-auto rounded border border-border p-2"
              >
                {faviconClusters.slice(0, 20).map((c) => (
                  <li key={c.hash} className="space-y-1">
                    <div className="flex items-center gap-2">
                      <code className="font-mono text-[11px]">{c.hash}</code>
                      <Badge variant="secondary" className="text-[10px]">
                        {c.hosts.length === 1 ? "unique" : `${c.hosts.length} hosts`}
                      </Badge>
                    </div>
                    <p className="font-mono text-[11px] text-muted-foreground">{c.hosts.slice(0, 8).join(", ")}
                      {c.hosts.length > 8 ? `, +${c.hosts.length - 8} more` : ""}</p>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {Object.keys(bySource).length > 0 && (
            <div className="space-y-2">
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Hosts per source</p>
              <div className="flex flex-wrap gap-1.5">
                {Object.entries(bySource).map(([name, count]) => (
                  <Badge key={name} variant="secondary" className="text-[10px]">{name}: {count}</Badge>
                ))}
              </div>
            </div>
          )}

          {best.length > 0 && (
            <div className="space-y-2">
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Best corroborated hosts</p>
              <div className="space-y-1.5">
                {best.map((b) => (
                  <div key={b.host} className="flex items-start justify-between gap-3 rounded-md border bg-muted/30 p-2.5">
                    <span className="min-w-0 flex-1 truncate font-mono text-xs">{b.host}</span>
                    <span className="shrink-0 text-[10px] text-muted-foreground">{b.sources.join(", ")}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border bg-muted/30 p-3">
      <p className="text-lg font-semibold tabular-nums">{value}</p>
      <p className="text-xs text-muted-foreground">{label}</p>
    </div>
  );
}

/**
 * What the fail-closed verification gate confirmed, and what it withheld.
 *
 * Withholding used to be invisible: the list existed only to keep unconfirmed
 * findings out of the counts, then went out of scope. A reader had no way to
 * tell a clean target from a noisy one that had been filtered, and no way to
 * audit a withholding they disagreed with. Showing the reasons is what turns
 * "we found nothing" into "we checked, and here is what we rejected".
 */
export function VerificationSummaryPanel({ mod }: { mod: ReconModule }) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const d = mod.data as Record<string, any>;
  const withheld = (d.withheld ?? []) as Array<{ title: string; category: string; affectedAsset: string; reason: string }>;
  const confirmed = Number(d.confirmedCount ?? 0);

  return (
    <Card data-testid="panel-verification-summary">
      <CardContent className="p-5">
        <ModuleHeader title="Verification" icon={ShieldCheck} confidence={mod.confidence ?? 0} generatedAt={mod.generatedAt} />

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <Stat label="Confirmed by live probe" value={String(confirmed)} />
            <Stat label="Withheld as unconfirmed" value={String(d.withheldCount ?? 0)} />
          </div>

          <p className="text-xs text-muted-foreground">
            Every finding is re-probed before it is stored. Anything a live probe could not reproduce is withheld
            rather than reported, so what reaches the inbox is what was still true at scan time.
          </p>

          {withheld.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              Nothing was withheld on this scan — every candidate finding reproduced.
            </p>
          ) : (
            <div className="space-y-2">
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Withheld ({withheld.length})
              </p>
              <div className="space-y-1.5">
                {withheld.map((w, i) => (
                  <div key={`${w.title}-${i}`} className="rounded-md border bg-muted/30 p-3">
                    <div className="flex items-start justify-between gap-3">
                      <p className="min-w-0 flex-1 text-sm font-medium">{w.title}</p>
                      <Badge variant="outline" className="shrink-0 text-[10px]">{w.category}</Badge>
                    </div>
                    <p className="mt-1 font-mono text-xs text-muted-foreground">{w.affectedAsset}</p>
                    <p className="mt-1 text-xs text-muted-foreground">Withheld: {w.reason}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
