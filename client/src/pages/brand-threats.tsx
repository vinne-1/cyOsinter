import { useMemo, useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { MetricTile } from "@/components/metric-tile";
import { ScrollStrip } from "@/components/scroll-strip";
import { cn } from "@/lib/utils";
import {
  ShieldAlert, Radar, Loader2, Mail, Globe, ExternalLink, Search, Server,
} from "lucide-react";
import type { ReconModule } from "@shared/schema";
import { RansomwarePanel } from "./ransomware-panel";
import { CodeLeakPanel } from "./code-leak-panel";

type Risk = "high" | "medium" | "low";

interface Lookalike {
  domain: string;
  kind: string;
  addresses: string[];
  mx: string[];
  nameservers: string[];
  resolves: boolean;
  risk: Risk;
}

interface BrandThreatData {
  target: string;
  generated: number;
  checked: number;
  registered: Lookalike[];
  counts: Record<Risk, number>;
  ownedExcluded: number;
  scannedAt: string;
}

const RISK_META: Record<Risk, { label: string; chip: string; dot: string; blurb: string }> = {
  high: {
    label: "High",
    chip: "bg-severity-critical/15 text-severity-critical ring-1 ring-inset ring-severity-critical/25",
    dot: "bg-severity-critical",
    blurb: "Live and mail-capable — can host a clone and send phishing as your brand",
  },
  medium: {
    label: "Medium",
    chip: "bg-severity-high/15 text-severity-high ring-1 ring-inset ring-severity-high/25",
    dot: "bg-severity-high",
    blurb: "Resolves to a host — likely a parking page or an active clone",
  },
  low: {
    label: "Low",
    chip: "bg-severity-low/15 text-severity-low ring-1 ring-inset ring-severity-low/25",
    dot: "bg-severity-low",
    blurb: "Registered but not serving — pre-positioned for later use",
  },
};

export default function BrandThreatsPage() {
  const { selectedWorkspaceId, selectedWorkspace } = useDomain();
  const { toast } = useToast();
  const [filter, setFilter] = useState<Risk | "all">("all");
  const [query, setQuery] = useState("");

  const { data: module, isLoading } = useQuery<ReconModule | null>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/brand-threats`],
    enabled: !!selectedWorkspaceId,
  });

  const data = (module?.data ?? null) as BrandThreatData | null;
  const target = selectedWorkspace?.domain || selectedWorkspace?.name || "";

  const scan = useMutation({
    mutationFn: async () => {
      // A sweep resolves several hundred names; allow well past the default.
      const res = await apiRequest(
        "POST",
        `/api/workspaces/${selectedWorkspaceId}/brand-threats`,
        {},
        { timeoutMs: 300_000 },
      );
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/brand-threats`] });
      toast({ title: "Sweep complete", description: "Lookalike domain results updated." });
    },
    onError: (err: Error) => {
      toast({ title: "Sweep failed", description: err.message, variant: "destructive" });
    },
  });

  const rows = useMemo(() => {
    const all = data?.registered ?? [];
    const q = query.trim().toLowerCase();
    return all.filter(
      (r) => (filter === "all" || r.risk === filter) && (!q || r.domain.includes(q) || r.kind.includes(q)),
    );
  }, [data, filter, query]);

  if (!selectedWorkspaceId) {
    return (
      <div className="p-6">
        <Card>
          <CardContent className="py-16 text-center">
            <Radar className="mx-auto mb-4 h-12 w-12 text-muted-foreground/40" aria-hidden="true" />
            <p className="text-base font-medium text-muted-foreground">No workspace selected</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-[1600px] space-y-6 p-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Brand Threats</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Domains registered to impersonate{" "}
            <span className="font-mono text-foreground">{target || "your brand"}</span> — typosquats,
            homoglyphs, bitsquats and combosquats, confirmed by DNS.
          </p>
        </div>
        <Button
          onClick={() => scan.mutate()}
          disabled={scan.isPending || !target}
          data-testid="button-run-brand-sweep"
        >
          {scan.isPending
            ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Sweeping…</>
            : <><Radar className="mr-2 h-4 w-4" /> Run sweep</>}
        </Button>
      </div>

      <RansomwarePanel workspaceId={selectedWorkspaceId} />

      <CodeLeakPanel workspaceId={selectedWorkspaceId} />

      {isLoading ? (
        <div className="space-y-4">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-32 rounded-xl" />)}
          </div>
          <Skeleton className="h-96 rounded-xl" />
        </div>
      ) : !data ? (
        <Card>
          <CardContent className="py-16 text-center">
            <ShieldAlert className="mx-auto mb-4 h-12 w-12 text-muted-foreground/40" aria-hidden="true" />
            <p className="text-base font-medium">No sweep has run yet</p>
            <p className="mx-auto mt-1 max-w-md text-sm text-muted-foreground">
              A sweep generates the domains an attacker would plausibly register to impersonate
              your brand, then resolves each one to find which are live. It uses DNS only — no
              third-party API key required.
            </p>
            <Button
              className="mt-6"
              onClick={() => scan.mutate()}
              disabled={scan.isPending || !target}
            >
              {scan.isPending
                ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Sweeping…</>
                : <><Radar className="mr-2 h-4 w-4" /> Run first sweep</>}
            </Button>
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <MetricTile
              label="Candidates checked"
              value={data.checked}
              hint="Permutations resolved"
              icon={Search}
              testId="brand-checked"
            />
            <MetricTile
              label="Registered lookalikes"
              value={data.registered.length}
              hint={data.ownedExcluded > 0 ? `${data.ownedExcluded} owned excluded` : "Exist in DNS"}
              icon={Globe}
              testId="brand-registered"
            />
            <MetricTile
              label="Phishing capable"
              value={data.counts.high}
              hint="Live host with mail records"
              icon={Mail}
              accent="hsl(var(--sev-critical))"
              emphasis={data.counts.high > 0}
              testId="brand-high"
            />
            <MetricTile
              label="Live hosts"
              value={data.counts.high + data.counts.medium}
              hint="Serving content today"
              icon={Server}
              accent="hsl(var(--sev-high))"
              testId="brand-live"
            />
          </div>

          <div className="rounded-xl border border-hairline bg-surface-2">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-hairline p-4">
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-semibold">
                  Lookalike domains{" "}
                  <span className="font-normal text-muted-foreground">({rows.length})</span>
                </h2>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <div className="relative">
                  <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
                  <Input
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    placeholder="Filter domains…"
                    aria-label="Filter lookalike domains"
                    className="h-8 w-52 pl-8 text-xs"
                  />
                </div>
                <ScrollStrip>
                  <div className="flex gap-1">
                    {(["all", "high", "medium", "low"] as const).map((r) => (
                      <button
                        key={r}
                        type="button"
                        onClick={() => setFilter(r)}
                        aria-pressed={filter === r}
                        className={cn(
                          "rounded-md px-2.5 py-1 text-xs font-medium capitalize transition-colors",
                          filter === r
                            ? "bg-primary text-primary-foreground"
                            : "text-muted-foreground hover:bg-surface-3 hover:text-foreground",
                        )}
                      >
                        {r === "all" ? `All ${data.registered.length}` : `${r} ${data.counts[r]}`}
                      </button>
                    ))}
                  </div>
                </ScrollStrip>
              </div>
            </div>

            {rows.length === 0 ? (
              <p className="py-16 text-center text-sm text-muted-foreground">
                No lookalike domains match this filter.
              </p>
            ) : (
              <ul className="divide-y divide-hairline">
                {rows.map((r) => {
                  const meta = RISK_META[r.risk];
                  return (
                    <li
                      key={r.domain}
                      className="flex flex-wrap items-center gap-x-4 gap-y-2 p-4 transition-colors hover:bg-surface-3/50"
                      data-testid={`lookalike-${r.domain}`}
                    >
                      <span className={cn("h-2 w-2 shrink-0 rounded-full", meta.dot)} aria-hidden="true" />

                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="truncate font-mono text-sm font-medium">{r.domain}</span>
                          <Badge variant="outline" className="text-[0.625rem] uppercase tracking-wide">
                            {r.kind}
                          </Badge>
                          {r.mx.length > 0 && (
                            <span className="inline-flex items-center gap-1 rounded bg-severity-critical/12 px-1.5 py-0.5 text-[0.625rem] font-medium text-severity-critical">
                              <Mail className="h-2.5 w-2.5" aria-hidden="true" /> MX
                            </span>
                          )}
                        </div>
                        <p className="mt-1 truncate font-mono text-xs text-muted-foreground">
                          {r.addresses[0] ?? "not resolving"}
                          {r.mx[0] ? ` · ${r.mx[0]}` : ""}
                          {r.nameservers[0] ? ` · ${r.nameservers[0]}` : ""}
                        </p>
                      </div>

                      <span className={cn("shrink-0 rounded-md px-2 py-0.5 text-xs font-medium", meta.chip)}>
                        {meta.label}
                      </span>

                      {/* Opened in a new tab with rel=noreferrer: never leak the
                          analyst's session or referrer to a hostile clone. */}
                      <a
                        href={`https://${r.domain}`}
                        target="_blank"
                        rel="noopener noreferrer nofollow"
                        aria-label={`Open ${r.domain} in a new tab`}
                        className="shrink-0 rounded p-1.5 text-muted-foreground transition-colors hover:bg-surface-3 hover:text-foreground"
                      >
                        <ExternalLink className="h-3.5 w-3.5" />
                      </a>
                    </li>
                  );
                })}
              </ul>
            )}

            <div className="flex flex-wrap gap-x-6 gap-y-2 border-t border-hairline p-4 text-xs text-muted-foreground">
              {(Object.keys(RISK_META) as Risk[]).map((r) => (
                <span key={r} className="inline-flex items-start gap-2">
                  <span className={cn("mt-1 h-2 w-2 shrink-0 rounded-full", RISK_META[r].dot)} />
                  <span>
                    <strong className="font-medium text-foreground">{RISK_META[r].label}</strong>
                    {" — "}
                    {RISK_META[r].blurb}
                  </span>
                </span>
              ))}
            </div>
          </div>

          <p className="text-xs text-muted-foreground">
            Swept {new Date(data.scannedAt).toLocaleString()} · {data.generated} candidates generated
            from <span className="font-mono">{data.target}</span>. Some results may be defensive
            registrations you already own.
          </p>
        </>
      )}
    </div>
  );
}
