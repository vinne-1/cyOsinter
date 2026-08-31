import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { Code2, Loader2, ShieldCheck, KeyRound, ExternalLink, Info } from "lucide-react";
import type { ReconModule } from "@shared/schema";

interface CodeLeakHit {
  repository: string;
  path: string;
  htmlUrl: string;
  matchedTerm: string;
  secrets: Array<{ name: string; severity: string; redacted: string }>;
  hasSecret: boolean;
}

interface CodeLeakData {
  terms: string[];
  filesInspected: number;
  hits: CodeLeakHit[];
  counts: { withSecrets: number; mentionsOnly: number };
  scannedAt: string;
}

/**
 * Source-code leak sweep for the selected workspace.
 *
 * Draws a hard line between a file that carries a credential and one that merely
 * mentions the domain — the latter is usually an open-source project referencing
 * you, and treating the two alike would bury the real leaks.
 */
export function CodeLeakPanel({ workspaceId }: { workspaceId: string | null }) {
  const { toast } = useToast();

  const { data, isLoading } = useQuery<{ module: ReconModule | null; configured: boolean }>({
    queryKey: [`/api/workspaces/${workspaceId}/code-leaks`],
    enabled: !!workspaceId,
  });

  const sweep = useMutation({
    mutationFn: async () => {
      // GitHub code search is rate limited to 10/min and the sweep paces itself
      // between terms, so allow generous time.
      const res = await apiRequest("POST", `/api/workspaces/${workspaceId}/code-leaks`, {}, { timeoutMs: 240_000 });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceId}/code-leaks`] });
      toast({ title: "Sweep complete", description: "Source-code leak results updated." });
    },
    onError: (err: Error) => toast({ title: "Sweep failed", description: err.message, variant: "destructive" }),
  });

  const result = (data?.module?.data ?? null) as CodeLeakData | null;
  const configured = data?.configured ?? false;

  return (
    <section className="rounded-xl border border-hairline bg-surface-2">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-hairline p-4">
        <div className="flex items-center gap-2">
          <Code2 className="h-4 w-4 text-primary" aria-hidden="true" />
          <h2 className="text-sm font-semibold">Source-code leaks</h2>
          <span className="text-xs text-muted-foreground">Public repositories mentioning your domains</span>
        </div>
        <Button
          size="sm"
          variant="outline"
          onClick={() => sweep.mutate()}
          disabled={sweep.isPending || !workspaceId || !configured}
          data-testid="button-sweep-code-leaks"
        >
          {sweep.isPending
            ? <><Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" /> Sweeping…</>
            : "Run sweep"}
        </Button>
      </div>

      {!configured ? (
        // Deliberately NOT an empty state: "nothing found" and "never ran" must
        // not look the same for a security check.
        <div className="flex items-start gap-3 p-5">
          <Info className="mt-0.5 h-5 w-5 shrink-0 text-severity-medium" aria-hidden="true" />
          <div>
            <p className="text-sm font-medium">Not configured — this check has not run</p>
            <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
              GitHub's code search API requires authentication. Set{" "}
              <code className="rounded bg-surface-inset px-1 py-0.5 font-mono">GITHUB_TOKEN</code> to a
              personal access token and restart. No scopes are needed to search public code, and the
              token is free.
            </p>
          </div>
        </div>
      ) : isLoading ? (
        <div className="p-4"><Skeleton className="h-24 rounded-lg" /></div>
      ) : !result ? (
        <p className="p-8 text-center text-sm text-muted-foreground">
          Not swept yet. This searches public repositories for your domains and scans what it finds
          with the same detectors used against your websites.
        </p>
      ) : result.hits.length === 0 ? (
        <div className="flex items-start gap-3 p-5">
          <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-severity-ok" aria-hidden="true" />
          <div>
            <p className="text-sm font-medium">No public code references found</p>
            <p className="mt-1 text-xs text-muted-foreground">
              Searched {result.terms.length} term{result.terms.length === 1 ? "" : "s"},
              inspected {result.filesInspected} file{result.filesInspected === 1 ? "" : "s"}.
            </p>
          </div>
        </div>
      ) : (
        <>
          {result.counts.withSecrets > 0 && (
            <div className="flex items-start gap-3 border-b border-severity-critical/25 bg-severity-critical/10 p-4">
              <KeyRound className="mt-0.5 h-5 w-5 shrink-0 text-severity-critical" aria-hidden="true" />
              <div>
                <p className="text-sm font-semibold text-severity-critical">
                  {result.counts.withSecrets} file{result.counts.withSecrets === 1 ? "" : "s"} contain
                  {result.counts.withSecrets === 1 ? "s" : ""} credential material
                </p>
                <p className="mt-1 text-xs text-muted-foreground">
                  Rotate first, then remove. Deleting a commit does not revoke a key that is already
                  published.
                </p>
              </div>
            </div>
          )}

          <ul className="divide-y divide-hairline">
            {result.hits.map((h, i) => (
              <li key={`${h.repository}-${h.path}-${i}`} className="flex flex-wrap items-start gap-x-4 gap-y-2 p-4">
                <span
                  aria-hidden="true"
                  className={cn(
                    "mt-1.5 h-2 w-2 shrink-0 rounded-full",
                    h.hasSecret ? "bg-severity-critical" : "bg-severity-info",
                  )}
                />
                <div className="min-w-0 flex-1">
                  <p className="truncate font-mono text-sm font-medium">{h.repository}</p>
                  <p className="mt-0.5 truncate font-mono text-xs text-muted-foreground">{h.path}</p>
                  {h.secrets.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {h.secrets.map((s) => (
                        <span
                          key={s.name}
                          className="inline-flex items-center gap-1 rounded bg-severity-critical/12 px-1.5 py-0.5 font-mono text-[0.6875rem] text-severity-critical"
                          // The value is masked server-side; the title shows the
                          // masked form too, never the credential.
                          title={s.redacted}
                        >
                          <KeyRound className="h-2.5 w-2.5" aria-hidden="true" />
                          {s.name}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                <span
                  className={cn(
                    "shrink-0 rounded-md px-2 py-0.5 text-xs font-medium",
                    h.hasSecret
                      ? "bg-severity-critical/15 text-severity-critical ring-1 ring-inset ring-severity-critical/25"
                      : "bg-severity-info/15 text-severity-info ring-1 ring-inset ring-severity-info/25",
                  )}
                >
                  {h.hasSecret ? "Credential" : "Mention"}
                </span>

                {h.htmlUrl && (
                  <a
                    href={h.htmlUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label={`Open ${h.repository}/${h.path} on GitHub`}
                    className="shrink-0 rounded p-1.5 text-muted-foreground transition-colors hover:bg-surface-3 hover:text-foreground"
                  >
                    <ExternalLink className="h-3.5 w-3.5" />
                  </a>
                )}
              </li>
            ))}
          </ul>

          <p className="border-t border-hairline p-4 text-xs text-muted-foreground">
            Swept {new Date(result.scannedAt).toLocaleString()} · {result.filesInspected} files
            inspected · {result.counts.mentionsOnly} mention
            {result.counts.mentionsOnly === 1 ? "" : "s"} without credentials. Secret values are
            masked before storage and never appear in reports.
          </p>
        </>
      )}
    </section>
  );
}
