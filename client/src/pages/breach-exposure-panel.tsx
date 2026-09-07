import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";
import { DatabaseZap, Loader2, ShieldAlert } from "lucide-react";

interface ReconModule {
  id: string;
  generatedAt?: string;
  data?: unknown;
}

interface BreachRecord {
  name: string;
  title: string;
  breachDate: string;
  pwnCount: number;
  dataClasses: string[];
  stealerLog: boolean;
  spamList: boolean;
  exposedCredentials: boolean;
}

interface BreachData {
  domain: string;
  confirmed: BreachRecord[];
  unverified: BreachRecord[];
  fabricated: BreachRecord[];
  notCovered: string[];
  scannedAt?: string;
}

/**
 * Public breach-corpus exposure for the workspace's own domain.
 *
 * Two things this panel is careful about, both mirroring the detector:
 *  - it separates records the corpus has VERIFIED from those it has not, and
 *    never shows a fabricated record as an exposure at all;
 *  - it states what the check cannot see. Per-account exposure needs a paid
 *    subscription and proof of domain ownership, so a clean result here must
 *    not be read as "no employee credentials are circulating".
 */
export function BreachExposurePanel({ workspaceId }: { workspaceId: string | null }) {
  const { toast } = useToast();

  const { data: module, isLoading } = useQuery<ReconModule | null>({
    queryKey: [`/api/workspaces/${workspaceId}/breach-exposure`],
    enabled: !!workspaceId,
  });

  const check = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/workspaces/${workspaceId}/breach-exposure`, {}, { timeoutMs: 60_000 });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceId}/breach-exposure`] });
      toast({ title: "Check complete", description: "Breach corpus results updated." });
    },
    onError: (err: Error) => {
      toast({ title: "Check failed", description: err.message, variant: "destructive" });
    },
  });

  const data = (module?.data ?? null) as BreachData | null;

  const BreachRow = ({ b, verified }: { b: BreachRecord; verified: boolean }) => (
    <li className="rounded border border-hairline p-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium">{b.title || b.name}</span>
        <span className="text-[11px] text-muted-foreground">{b.breachDate?.slice(0, 10)}</span>
        {b.exposedCredentials && (
          <Badge variant="destructive" className="text-[10px]">credentials exposed</Badge>
        )}
        {b.stealerLog && <Badge variant="secondary" className="text-[10px]">infostealer</Badge>}
        {b.spamList && <Badge variant="secondary" className="text-[10px]">spam list</Badge>}
        {!verified && <Badge variant="secondary" className="text-[10px]">unverified</Badge>}
      </div>
      <p className="mt-1 text-[11px] text-muted-foreground">
        {b.pwnCount > 0 ? `${b.pwnCount.toLocaleString("en-US")} accounts` : "account count not published"}
        {b.dataClasses?.length ? ` · ${b.dataClasses.slice(0, 5).join(", ")}` : ""}
      </p>
    </li>
  );

  return (
    <section className="rounded-xl border border-hairline bg-surface-2">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-hairline p-4">
        <div className="flex items-center gap-2">
          <DatabaseZap className="h-4 w-4" aria-hidden="true" />
          <h2 className="text-sm font-semibold">Breach corpus exposure</h2>
          <span className="text-xs text-muted-foreground">
            Public breach catalogue · no API key required
          </span>
        </div>
        <Button
          size="sm"
          variant="outline"
          onClick={() => check.mutate()}
          disabled={check.isPending || !workspaceId}
          data-testid="button-check-breach-exposure"
        >
          {check.isPending
            ? <><Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" /> Checking…</>
            : "Check exposure"}
        </Button>
      </div>

      <div className="p-4">
        {isLoading ? (
          <div className="space-y-2">
            <Skeleton className="h-4 w-2/3" />
            <Skeleton className="h-4 w-1/2" />
          </div>
        ) : !data ? (
          <p className="text-xs text-muted-foreground">
            No check has run yet. This asks the public breach catalogue whether your organisation appears in it as
            the breached party. It reads incident metadata only — no password, hash or email address is sent or
            received.
          </p>
        ) : (
          <div className="space-y-5">
            {data.confirmed?.length > 0 && (
              <div className="space-y-2">
                <p className="flex items-center gap-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  <ShieldAlert className="h-3.5 w-3.5" aria-hidden="true" />
                  Confirmed breaches ({data.confirmed.length})
                </p>
                <ul
                  tabIndex={0}
                  aria-label="Confirmed breach records naming this organisation"
                  className="max-h-64 space-y-2 overflow-auto"
                >
                  {data.confirmed.map((b) => <BreachRow key={b.name} b={b} verified />)}
                </ul>
                <p className="text-xs text-muted-foreground">
                  These are historical incidents already in the public record. They do not indicate a current,
                  ongoing compromise — but any account whose password has not changed since these dates should be
                  treated as exposed.
                </p>
              </div>
            )}

            {data.unverified?.length > 0 && (
              <div className="space-y-2">
                <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Unverified records ({data.unverified.length})
                </p>
                <ul
                  tabIndex={0}
                  aria-label="Unverified breach records"
                  className="max-h-48 space-y-2 overflow-auto"
                >
                  {data.unverified.map((b) => <BreachRow key={b.name} b={b} verified={false} />)}
                </ul>
                <p className="text-xs text-muted-foreground">
                  The corpus maintainer has not been able to confirm these are genuine. Unverified data is sometimes
                  recycled or invented, so treat them as leads to corroborate rather than as established fact.
                </p>
              </div>
            )}

            {data.confirmed?.length === 0 && data.unverified?.length === 0 && (
              <p className="text-xs text-muted-foreground">
                No records in the public breach catalogue name {data.domain}.
              </p>
            )}

            {/* Coverage stated, never implied — a clean result is narrower than it looks. */}
            {data.notCovered?.length > 0 && (
              <div className="rounded border border-hairline p-2.5">
                <p className="text-[11px] font-medium">Not covered by this check</p>
                <ul className="mt-1 space-y-1">
                  {data.notCovered.map((n) => (
                    <li key={n} className="text-[11px] text-muted-foreground">{n}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>
    </section>
  );
}
