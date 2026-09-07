import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";
import { Smartphone, Loader2, ExternalLink, ShieldCheck } from "lucide-react";

interface ReconModule {
  id: string;
  generatedAt?: string;
  data?: unknown;
}

interface StoreApp {
  name: string;
  seller: string;
  sellerUrl?: string;
  bundleId?: string;
  storeUrl?: string;
  ratings?: number;
  reason: string;
  brandInBundleId?: boolean;
}

interface MobileAppData {
  brand: string;
  official: StoreApp[];
  thirdParty: StoreApp[];
  storesChecked: string[];
  storesNotChecked: Array<{ store: string; reason: string }>;
  scannedAt?: string;
}

/**
 * App-store sweep for apps carrying the workspace's brand.
 *
 * Two things this panel is careful about, both mirroring the detector:
 *  - it never labels a third-party app "fake". Payment integrations, resellers
 *    and partner clients legitimately carry another company's brand, so the
 *    question put to the reader is "is this authorised?", not "is this an
 *    attack?";
 *  - it states which stores were NOT searched. Android has no free official
 *    search API, and a reader must be able to tell "not checked" from "nothing
 *    there".
 */
export function MobileAppsPanel({ workspaceId }: { workspaceId: string | null }) {
  const { toast } = useToast();

  const { data: module, isLoading } = useQuery<ReconModule | null>({
    queryKey: [`/api/workspaces/${workspaceId}/mobile-apps`],
    enabled: !!workspaceId,
  });

  const sweep = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/workspaces/${workspaceId}/mobile-apps`, {}, { timeoutMs: 60_000 });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceId}/mobile-apps`] });
      toast({ title: "Sweep complete", description: "App store results updated." });
    },
    onError: (err: Error) => {
      toast({ title: "Sweep failed", description: err.message, variant: "destructive" });
    },
  });

  const data = (module?.data ?? null) as MobileAppData | null;

  const AppRow = ({ app, official }: { app: StoreApp; official: boolean }) => (
    <li className="rounded border border-hairline p-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium">{app.name}</span>
        {official ? (
          <Badge variant="secondary" className="text-[10px]">confirmed yours</Badge>
        ) : app.brandInBundleId ? (
          <Badge variant="destructive" className="text-[10px]">brand in identifier</Badge>
        ) : null}
        {app.storeUrl && (
          <a
            href={app.storeUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-[11px] underline"
          >
            App Store <ExternalLink className="h-3 w-3" aria-hidden="true" />
          </a>
        )}
      </div>
      <p className="mt-1 text-[11px] text-muted-foreground">
        Published by <span className="font-medium">{app.seller}</span>
        {typeof app.ratings === "number" && app.ratings > 0 ? ` · ${app.ratings.toLocaleString()} ratings` : ""}
      </p>
      <p className="mt-0.5 text-[11px] text-muted-foreground">{app.reason}</p>
    </li>
  );

  return (
    <section className="rounded-xl border border-hairline bg-surface-2">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-hairline p-4">
        <div className="flex items-center gap-2">
          <Smartphone className="h-4 w-4" aria-hidden="true" />
          <h2 className="text-sm font-semibold">Mobile apps using your brand</h2>
          <span className="text-xs text-muted-foreground">Apple App Store · no API key required</span>
        </div>
        <Button
          size="sm"
          variant="outline"
          onClick={() => sweep.mutate()}
          disabled={sweep.isPending || !workspaceId}
          data-testid="button-sweep-mobile-apps"
        >
          {sweep.isPending
            ? <><Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" /> Searching…</>
            : "Search app stores"}
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
            No sweep has run yet. This searches the Apple App Store for apps published under your brand name and
            confirms which are yours from the developer's own listed website.
          </p>
        ) : (
          <div className="space-y-5">
            {data.thirdParty?.length > 0 && (
              <div className="space-y-2">
                <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Published by others ({data.thirdParty.length})
                </p>
                <p className="text-xs text-muted-foreground">
                  These carry the “{data.brand}” name but the developer's website does not tie back to your domain.
                  That does not make them fake — integrations, resellers and partner clients legitimately use another
                  company's brand. Confirm each one is authorised.
                </p>
                <ul
                  tabIndex={0}
                  aria-label="Apps published by parties other than the domain owner"
                  className="max-h-72 space-y-2 overflow-auto"
                >
                  {data.thirdParty.slice(0, 30).map((a) => (
                    <AppRow key={`${a.name}-${a.seller}`} app={a} official={false} />
                  ))}
                </ul>
              </div>
            )}

            {data.official?.length > 0 && (
              <div className="space-y-2">
                <p className="flex items-center gap-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
                  Confirmed yours ({data.official.length})
                </p>
                <ul
                  tabIndex={0}
                  aria-label="Apps confirmed published by the domain owner"
                  className="max-h-56 space-y-2 overflow-auto"
                >
                  {data.official.map((a) => (
                    <AppRow key={`${a.name}-${a.seller}`} app={a} official />
                  ))}
                </ul>
              </div>
            )}

            {data.thirdParty?.length === 0 && data.official?.length === 0 && (
              <p className="text-xs text-muted-foreground">
                No apps on the Apple App Store carry the “{data.brand}” name.
              </p>
            )}

            {/* Coverage stated, never implied — "not checked" must not read as "nothing there". */}
            {data.storesNotChecked?.length > 0 && (
              <div className="rounded border border-hairline p-2.5">
                <p className="text-[11px] font-medium">Not covered by this sweep</p>
                <ul className="mt-1 space-y-1">
                  {data.storesNotChecked.map((s) => (
                    <li key={s.store} className="text-[11px] text-muted-foreground">
                      <span className="font-medium">{s.store}</span> — {s.reason}
                    </li>
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
