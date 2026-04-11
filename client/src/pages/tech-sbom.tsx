import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Server, AlertTriangle, RefreshCw, Package } from "lucide-react";
import { buildUrl } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

interface TechItem {
  id: string;
  host: string;
  product: string;
  version: string | null;
  source: string;
  confidence: number;
  eol: boolean;
  lastSeen: string;
}

interface TechResponse {
  total: number;
  products: Array<{
    product: string;
    versions: Array<{ version: string | null; hosts: string[]; eol: boolean; source: string }>;
    eolCount: number;
  }>;
  items: TechItem[];
}

interface SprawlItem {
  product: string;
  versionCount: number;
  versions: string[];
}

function ProductCard({ product }: { product: TechResponse["products"][number] }) {
  const hasEol = product.eolCount > 0;
  return (
    <Card className={hasEol ? "border-red-500/40" : ""}>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base flex items-center gap-2">
            <Package className="w-4 h-4" />
            {product.product}
          </CardTitle>
          {hasEol && (
            <Badge variant="destructive" className="text-xs">
              {product.eolCount} EOL
            </Badge>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-1">
        {product.versions.slice(0, 6).map((v, i) => (
          <div key={i} className="flex items-center justify-between text-sm">
            <span className="font-mono">{v.version ?? "unknown"}</span>
            <div className="flex items-center gap-2">
              {v.eol && <Badge variant="destructive" className="text-[10px] px-1 py-0">EOL</Badge>}
              <span className="text-muted-foreground text-xs">{v.source}</span>
            </div>
          </div>
        ))}
        {product.versions.length > 6 && (
          <p className="text-xs text-muted-foreground">+{product.versions.length - 6} more versions</p>
        )}
      </CardContent>
    </Card>
  );
}

export default function TechSbomPage() {
  const { selectedWorkspace: ws } = useDomain();
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data: techData, isLoading } = useQuery<TechResponse>({
    queryKey: [`/api/workspaces/${ws?.id}/tech-inventory`],
    enabled: !!ws,
  });

  const { data: sprawl = [] } = useQuery<SprawlItem[]>({
    queryKey: [`/api/workspaces/${ws?.id}/tech-inventory/sprawl`],
    enabled: !!ws,
  });

  const { data: eolItems = [] } = useQuery<TechItem[]>({
    queryKey: [`/api/workspaces/${ws?.id}/tech-inventory/eol`],
    enabled: !!ws,
  });

  const { mutate: refresh, isPending: refreshing } = useMutation({
    mutationFn: () =>
      fetch(buildUrl(`/api/workspaces/${ws!.id}/tech-inventory/refresh`), { method: "POST" }).then((r) => r.json()),
    onSuccess: () => {
      toast({ title: "Tech inventory refresh started" });
      setTimeout(() => qc.invalidateQueries({ queryKey: [`/api/workspaces/${ws?.id}/tech-inventory`] }), 3000);
    },
  });

  if (!ws) return <div className="p-6 text-muted-foreground">Select a workspace.</div>;

  const eolCount = eolItems.length;
  const sprawlCount = sprawl.length;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Software Bill of Materials</h1>
          <p className="text-muted-foreground">Technology fingerprints, version sprawl, and EOL software detected across assets.</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refresh()} disabled={refreshing}>
          <RefreshCw className={`w-4 h-4 mr-2 ${refreshing ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-3 gap-4">
        <Card>
          <CardContent className="p-4 text-center">
            <div className="text-3xl font-bold">{techData?.products.length ?? 0}</div>
            <div className="text-sm text-muted-foreground">Products Detected</div>
          </CardContent>
        </Card>
        <Card className={eolCount > 0 ? "border-red-500/40" : ""}>
          <CardContent className="p-4 text-center">
            <div className={`text-3xl font-bold ${eolCount > 0 ? "text-red-500" : ""}`}>{eolCount}</div>
            <div className="text-sm text-muted-foreground">EOL Versions</div>
          </CardContent>
        </Card>
        <Card className={sprawlCount > 0 ? "border-yellow-500/40" : ""}>
          <CardContent className="p-4 text-center">
            <div className={`text-3xl font-bold ${sprawlCount > 0 ? "text-yellow-500" : ""}`}>{sprawlCount}</div>
            <div className="text-sm text-muted-foreground">Version Sprawl Issues</div>
          </CardContent>
        </Card>
      </div>

      {isLoading ? (
        <p className="text-muted-foreground">Building tech inventory...</p>
      ) : !techData || techData.total === 0 ? (
        <Card><CardContent className="p-8 text-center">
          <Server className="w-12 h-12 mx-auto mb-4 text-muted-foreground/40" />
          <p className="text-muted-foreground">No tech stack data. Run a scan to populate the SBOM.</p>
        </CardContent></Card>
      ) : (
        <>
          {/* EOL alert */}
          {eolCount > 0 && (
            <Card className="border-red-500/40">
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-red-500 text-base">
                  <AlertTriangle className="w-4 h-4" />
                  End-of-Life Software ({eolCount} instances)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {eolItems.map((item) => (
                    <div key={item.id} className="border border-red-500/30 rounded px-2 py-1 text-xs">
                      <span className="font-mono font-medium">{item.product}</span>
                      {item.version && <span className="text-muted-foreground">/{item.version}</span>}
                      <span className="text-muted-foreground ml-1">on {item.host}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Version sprawl */}
          {sprawl.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-base">Version Sprawl</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {sprawl.map((item) => (
                  <div key={item.product} className="flex items-center gap-3 text-sm">
                    <span className="font-mono font-medium w-24 truncate">{item.product}</span>
                    <Badge variant="secondary">{item.versionCount} versions</Badge>
                    <span className="text-muted-foreground text-xs">{item.versions.join(", ")}</span>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {/* Product grid */}
          <div>
            <h2 className="text-lg font-semibold mb-3">All Products ({techData.products.length})</h2>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {techData.products.map((p) => <ProductCard key={p.product} product={p} />)}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
