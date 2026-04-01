import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Network } from "lucide-react";
import type { ReconModule } from "@shared/schema";
import { ModuleHeader } from "./shared";

export function BGPRoutingPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as {
    ips?: Record<string, {
      ip?: string;
      prefixes?: Array<{ prefix?: string; cidr?: number; asn?: { asn?: number; name?: string; country_code?: string } }>;
      rir_allocation?: { rir_name?: string; country_code?: string; prefix?: string } | null;
      maxmind?: { country_code?: string; city?: string | null } | null;
    } | null>;
  };
  const ips = d?.ips ?? {};
  const entries = Object.entries(ips).filter(([, v]) => v != null);

  return (
    <div className="space-y-4" data-testid="panel-bgp-routing">
      <ModuleHeader title="BGP Routing (BGPView)" icon={Network} confidence={mod.confidence || 0} generatedAt={mod.generatedAt} />
      <p className="text-sm text-muted-foreground">
        BGP and routing data from BGPView API for public IPs discovered during the scan. Free, no API key required.
      </p>
      {entries.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <Network className="w-12 h-12 text-muted-foreground/40 mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">No BGP data for this workspace</p>
            <p className="text-xs text-muted-foreground mt-1">Run a scan that discovers public IPs to populate BGP routing information</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {entries.map(([ip, data]) => {
            if (!data) return null;
            const prefixes = data.prefixes ?? [];
            const rir = data.rir_allocation;
            const maxmind = data.maxmind;
            return (
              <Card key={ip}>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-mono">{ip}</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {prefixes.length > 0 && (
                    <div className="space-y-1">
                      <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Prefixes & ASN</h4>
                      <div className="space-y-2">
                        {prefixes.map((p, i) => (
                          <div key={i} className="p-2 rounded-md bg-muted/40 space-y-1">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-sm font-mono">{p.prefix}</span>
                              {p.asn && (
                                <Badge variant="outline" className="text-xs no-default-hover-elevate no-default-active-elevate">
                                  AS{p.asn.asn} {p.asn.name ?? ""}
                                </Badge>
                              )}
                            </div>
                            {p.asn?.country_code && (
                              <p className="text-xs text-muted-foreground">Country: {p.asn.country_code}</p>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {rir && (
                    <div className="space-y-1">
                      <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">RIR Allocation</h4>
                      <div className="grid grid-cols-2 gap-2 text-sm">
                        {rir.rir_name && <div><span className="text-muted-foreground">RIR:</span> {rir.rir_name}</div>}
                        {rir.country_code && <div><span className="text-muted-foreground">Country:</span> {rir.country_code}</div>}
                        {rir.prefix && <div><span className="text-muted-foreground">Prefix:</span> {rir.prefix}</div>}
                      </div>
                    </div>
                  )}
                  {maxmind && (maxmind.country_code || maxmind.city) && (
                    <div className="space-y-1">
                      <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Geo (MaxMind)</h4>
                      <div className="grid grid-cols-2 gap-2 text-sm">
                        {maxmind.country_code && <div><span className="text-muted-foreground">Country:</span> {maxmind.country_code}</div>}
                        {maxmind.city && <div><span className="text-muted-foreground">City:</span> {maxmind.city}</div>}
                      </div>
                    </div>
                  )}
                  {prefixes.length === 0 && !rir && (!maxmind || (!maxmind.country_code && !maxmind.city)) && (
                    <p className="text-xs text-muted-foreground">No BGP data available for this IP</p>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
