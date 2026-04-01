import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Building2, MapPin } from "lucide-react";
import type { ReconModule } from "@shared/schema";
import { ModuleHeader, EvidenceLink, StatusIcon } from "./shared";

export function OrgIdentityPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as Record<string, any>;
  return (
    <div className="space-y-4" data-testid="panel-org-identity">
      <ModuleHeader title="Organization Identity" icon={Building2} confidence={mod.confidence || 0} generatedAt={mod.generatedAt} />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardContent className="p-4 space-y-3">
            <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Domain & Brand</h4>
            <div className="space-y-2">
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm text-muted-foreground">Canonical Domain</span>
                <span className="text-sm font-mono">{d.canonicalDomain}</span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm text-muted-foreground">Parent Domains</span>
                <div className="flex gap-1 flex-wrap">
                  {(d.parentDomains || []).map((dom: string) => (
                    <Badge key={dom} variant="outline" className="text-xs font-mono no-default-hover-elevate no-default-active-elevate">{dom}</Badge>
                  ))}
                </div>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm text-muted-foreground">Brand Aliases</span>
                <span className="text-sm">{(d.brandAliases || []).join(", ")}</span>
              </div>
            </div>
            {(d.legalOrgNames || []).length > 0 && (
              <div className="space-y-1 pt-2 border-t">
                <h5 className="text-xs text-muted-foreground">Legal Org Names</h5>
                {d.legalOrgNames.map((org: any, i: number) => (
                  <div key={i} className="flex items-center justify-between gap-2 text-sm">
                    <span>{org.name}</span>
                    <span className="text-xs text-muted-foreground">{org.source} ({org.confidence}%)</span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 space-y-3">
            <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">WHOIS / RDAP</h4>
            {d.whois && (
              <div className="space-y-2">
                {[
                  ["Registrar", d.whois.registrar],
                  ["Registered", d.whois.registrationDate],
                  ["Expires", d.whois.expirationDate],
                  ["Privacy Masked", d.whois.privacyMasked ? "Yes" : "No"],
                ].map(([label, value]) => (
                  <div key={label as string} className="flex items-center justify-between gap-2">
                    <span className="text-sm text-muted-foreground">{label}</span>
                    <span className="text-sm font-mono">{value}</span>
                  </div>
                ))}
                <div>
                  <span className="text-xs text-muted-foreground">Name Servers</span>
                  <div className="flex gap-1 flex-wrap mt-1">
                    {(d.whois.nameServers || []).map((ns: string) => (
                      <Badge key={ns} variant="outline" className="text-xs font-mono no-default-hover-elevate no-default-active-elevate">{ns}</Badge>
                    ))}
                  </div>
                </div>
                <EvidenceLink url={d.whois.evidenceUrl} label="WHOIS Record" />
              </div>
            )}
          </CardContent>
        </Card>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardContent className="p-4 space-y-3">
            <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">ASN & ISP Mapping</h4>
            {(d.asn || []).map((a: any, i: number) => (
              <div key={i} className="p-2 rounded-md bg-muted/40 space-y-1">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-mono">{a.number}</span>
                  <span className="text-sm">{a.name}</span>
                </div>
                <div className="flex gap-1 flex-wrap">
                  {(a.ipRanges || []).map((ip: string) => (
                    <Badge key={ip} variant="outline" className="text-xs font-mono no-default-hover-elevate no-default-active-elevate">{ip}</Badge>
                  ))}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 space-y-3">
            <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Geographies</h4>
            {(d.geographies || []).map((geo: any, i: number) => (
              <div key={i} className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/40">
                <div className="flex items-center gap-2">
                  <MapPin className="w-3 h-3 text-muted-foreground" />
                  <span className="text-sm">{geo.location}</span>
                </div>
                <span className="text-xs text-muted-foreground">{geo.source} ({geo.confidence}%)</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
