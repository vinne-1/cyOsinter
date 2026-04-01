import { useQuery } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Shield } from "lucide-react";

export function IPReputationPanel() {
  const { selectedWorkspaceId } = useDomain();
  const { data: ipEnrichment = {}, isLoading } = useQuery<
    Record<string, {
      abuseipdb?: {
        ipAddress?: string;
        abuseConfidenceScore?: number;
        totalReports?: number;
        countryCode?: string;
        countryName?: string;
        isp?: string;
        usageType?: string;
        domain?: string;
      } | null;
      virustotal?: {
        ip?: string;
        malicious?: number;
        suspicious?: number;
        harmless?: number;
        undetected?: number;
        as_owner?: string;
        country?: string;
        continent?: string;
      } | null;
    }>
  >({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/ip-enrichment`],
    enabled: !!selectedWorkspaceId,
  });
  const entries = Object.entries(ipEnrichment);
  if (isLoading) {
    return (
      <div className="space-y-4" data-testid="panel-ip-reputation">
        <div className="flex items-center gap-3 mb-4">
          <div className="flex items-center justify-center w-9 h-9 rounded-md bg-primary/10 flex-shrink-0">
            <Shield className="w-5 h-5 text-primary" />
          </div>
          <h3 className="text-base font-semibold">IP Reputation (AbuseIPDB / VirusTotal)</h3>
        </div>
        <Skeleton className="h-48 w-full" />
      </div>
    );
  }
  if (entries.length === 0) {
    return (
      <div className="space-y-4" data-testid="panel-ip-reputation">
        <div className="flex items-center gap-3 mb-4">
          <div className="flex items-center justify-center w-9 h-9 rounded-md bg-primary/10 flex-shrink-0">
            <Shield className="w-5 h-5 text-primary" />
          </div>
          <h3 className="text-base font-semibold">IP Reputation (AbuseIPDB / VirusTotal)</h3>
        </div>
        <Card>
          <CardContent className="py-12 text-center">
            <Shield className="w-12 h-12 text-muted-foreground/40 mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">No public IPs found yet</p>
            <p className="text-xs text-muted-foreground mt-1">Run a scan to discover IPs and enrich them with threat intelligence</p>
          </CardContent>
        </Card>
      </div>
    );
  }
  return (
    <div className="space-y-4" data-testid="panel-ip-reputation">
      <div className="flex items-center gap-3 mb-4">
        <div className="flex items-center justify-center w-9 h-9 rounded-md bg-primary/10 flex-shrink-0">
          <Shield className="w-5 h-5 text-primary" />
        </div>
        <h3 className="text-base font-semibold">IP Reputation (AbuseIPDB / VirusTotal)</h3>
      </div>
      <p className="text-sm text-muted-foreground">
        Threat intelligence from AbuseIPDB and VirusTotal for public IPs discovered in this workspace.
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {entries.map(([ip, data]) => {
          const abuse = data?.abuseipdb;
          const vt = data?.virustotal;
          const score = abuse?.abuseConfidenceScore ?? -1;
          const scoreColor =
            score < 0 ? "" : score < 25 ? "bg-green-600/15 text-green-400" : score <= 75 ? "bg-yellow-600/15 text-yellow-400" : "bg-red-600/15 text-red-400";
          return (
            <Card key={ip}>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <CardTitle className="text-sm font-mono">{ip}</CardTitle>
                  <div className="flex gap-2 flex-wrap">
                    {abuse && (
                      <Badge variant="outline" className={`text-xs border-0 font-mono no-default-hover-elevate no-default-active-elevate ${scoreColor}`}>
                        AbuseIPDB: {abuse.abuseConfidenceScore}%
                      </Badge>
                    )}
                    {vt && (vt.malicious !== undefined || vt.suspicious !== undefined) && (
                      <Badge variant="outline" className="text-xs border-0 no-default-hover-elevate no-default-active-elevate bg-slate-600/15">
                        VT: {vt.malicious ?? 0} mal / {vt.suspicious ?? 0} susp
                      </Badge>
                    )}
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                {abuse && (
                  <div className="space-y-1">
                    <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">AbuseIPDB</h4>
                    <div className="grid grid-cols-2 gap-2 text-sm">
                      {abuse.countryName && <div><span className="text-muted-foreground">Country:</span> {abuse.countryName}</div>}
                      {abuse.isp && <div><span className="text-muted-foreground">ISP:</span> {abuse.isp}</div>}
                      {abuse.usageType && <div><span className="text-muted-foreground">Usage:</span> {abuse.usageType}</div>}
                      {abuse.domain && <div><span className="text-muted-foreground">Domain:</span> {abuse.domain}</div>}
                      {abuse.totalReports !== undefined && <div><span className="text-muted-foreground">Reports:</span> {abuse.totalReports}</div>}
                    </div>
                  </div>
                )}
                {vt && (
                  <div className="space-y-1">
                    <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">VirusTotal</h4>
                    <div className="grid grid-cols-2 gap-2 text-sm">
                      {vt.country && <div><span className="text-muted-foreground">Country:</span> {vt.country}</div>}
                      {vt.as_owner && <div><span className="text-muted-foreground">AS Owner:</span> {vt.as_owner}</div>}
                      <div><span className="text-muted-foreground">Malicious:</span> {vt.malicious ?? 0}</div>
                      <div><span className="text-muted-foreground">Suspicious:</span> {vt.suspicious ?? 0}</div>
                      <div><span className="text-muted-foreground">Harmless:</span> {vt.harmless ?? 0}</div>
                    </div>
                  </div>
                )}
                {!abuse && !vt && (
                  <p className="text-xs text-muted-foreground">No enrichment data (configure API keys in Integrations)</p>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
