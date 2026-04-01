import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Globe } from "lucide-react";
import type { ReconModule } from "@shared/schema";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ModuleHeader, StatusIcon } from "./shared";

export function WebPresencePanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as Record<string, any>;
  const totalSubdomains = d.totalSubdomains ?? d.totalSubdomainsEnumerated ?? 0;
  const discoveredDomains = d.discoveredDomains ?? (Array.isArray(d.liveSubdomains) ? d.liveSubdomains.map((domain: string) => ({ domain, ip: "-", cdn: "None", waf: false, newSinceLastRun: false })) : []);
  const liveServicesCount = d.liveServices != null ? (Array.isArray(d.liveServices) ? d.liveServices.length : Number(d.liveServices)) : discoveredDomains.length;
  return (
    <div className="space-y-4" data-testid="panel-web-presence">
      <ModuleHeader title="Web Presence Map" icon={Globe} confidence={mod.confidence || 0} generatedAt={mod.generatedAt} />
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card><CardContent className="p-3 text-center"><p className="text-lg font-semibold">{totalSubdomains}</p><p className="text-xs text-muted-foreground">Total Subdomains</p></CardContent></Card>
        <Card><CardContent className="p-3 text-center"><p className="text-lg font-semibold text-green-400">{d.newSinceLastRun ?? 0}</p><p className="text-xs text-muted-foreground">New Since Last Run</p></CardContent></Card>
        <Card><CardContent className="p-3 text-center"><p className="text-lg font-semibold">{liveServicesCount}</p><p className="text-xs text-muted-foreground">Live Services</p></CardContent></Card>
        <Card><CardContent className="p-3 text-center"><p className="text-lg font-semibold">{(d.screenshots || []).length}</p><p className="text-xs text-muted-foreground">Screenshots</p></CardContent></Card>
      </div>
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Subdomain Inventory</CardTitle></CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Domain</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead>CDN</TableHead>
                  <TableHead>WAF</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {discoveredDomains.map((dom: any, i: number) => (
                  <TableRow key={i}>
                    <TableCell className="font-mono text-sm">{dom.domain}</TableCell>
                    <TableCell className="font-mono text-sm text-muted-foreground">{dom.ip}</TableCell>
                    <TableCell>{dom.cdn ? <Badge variant="outline" className="text-xs no-default-hover-elevate no-default-active-elevate">{dom.cdn}</Badge> : <span className="text-xs text-muted-foreground">None</span>}</TableCell>
                    <TableCell><StatusIcon pass={dom.waf} /></TableCell>
                    <TableCell>{dom.newSinceLastRun ? <Badge variant="outline" className="text-xs bg-green-600/15 text-green-400 border-0 no-default-hover-elevate no-default-active-elevate">New</Badge> : <span className="text-xs text-muted-foreground">Known</span>}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
      {d.subdomainBruteforce && (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Subdomain Bruteforce</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            <p className="text-xs text-muted-foreground">Wordlist: {d.subdomainBruteforce.wordlistSource}</p>
            <div className="flex flex-wrap gap-3">
              <span className="text-sm"><strong>{d.subdomainBruteforce.tried}</strong> tried</span>
              <span className="text-sm"><strong>{d.subdomainBruteforce.resolved?.length ?? 0}</strong> resolved</span>
              <span className="text-sm text-green-500"><strong>{d.subdomainBruteforce.liveWithHttp?.length ?? 0}</strong> with HTTP(S)</span>
            </div>
            {(d.subdomainBruteforce.resolved?.length ?? 0) > 0 && (
              <div className="max-h-48 overflow-auto">
                <p className="text-xs font-medium text-muted-foreground mb-1">Resolved subdomains</p>
                <ul className="text-xs font-mono space-y-0.5">
                  {(d.subdomainBruteforce.resolved || []).slice(0, 50).map((s: string, i: number) => (
                    <li key={i}>{s}{(d.subdomainBruteforce.liveWithHttp || []).includes(s) && <span className="text-green-500 ml-1">(live)</span>}</li>
                  ))}
                  {(d.subdomainBruteforce.resolved?.length ?? 0) > 50 && <li className="text-muted-foreground">+ {(d.subdomainBruteforce.resolved?.length ?? 0) - 50} more</li>}
                </ul>
              </div>
            )}
          </CardContent>
        </Card>
      )}
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Screenshot Gallery</CardTitle></CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {(d.screenshots || []).map((ss: any, i: number) => (
              <div key={i} className="p-3 rounded-md bg-muted/40 space-y-1">
                <div className="w-full h-20 rounded-md bg-muted flex items-center justify-center">
                  <Globe className="w-6 h-6 text-muted-foreground/30" />
                </div>
                <p className="text-sm font-medium">{ss.page}</p>
                <p className="text-xs text-muted-foreground font-mono">{ss.host}</p>
                <p className="text-xs text-muted-foreground">{ss.description}</p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
