import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Network,
  ArrowRightLeft,
  Info,
  LayoutDashboard,
  MapPin,
  Cookie,
  FileText,
  List,
  Shield,
  Wifi,
  CheckCircle2,
} from "lucide-react";
import type { ReconModule } from "@shared/schema";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ModuleHeader } from "./shared";

// DNS Overview (OSINT)
export function DNSOverviewPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as Record<string, any>;
  const rec = d.dnsRecords || {};
  return (
    <div className="space-y-4" data-testid="panel-dns-overview">
      <ModuleHeader title="DNS Records" icon={Network} confidence={mod.confidence || 0} generatedAt={mod.generatedAt} />
      {d.dnssec && <div className="flex items-center gap-2"><Shield className="w-4 h-4" /><span className="text-sm">SOA present: {d.dnssec.soaPresent ? "Yes" : "No"}</span></div>}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {rec.a?.length > 0 && <Card><CardHeader className="pb-2"><CardTitle className="text-sm font-medium">A</CardTitle></CardHeader><CardContent><pre className="text-xs font-mono whitespace-pre-wrap">{rec.a.join("\n")}</pre></CardContent></Card>}
        {rec.aaaa?.length > 0 && <Card><CardHeader className="pb-2"><CardTitle className="text-sm font-medium">AAAA</CardTitle></CardHeader><CardContent><pre className="text-xs font-mono whitespace-pre-wrap break-all">{rec.aaaa.join("\n")}</pre></CardContent></Card>}
        {rec.cname?.length > 0 && <Card><CardHeader className="pb-2"><CardTitle className="text-sm font-medium">CNAME</CardTitle></CardHeader><CardContent><pre className="text-xs font-mono">{rec.cname.join("\n")}</pre></CardContent></Card>}
        {rec.ns?.length > 0 && <Card><CardHeader className="pb-2"><CardTitle className="text-sm font-medium">NS</CardTitle></CardHeader><CardContent><pre className="text-xs font-mono">{rec.ns.join("\n")}</pre></CardContent></Card>}
        {rec.mx?.length > 0 && <Card><CardHeader className="pb-2"><CardTitle className="text-sm font-medium">MX</CardTitle></CardHeader><CardContent><pre className="text-xs font-mono">{rec.mx.map((m: any) => `${m.priority} ${m.exchange}`).join("\n")}</pre></CardContent></Card>}
        {rec.soa && <Card><CardHeader className="pb-2"><CardTitle className="text-sm font-medium">SOA</CardTitle></CardHeader><CardContent><pre className="text-xs font-mono">{rec.soa.nsname} {rec.soa.hostmaster}</pre></CardContent></Card>}
        {rec.txt?.length > 0 && <Card className="md:col-span-2"><CardHeader className="pb-2"><CardTitle className="text-sm font-medium">TXT</CardTitle></CardHeader><CardContent><pre className="text-xs font-mono whitespace-pre-wrap break-all">{rec.txt.flat().join("\n")}</pre></CardContent></Card>}
      </div>
    </div>
  );
}

// Redirect Chain (OSINT)
export function RedirectChainPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as Record<string, any>;
  const chain = (d.redirectChain || []) as Array<{ status: number; url: string; location?: string }>;
  return (
    <div className="space-y-4" data-testid="panel-redirect-chain">
      <ModuleHeader title="Redirect Chain" icon={ArrowRightLeft} confidence={mod.confidence || 0} generatedAt={mod.generatedAt} />
      <Card>
        <CardContent className="pt-4 space-y-2">
          {chain.length === 0 ? <p className="text-sm text-muted-foreground">No redirects or single response.</p> : chain.map((step: any, i: number) => (
            <div key={i} className="flex items-center gap-2 flex-wrap">
              <span className="font-mono text-xs bg-muted px-2 py-1 rounded">{step.status}</span>
              <span className="text-sm font-mono truncate max-w-[60%]" title={step.url}>{step.url}</span>
              {step.location && <><ArrowRightLeft className="w-3 h-3 text-muted-foreground flex-shrink-0" /><span className="text-xs text-muted-foreground truncate max-w-[30%]" title={step.location}>{step.location}</span></>}
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

// Domain Info / Whois (OSINT)
export function DomainInfoPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as Record<string, any>;
  const info = d.domainInfo || {};
  const keys = Object.keys(info).filter(k => info[k]);
  return (
    <div className="space-y-4" data-testid="panel-domain-info">
      <ModuleHeader title="Domain Info" icon={Info} confidence={mod.confidence || 0} generatedAt={mod.generatedAt} />
      <Card>
        <CardContent className="pt-4">
          <div className="space-y-2">
            {keys.length === 0 ? <p className="text-sm text-muted-foreground">No whois data.</p> : keys.slice(0, 20).map((k) => (
              <div key={k} className="flex justify-between gap-2 text-sm">
                <span className="text-muted-foreground capitalize">{k.replace(/([A-Z])/g, " $1").trim()}</span>
                <span className="font-mono text-right break-all">{String(info[k]).slice(0, 200)}{String(info[k]).length > 200 ? "..." : ""}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// Website Overview (OSINT: cookies, headers, security.txt, sitemap, robots, tech, social, location, ports)
export function WebsiteOverviewPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as Record<string, any>;
  return (
    <div className="space-y-4" data-testid="panel-website-overview">
      <ModuleHeader title="Website Overview" icon={LayoutDashboard} confidence={mod.confidence || 0} generatedAt={mod.generatedAt} />
      {d.serverLocation && (d.serverLocation.country || d.serverLocation.city) && (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium flex items-center gap-2"><MapPin className="w-4 h-4" />Server Location</CardTitle></CardHeader>
          <CardContent className="text-sm">{[d.serverLocation.city, d.serverLocation.region, d.serverLocation.country].filter(Boolean).join(", ")}{d.serverLocation.org ? ` (${d.serverLocation.org})` : ""}</CardContent>
        </Card>
      )}
      {(d.openPorts || []).length > 0 && (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium flex items-center gap-2"><Wifi className="w-4 h-4" />Open Ports</CardTitle></CardHeader>
          <CardContent><div className="flex flex-wrap gap-1">{(d.openPorts || []).map((p: number) => <Badge key={p} variant="outline" className="font-mono no-default-hover-elevate no-default-active-elevate">{p}</Badge>)}</div></CardContent>
        </Card>
      )}
      {(d.cookies || []).length > 0 && (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium flex items-center gap-2"><Cookie className="w-4 h-4" />Cookies</CardTitle></CardHeader>
          <CardContent>
            <Table>
              <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Secure</TableHead><TableHead>HttpOnly</TableHead><TableHead>SameSite</TableHead></TableRow></TableHeader>
              <TableBody>{(d.cookies || []).map((c: any, i: number) => <TableRow key={i}><TableCell className="font-mono text-sm">{c.name}</TableCell><TableCell>{c.secure ? <CheckCircle2 className="w-4 h-4 text-green-500" /> : "-"}</TableCell><TableCell>{c.httpOnly ? <CheckCircle2 className="w-4 h-4 text-green-500" /> : "-"}</TableCell><TableCell className="text-xs">{c.sameSite || "-"}</TableCell></TableRow>)}</TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
      {d.responseHeaders && Object.keys(d.responseHeaders).length > 0 && (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Response Headers</CardTitle></CardHeader>
          <CardContent><pre className="text-xs font-mono overflow-auto max-h-60 whitespace-pre-wrap break-all">{Object.entries(d.responseHeaders).map(([k, v]) => `${k}: ${v}`).join("\n")}</pre></CardContent>
        </Card>
      )}
      {d.securityTxt && (d.securityTxt.parsed && Object.keys(d.securityTxt.parsed).length > 0) && (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium flex items-center gap-2"><Shield className="w-4 h-4" />Security.txt</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {Object.entries(d.securityTxt.parsed).map(([k, v]) => <div key={k} className="text-sm"><span className="text-muted-foreground">{k}:</span> {String(v).startsWith("http") ? <a href={String(v)} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">{String(v)}</a> : String(v)}</div>)}
            {d.securityTxt.raw && <pre className="text-xs font-mono mt-2 p-2 rounded bg-muted overflow-auto max-h-32">{d.securityTxt.raw}</pre>}
          </CardContent>
        </Card>
      )}
      {(d.sitemapUrls || []).length > 0 && (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium flex items-center gap-2"><List className="w-4 h-4" />Sitemap ({d.sitemapUrls.length} URLs)</CardTitle></CardHeader>
          <CardContent><ul className="text-xs font-mono space-y-1 max-h-48 overflow-auto">{(d.sitemapUrls || []).slice(0, 50).map((u: string, i: number) => <li key={i} className="truncate" title={u}>{u}</li>)}{(d.sitemapUrls || []).length > 50 && <li className="text-muted-foreground">... and {(d.sitemapUrls || []).length - 50} more</li>}</ul></CardContent>
        </Card>
      )}
      {d.robotsTxt && (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium flex items-center gap-2"><FileText className="w-4 h-4" />Robots.txt</CardTitle></CardHeader>
          <CardContent><pre className="text-xs font-mono overflow-auto max-h-48 whitespace-pre-wrap">{d.robotsTxt}</pre></CardContent>
        </Card>
      )}
      {(d.techStack || []).length > 0 && (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Tech Stack</CardTitle></CardHeader>
          <CardContent><div className="flex flex-wrap gap-2">{(d.techStack || []).map((t: any, i: number) => <Badge key={i} variant="outline" className="no-default-hover-elevate no-default-active-elevate">{t.name} <span className="text-muted-foreground text-xs">({t.source})</span></Badge>)}</div></CardContent>
        </Card>
      )}
      {d.socialTags && Object.keys(d.socialTags).length > 0 && (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Social / Meta Tags</CardTitle></CardHeader>
          <CardContent><div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-sm">{(Object.entries(d.socialTags || {})).map(([k, v]) => <div key={k}><span className="text-muted-foreground">{k}:</span> {String(v).length > 80 ? String(v).slice(0, 80) + "..." : String(v)}</div>)}</div></CardContent>
        </Card>
      )}
      {d.dnssec && <div className="text-xs text-muted-foreground">DNSSEC: SOA present = {d.dnssec.soaPresent ? "Yes" : "No"}</div>}
    </div>
  );
}
