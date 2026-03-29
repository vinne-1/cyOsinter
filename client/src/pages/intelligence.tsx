import React, { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Building2,
  Globe,
  Cpu,
  Cloud,
  FileWarning,
  ShieldAlert,
  Megaphone,
  Linkedin,
  Users,
  Briefcase,
  Code2,
  Link2,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ExternalLink,
  MapPin,
  TrendingUp,
  Server,
  Lock,
  Mail,
  Search,
  Network,
  ArrowRightLeft,
  Info,
  LayoutDashboard,
  Cookie,
  FileText,
  List,
  Shield,
  Wifi,
  Zap,
  Download,
  ChevronDown,
  ChevronRight,
} from "lucide-react";
import type { ReconModule, Scan } from "@shared/schema";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

function ConfidenceBadge({ confidence }: { confidence: number }) {
  const color = confidence >= 90 ? "bg-green-600/15 text-green-400" :
    confidence >= 70 ? "bg-yellow-600/15 text-yellow-400" :
    "bg-orange-600/15 text-orange-400";
  return (
    <Badge variant="outline" className={`${color} border-0 no-default-hover-elevate no-default-active-elevate text-xs`} data-testid="badge-confidence">
      {confidence}% confidence
    </Badge>
  );
}

function GradeBadge({ grade }: { grade: string }) {
  const color = grade.startsWith("A") ? "bg-green-600/15 text-green-400" :
    grade.startsWith("B") ? "bg-blue-600/15 text-blue-400" :
    grade.startsWith("C") ? "bg-yellow-600/15 text-yellow-400" :
    "bg-red-600/15 text-red-400";
  return (
    <Badge variant="outline" className={`${color} border-0 no-default-hover-elevate no-default-active-elevate font-mono`} data-testid="badge-grade">
      {grade}
    </Badge>
  );
}

function SeverityDot({ severity }: { severity: string }) {
  const color = severity === "critical" ? "bg-red-500" :
    severity === "high" ? "bg-orange-500" :
    severity === "medium" ? "bg-yellow-500" :
    severity === "low" ? "bg-blue-500" : "bg-slate-500";
  return <div className={`w-2 h-2 rounded-full flex-shrink-0 ${color}`} />;
}

function StatusIcon({ pass }: { pass: boolean }) {
  return pass ?
    <CheckCircle2 className="w-4 h-4 text-green-400 flex-shrink-0" /> :
    <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />;
}

function ModuleHeader({ title, icon: Icon, confidence, generatedAt }: { title: string; icon: React.ElementType; confidence: number; generatedAt?: string | Date | null }) {
  const freshness = generatedAt ? (() => {
    const ago = Date.now() - new Date(generatedAt).getTime();
    if (ago < 3_600_000) return { text: `${Math.max(1, Math.round(ago / 60_000))}m ago`, fresh: true };
    if (ago < 86_400_000) return { text: `${Math.round(ago / 3_600_000)}h ago`, fresh: true };
    if (ago < 604_800_000) return { text: `${Math.round(ago / 86_400_000)}d ago`, fresh: false };
    return { text: `${Math.round(ago / 604_800_000)}w ago`, fresh: false };
  })() : null;
  return (
    <div className="flex items-center justify-between gap-3 mb-4 flex-wrap">
      <div className="flex items-center gap-3">
        <div className="flex items-center justify-center w-9 h-9 rounded-md bg-primary/10 flex-shrink-0">
          <Icon className="w-5 h-5 text-primary" />
        </div>
        <div>
          <h3 className="text-base font-semibold">{title}</h3>
          {freshness && <p className={`text-[10px] ${freshness.fresh ? "text-muted-foreground/50" : "text-yellow-500/70"}`}>{freshness.text}</p>}
        </div>
      </div>
      <ConfidenceBadge confidence={confidence} />
    </div>
  );
}

function EvidenceLink({ url, label }: { url?: string; label?: string }) {
  if (!url) return null;
  return (
    <a href={url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-primary hover:underline">
      <ExternalLink className="w-3 h-3" />
      {label || "Evidence"}
    </a>
  );
}

// Module 1: Org Identity
function OrgIdentityPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as any;
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

// Module 2: Web Presence Map
function WebPresencePanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as any;
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

// Module 3: Tech Stack
function TechStackPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as any;
  const allTech = [
    ...(d.frontend || []).map((t: any) => ({ ...t, category: "Frontend" })),
    ...(d.backend || []).map((t: any) => ({ ...t, category: "Backend" })),
  ];
  return (
    <div className="space-y-4" data-testid="panel-tech-stack">
      <ModuleHeader title="Technology Radar" icon={Cpu} confidence={mod.confidence || 0} generatedAt={mod.generatedAt} />
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        <Card><CardContent className="p-3 text-center"><p className="text-lg font-semibold">{d.totalTechnologies || 0}</p><p className="text-xs text-muted-foreground">Technologies Detected</p></CardContent></Card>
        <Card><CardContent className="p-3 text-center"><p className="text-lg font-semibold">{(d.thirdParty || []).length}</p><p className="text-xs text-muted-foreground">Third-Party Services</p></CardContent></Card>
        <Card><CardContent className="p-3 text-center"><p className="text-lg font-semibold text-orange-400">{(d.riskFlags || []).length}</p><p className="text-xs text-muted-foreground">Risk Flags</p></CardContent></Card>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Stack Components</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {allTech.map((t: any, i: number) => (
              <div key={i} className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/40">
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className="text-xs no-default-hover-elevate no-default-active-elevate">{t.category}</Badge>
                  <span className="text-sm font-medium">{t.name}</span>
                  {t.version && <span className="text-xs text-muted-foreground font-mono">{t.version}</span>}
                </div>
                <span className="text-xs text-muted-foreground">{t.confidence}%</span>
              </div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Third-Party Services</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(d.thirdParty || []).map((t: any, i: number) => (
              <div key={i} className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/40">
                <div>
                  <p className="text-sm font-medium">{t.name}</p>
                  <p className="text-xs text-muted-foreground">{t.category}</p>
                </div>
                <span className="text-xs text-muted-foreground">{t.confidence}%</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
      {(d.riskFlags || []).length > 0 && (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Risk Flags</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(d.riskFlags || []).map((f: any, i: number) => (
              <div key={i} className="flex items-center gap-3 p-2 rounded-md bg-muted/40">
                <SeverityDot severity={f.severity} />
                <div className="flex-1">
                  <span className="text-sm font-medium">{f.tech} {f.version}</span>
                  <p className="text-xs text-muted-foreground">{f.risk}</p>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// Normalize cloud_footprint emailSecurity (backend may send { found, record, issues }) and derive grades when missing
function normalizeCloudFootprintData(d: Record<string, unknown>) {
  const raw = d.emailSecurity as Record<string, unknown> | undefined;
  if (!raw) return { email: d.emailSecurity, grades: (d.grades || {}) as Record<string, string> };
  const email: Record<string, { status: string; record: string; issue?: string }> = {};
  const grades: Record<string, string> = { ...(d.grades as Record<string, string>) };
  const gradeNum = (g: string) => ({ A: 4, B: 3, C: 2, D: 1, F: 0 }[g] ?? 0);
  for (const key of ["spf", "dmarc"]) {
    const v = raw[key] as { found?: boolean; record?: string; issues?: string[]; status?: string; issue?: string } | undefined;
    if (!v) continue;
    if ("found" in v && typeof v.found === "boolean") {
      const issues = v.issues ?? [];
      const status = v.found && issues.length === 0 ? "pass" : v.found ? "fail" : "none";
      const issue = issues.length ? issues.join("; ") : undefined;
      email[key] = { status, record: v.record ?? "", issue };
      if (!grades[key]) {
        grades[key] = !v.found ? "F" : issues.length === 0 ? "A" : (v.record?.includes?.("+all") || key === "dmarc" && v.record?.includes?.("p=none")) ? (key === "spf" ? "D" : "C") : "B";
      }
    } else if (v.status !== undefined) {
      email[key] = { status: v.status, record: v.record ?? "", issue: v.issue };
    }
  }
  // Fallback when backend sent new shape (status/record/issue) but no grades
  if (!grades.spf && email.spf?.record) {
    grades.spf = email.spf.status === "pass" ? "A" : email.spf.status === "fail" ? "B" : "F";
  }
  if (!grades.dmarc && email.dmarc?.record) {
    grades.dmarc = email.dmarc.status === "pass" ? "A" : email.dmarc.status === "fail" ? "B" : "F";
  }
  if (!grades.overall && (grades.spf || grades.dmarc)) {
    const n = (gradeNum(grades.spf) + gradeNum(grades.dmarc)) / 2;
    grades.overall = n >= 3.5 ? "A" : n >= 2.5 ? "B" : n >= 1.5 ? "C" : n >= 0.5 ? "D" : "F";
  }
  return { email: { ...raw, ...email }, grades };
}

// Module 4: Cloud & Edge Footprint
function CloudFootprintPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as any;
  const { email: emailRaw, grades } = normalizeCloudFootprintData(d);
  const email = ((emailRaw ?? {}) as Record<string, { status: string; record: string; issue?: string }>);
  return (
    <div className="space-y-4" data-testid="panel-cloud-footprint">
      <ModuleHeader title="Cloud & Email Security" icon={Cloud} confidence={mod.confidence || 0} generatedAt={mod.generatedAt} />
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card><CardContent className="p-3 text-center"><GradeBadge grade={grades.spf || "N/A"} /><p className="text-xs text-muted-foreground mt-1">SPF</p></CardContent></Card>
        <Card><CardContent className="p-3 text-center"><GradeBadge grade={grades.dmarc || "N/A"} /><p className="text-xs text-muted-foreground mt-1">DMARC</p></CardContent></Card>
        <Card><CardContent className="p-3 text-center"><GradeBadge grade={grades.dkim || "N/A"} /><p className="text-xs text-muted-foreground mt-1">DKIM</p></CardContent></Card>
        <Card><CardContent className="p-3 text-center"><GradeBadge grade={grades.overall || "N/A"} /><p className="text-xs text-muted-foreground mt-1">Overall</p></CardContent></Card>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Cloud Providers</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(d.cloudProviders || []).map((cp: any, i: number) => (
              <div key={i} className="p-2 rounded-md bg-muted/40 space-y-1">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-medium">{cp.provider}</span>
                  <span className="text-xs text-muted-foreground">{cp.confidence}%</span>
                </div>
                <div className="flex gap-1 flex-wrap">
                  {(cp.evidence || []).map((e: string, j: number) => (
                    <Badge key={j} variant="outline" className="text-xs no-default-hover-elevate no-default-active-elevate">{e}</Badge>
                  ))}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Storage Endpoints</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(d.storageEndpoints || []).map((s: any, i: number) => (
              <div key={i} className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/40">
                <div>
                  <p className="text-sm font-medium font-mono">{s.name}</p>
                  <p className="text-xs text-muted-foreground">{s.type} ({s.provider})</p>
                </div>
                <div className="flex items-center gap-2">
                  {s.accessible ? <Badge variant="outline" className="text-xs bg-red-600/15 text-red-400 border-0 no-default-hover-elevate no-default-active-elevate">Public</Badge> : <Badge variant="outline" className="text-xs bg-green-600/15 text-green-400 border-0 no-default-hover-elevate no-default-active-elevate">Private</Badge>}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Email Security</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          {email.spf && (
            <div className="p-2 rounded-md bg-muted/40 space-y-1">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2"><StatusIcon pass={email.spf.status === "pass"} /><span className="text-sm font-medium">SPF</span></div>
                <GradeBadge grade={grades.spf || "N/A"} />
              </div>
              <p className="text-xs font-mono text-muted-foreground break-all">{email.spf.record}</p>
              {email.spf.issue && <p className="text-xs text-yellow-400">{email.spf.issue}</p>}
            </div>
          )}
          {email.dmarc && (
            <div className="p-2 rounded-md bg-muted/40 space-y-1">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2"><StatusIcon pass={email.dmarc.status === "pass"} /><span className="text-sm font-medium">DMARC</span></div>
                <GradeBadge grade={grades.dmarc || "N/A"} />
              </div>
              <p className="text-xs font-mono text-muted-foreground break-all">{email.dmarc.record}</p>
              {email.dmarc.issue && <p className="text-xs text-yellow-400">{email.dmarc.issue}</p>}
            </div>
          )}
          {email.dkim && (
            <div className="p-2 rounded-md bg-muted/40 space-y-1">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2"><StatusIcon pass={email.dkim.status === "pass"} /><span className="text-sm font-medium">DKIM</span></div>
                <GradeBadge grade={grades.dkim || "N/A"} />
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

const RESPONSE_TYPE_ORDER = ["success", "forbidden", "unauthorized", "redirect", "redirect_to_login", "server_error", "not_found", "soft_404", "other"] as const;
const RESPONSE_TYPE_LABELS: Record<string, string> = {
  success: "Accessible (200)",
  forbidden: "Forbidden (403)",
  unauthorized: "Unauthorized (401)",
  redirect: "Redirect (3xx)",
  redirect_to_login: "Redirect to Login (protected)",
  server_error: "Server Error (5xx)",
  not_found: "Page Not Found (404)",
  soft_404: "Soft 404 (200 with not-found content)",
  other: "Other",
};

function deriveResponseType(v: { status?: number; accessible?: boolean }): string {
  const s = v.status;
  if (s === 200) return v.accessible ? "success" : "not_found";
  if (s === 404) return "not_found";
  if (s === 403) return "forbidden";
  if (s === 401) return "unauthorized";
  if (s && [301, 302, 307, 308].includes(s)) return "redirect";
  if (s && s >= 500) return "server_error";
  return "other";
}

// Module 5: Exposed Content
function ExposedContentPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as any;
  const publicFiles = d.publicFiles || [];
  const pathChecks = d.pathChecks ? Object.entries(d.pathChecks) as [string, { status: number; accessible?: boolean; responseType?: string; severity?: string; validated?: boolean; confidence?: string; redirectTarget?: string }][] : [];
  const rows: Array<{ path: string; type: string; severity: string; responseType: string; validated?: boolean; confidence?: string; redirectTarget?: string; firstSeen: string; evidenceUrl?: string }> = publicFiles.length
    ? publicFiles.map((f: any) => ({ ...f, responseType: f.responseType ?? "other" }))
    : pathChecks.map(([path, v]) => ({
        path,
        type: path.replace(/^\//, "").replace(/\//g, " ") || "path",
        severity: v.severity ?? (v.accessible ? "low" : "info"),
        responseType: v.responseType ?? deriveResponseType(v),
        validated: v.validated,
        confidence: v.confidence,
        redirectTarget: v.redirectTarget,
        firstSeen: "-",
        evidenceUrl: path.startsWith("http") ? path : undefined,
      }));

  const grouped = rows.reduce((acc, r) => {
    const rt = r.responseType;
    if (!acc[rt]) acc[rt] = [];
    acc[rt].push(r);
    return acc;
  }, {} as Record<string, typeof rows>);

  const dirBrute = d.directoryBruteforce;
  const hitCounts: Record<string, number> = dirBrute?.hits?.reduce((acc: Record<string, number>, h: { responseType?: string }) => {
    const rt = h.responseType ?? "other";
    acc[rt] = (acc[rt] ?? 0) + 1;
    return acc;
  }, {} as Record<string, number>) ?? {};

  const positiveResponseTypes = ["success", "redirect", "redirect_to_login", "forbidden", "unauthorized"];
  const dirBruteGrouped = (dirBrute?.hits || []).reduce((acc: Record<string, Array<{ path: string; status: number; responseType?: string; severity?: string; evidenceUrl?: string }>>, h: { path: string; status: number; responseType?: string; severity?: string; evidenceUrl?: string }) => {
    const rt = h.responseType ?? (h.status >= 200 && h.status < 300 ? "success" : h.status >= 300 && h.status < 400 ? "redirect" : h.status === 403 ? "forbidden" : h.status === 401 ? "unauthorized" : h.status === 404 ? "not_found" : "other");
    if (!acc[rt]) acc[rt] = [];
    acc[rt].push(h);
    return acc;
  }, {} as Record<string, Array<{ path: string; status: number; responseType?: string; severity?: string; evidenceUrl?: string }>>);

  return (
    <div className="space-y-4" data-testid="panel-exposed-content">
      <ModuleHeader title="Exposed Content & Leaks" icon={FileWarning} confidence={mod.confidence || 0} generatedAt={mod.generatedAt} />
      {dirBrute && (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Directory Bruteforce</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <p className="text-xs text-muted-foreground">Wordlist: {dirBrute.wordlistSource}</p>
            <div className="flex flex-wrap gap-3">
              <span className="text-sm"><strong>{dirBrute.tried}</strong> tried</span>
              <span className="text-sm"><strong>{dirBrute.hits?.length ?? 0}</strong> total</span>
              {Object.entries(hitCounts).map(([rt, n]) => (
                <span key={rt} className="text-sm text-muted-foreground">{RESPONSE_TYPE_LABELS[rt] ?? rt}: <strong>{n}</strong></span>
              ))}
            </div>
            {(dirBrute.hits?.length ?? 0) > 0 && (
              <div className="space-y-4">
                {[...RESPONSE_TYPE_ORDER, ...Object.keys(dirBruteGrouped).filter((k) => !(RESPONSE_TYPE_ORDER as readonly string[]).includes(k))].map((rt) => {
                  const items = dirBruteGrouped[rt];
                  if (!items?.length) return null;
                  const isPositive = positiveResponseTypes.includes(rt);
                  return (
                    <div key={rt}>
                      <h4 className={`text-sm font-medium mb-2 ${isPositive ? "text-green-400" : ""}`}>
                        {RESPONSE_TYPE_LABELS[rt] ?? rt} ({items.length})
                        {isPositive && <span className="text-xs text-muted-foreground ml-1">(positive hit)</span>}
                      </h4>
                      <div className="overflow-x-auto max-h-48">
                        <Table>
                          <TableHeader><TableRow><TableHead>Path</TableHead><TableHead>Status</TableHead><TableHead>Response</TableHead><TableHead>Severity</TableHead><TableHead>Evidence</TableHead></TableRow></TableHeader>
                          <TableBody>
                            {items.slice(0, 50).map((h: { path: string; status: number; responseType?: string; severity?: string; evidenceUrl?: string }, i: number) => (
                              <TableRow key={`${rt}-${i}`}>
                                <TableCell className="font-mono text-xs">{h.path}</TableCell>
                                <TableCell>{h.status}</TableCell>
                                <TableCell className="text-xs">{RESPONSE_TYPE_LABELS[h.responseType ?? "other"] ?? h.responseType}</TableCell>
                                <TableCell><div className="flex items-center gap-1.5"><SeverityDot severity={h.severity ?? "info"} /><span className="text-xs capitalize">{h.severity ?? "info"}</span></div></TableCell>
                                <TableCell><EvidenceLink url={h.evidenceUrl} label="Open" /></TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                        {items.length > 50 && <p className="text-xs text-muted-foreground mt-1">+ {items.length - 50} more</p>}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>
      )}
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Public Files & Endpoints ({rows.length})</CardTitle></CardHeader>
        <CardContent className="space-y-6">
          {[...RESPONSE_TYPE_ORDER, ...Object.keys(grouped).filter((k) => !(RESPONSE_TYPE_ORDER as readonly string[]).includes(k))].map((rt) => {
            const items = grouped[rt];
            if (!items?.length) return null;
            return (
              <div key={rt}>
                <h4 className="text-sm font-medium mb-2">{RESPONSE_TYPE_LABELS[rt] ?? rt} ({items.length})</h4>
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader><TableRow><TableHead>Path</TableHead><TableHead>Type</TableHead><TableHead>Severity</TableHead><TableHead>Confidence</TableHead><TableHead>Evidence</TableHead></TableRow></TableHeader>
                    <TableBody>
                      {items.map((f: any, i: number) => (
                        <TableRow key={`${rt}-${i}`}>
                          <TableCell className="font-mono text-sm">{f.path}</TableCell>
                          <TableCell className="text-sm">{f.type}</TableCell>
                          <TableCell><div className="flex items-center gap-1.5"><SeverityDot severity={f.severity} /><span className="text-sm capitalize">{f.severity}</span></div></TableCell>
                          <TableCell>{f.confidence ? <Badge variant="outline" className="text-xs border-0 no-default-hover-elevate no-default-active-elevate">{f.confidence}</Badge> : null}</TableCell>
                          <TableCell><EvidenceLink url={f.evidenceUrl} /></TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </div>
            );
          })}
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Secrets Exposure Indicators</CardTitle></CardHeader>
        <CardContent className="space-y-2">
          {(d.secretsExposure || []).map((s: any, i: number) => (
            <div key={i} className="flex items-start justify-between gap-3 p-2 rounded-md bg-muted/40">
              <div className="flex items-start gap-2">
                <SeverityDot severity={s.severity} />
                <div>
                  <p className="text-sm font-medium">{s.pattern}</p>
                  <p className="text-xs text-muted-foreground">{s.location}</p>
                  {s.redacted && <Badge variant="outline" className="text-xs mt-1 no-default-hover-elevate no-default-active-elevate">Redacted</Badge>}
                </div>
              </div>
              <EvidenceLink url={s.evidenceUrl} />
            </div>
          ))}
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Archived / Changed URLs</CardTitle></CardHeader>
        <CardContent className="space-y-2">
          {(d.archivedUrls || []).map((u: any, i: number) => (
            <div key={i} className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/40">
              <div className="flex items-center gap-2">
                <Badge variant="outline" className={`text-xs border-0 no-default-hover-elevate no-default-active-elevate ${u.status === "Removed" ? "bg-red-600/15 text-red-400" : "bg-yellow-600/15 text-yellow-400"}`}>{u.status}</Badge>
                <span className="text-sm font-mono">{u.url}</span>
              </div>
              <span className="text-xs text-muted-foreground">{u.source} | {u.lastSeen}</span>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

// DNS Overview (OSINT)
function DNSOverviewPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as any;
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
function RedirectChainPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as any;
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
function DomainInfoPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as any;
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
                <span className="font-mono text-right break-all">{String(info[k]).slice(0, 200)}{String(info[k]).length > 200 ? "…" : ""}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// Website Overview (OSINT: cookies, headers, security.txt, sitemap, robots, tech, social, location, ports)
function WebsiteOverviewPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as any;
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
          <CardContent><ul className="text-xs font-mono space-y-1 max-h-48 overflow-auto">{(d.sitemapUrls || []).slice(0, 50).map((u: string, i: number) => <li key={i} className="truncate" title={u}>{u}</li>)}{(d.sitemapUrls || []).length > 50 && <li className="text-muted-foreground">… and {(d.sitemapUrls || []).length - 50} more</li>}</ul></CardContent>
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
          <CardContent><div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-sm">{(Object.entries(d.socialTags || {})).map(([k, v]) => <div key={k}><span className="text-muted-foreground">{k}:</span> {String(v).length > 80 ? String(v).slice(0, 80) + "…" : String(v)}</div>)}</div></CardContent>
        </Card>
      )}
      {d.dnssec && <div className="text-xs text-muted-foreground">DNSSEC: SOA present = {d.dnssec.soaPresent ? "Yes" : "No"}</div>}
    </div>
  );
}

// Derive TLS grade from ssl when backend did not send tlsPosture (e.g. old payload)
function deriveTlsGrade(d: Record<string, unknown>): string {
  const grade = (d.tlsPosture as { grade?: string } | undefined)?.grade;
  if (grade) return grade;
  const ssl = d.ssl as { daysRemaining?: number; protocol?: string } | undefined;
  if (!ssl || ssl.daysRemaining == null) return "N/A";
  if (ssl.daysRemaining <= 0) return "F";
  const proto = (ssl.protocol || "").toLowerCase();
  if ((proto === "tlsv1.2" || proto === "tlsv1.3") && ssl.daysRemaining > 30) return "A";
  if (proto === "tlsv1.2" || proto === "tlsv1.3") return "B";
  return "C";
}

// Module 6: Attack Surface Summary
function AttackSurfacePanel({ mod }: { mod: ReconModule }) {
  const { selectedWorkspaceId } = useDomain();
  const [sortBy, setSortBy] = useState<"host" | "riskScore" | "tlsGrade" | "waf">("riskScore");
  const [sortDesc, setSortDesc] = useState(true);
  const [expandedHost, setExpandedHost] = useState<string | null>(null);
  const d = mod.data as any;
  const headers = d.securityHeaders || {};
  const tlsGrade = deriveTlsGrade(d);
  const publicIPs = (d.publicIPs || []) as Array<{ ip: string; banner?: string; services?: string[] }>;
  const ips = publicIPs.map((p) => p.ip).filter(Boolean);
  const assetInventory = (d.assetInventory || []) as Array<{ host: string; ip: string; category: string; riskScore: number; tlsGrade: string; waf: string; cdn: string }>;

  const rawPerAssetHeaders = d.perAssetHeaders || {};
  const rawPerAssetTls = d.perAssetTls || {};
  const rawPerAssetLeaks = d.perAssetLeaks || {};

  const perAssetHeaders = useMemo(() => {
    if (Array.isArray(rawPerAssetHeaders)) return rawPerAssetHeaders as Array<{ host: string; headers: Record<string, { present: boolean; value?: string }>; missingCount: number }>;
    return Object.entries(rawPerAssetHeaders).map(([host, headers]) => ({
      host,
      headers: headers as Record<string, { present: boolean; value?: string | null }>,
      missingCount: Object.values(headers as Record<string, { present: boolean }>).filter((h) => !h.present).length,
    }));
  }, [rawPerAssetHeaders]);

  const perAssetTls = useMemo(() => {
    if (Array.isArray(rawPerAssetTls)) return rawPerAssetTls as Array<{ host: string; grade: string; daysRemaining: number; issuer: string }>;
    return Object.entries(rawPerAssetTls).map(([host, tls]) => {
      const t = tls as { daysRemaining?: number; protocol?: string; issuer?: string; subject?: string } | null;
      if (!t) return { host, grade: "N/A", daysRemaining: -1, issuer: "Unknown" };
      const proto = (t.protocol || "").toLowerCase();
      let grade = "F";
      if (t.daysRemaining != null && t.daysRemaining > 0) {
        if ((proto === "tlsv1.2" || proto === "tlsv1.3") && t.daysRemaining > 30) grade = "A";
        else if (proto === "tlsv1.2" || proto === "tlsv1.3") grade = "B";
        else grade = "C";
      }
      return { host, grade, daysRemaining: t.daysRemaining ?? -1, issuer: t.issuer || "Unknown" };
    });
  }, [rawPerAssetTls]);

  const perAssetLeaks = useMemo(() => {
    if (Array.isArray(rawPerAssetLeaks)) return rawPerAssetLeaks as Array<{ host: string; leaks: string[] }>;
    return Object.entries(rawPerAssetLeaks).map(([host, leaks]) => ({
      host,
      leaks: (leaks || []) as string[],
    }));
  }, [rawPerAssetLeaks]);

  const headersByHost = useMemo(() => new Map(perAssetHeaders.map((h) => [h.host, h])), [perAssetHeaders]);
  const tlsByHost = useMemo(() => new Map(perAssetTls.map((t) => [t.host, t])), [perAssetTls]);
  const leaksByHost = useMemo(() => new Map(perAssetLeaks.map((l) => [l.host, l])), [perAssetLeaks]);
  const sortedAssets = useMemo(() => {
    const arr = [...assetInventory];
    arr.sort((a, b) => {
      let cmp = 0;
      if (sortBy === "host") cmp = a.host.localeCompare(b.host);
      else if (sortBy === "riskScore") cmp = a.riskScore - b.riskScore;
      else if (sortBy === "tlsGrade") cmp = (a.tlsGrade || "Z").localeCompare(b.tlsGrade || "Z");
      else if (sortBy === "waf") cmp = (a.waf ? "1" : "0").localeCompare(b.waf ? "1" : "0");
      return sortDesc ? -cmp : cmp;
    });
    return arr;
  }, [assetInventory, sortBy, sortDesc]);
  const { data: ipEnrichment = {} } = useQuery<Record<string, { abuseipdb?: { abuseConfidenceScore?: number; totalReports?: number; countryCode?: string; isp?: string } | null; virustotal?: { malicious?: number; suspicious?: number } | null }>>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/ip-enrichment`],
    enabled: !!selectedWorkspaceId && ips.length > 0,
  });
  const exportAttackSurface = (format: "json" | "csv") => {
    const data = assetInventory.length > 0 ? assetInventory : [{ host: "-", ip: "-", category: "-", riskScore: d.surfaceRiskScore ?? 0, tlsGrade, waf: d.wafDetection?.provider || "", cdn: "None" }];
    if (format === "json") {
      const blob = new Blob([JSON.stringify({ attackSurface: data, surfaceRiskScore: d.surfaceRiskScore, wafDetection: d.wafDetection }, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "attack-surface.json";
      a.click();
      URL.revokeObjectURL(url);
    } else {
      const csv = ["host,ip,category,riskScore,tlsGrade,waf,cdn", ...data.map((r) => `${r.host},${r.ip},${r.category},${r.riskScore},${r.tlsGrade},${r.waf},${r.cdn}`)].join("\n");
      const blob = new Blob([csv], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "attack-surface.csv";
      a.click();
      URL.revokeObjectURL(url);
    }
  };
  const highRiskCount = assetInventory.filter((a) => a.riskScore >= 60).length;
  const wafCoverage = assetInventory.length > 0 ? Math.round((assetInventory.filter((a) => a.waf).length / assetInventory.length) * 100) : 0;
  return (
    <div className="space-y-4" data-testid="panel-attack-surface">
      <ModuleHeader title="External Attack Surface" icon={ShieldAlert} confidence={mod.confidence || 0} generatedAt={mod.generatedAt} />
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
        <Card>
          <CardContent className="p-3 text-center">
            <p className={`text-2xl font-semibold ${(d.surfaceRiskScore || 0) >= 80 ? 'text-green-400' : (d.surfaceRiskScore || 0) >= 60 ? 'text-yellow-500' : 'text-red-500'}`}>
              {d.surfaceRiskScore || 0}
            </p>
            <p className="text-xs text-muted-foreground">Surface Risk Score</p>
          </CardContent>
        </Card>
        <Card><CardContent className="p-3 text-center"><p className="text-lg font-semibold">{assetInventory.length || (d.publicIPs || []).length}</p><p className="text-xs text-muted-foreground">Hosts</p></CardContent></Card>
        <Card><CardContent className="p-3 text-center"><p className="text-lg font-semibold text-orange-400">{highRiskCount}</p><p className="text-xs text-muted-foreground">High Risk</p></CardContent></Card>
        <Card><CardContent className="p-3 text-center"><GradeBadge grade={tlsGrade} /><p className="text-xs text-muted-foreground mt-1">TLS Grade</p></CardContent></Card>
        <Card><CardContent className="p-3 text-center"><StatusIcon pass={d.wafDetection?.detected || false} /><p className="text-xs text-muted-foreground mt-1">WAF {d.wafDetection?.provider || ""}</p></CardContent></Card>
        <Card><CardContent className="p-3 text-center"><p className="text-lg font-semibold">{wafCoverage}%</p><p className="text-xs text-muted-foreground">WAF Coverage</p></CardContent></Card>
      </div>
      {(d.riskBreakdown || []).length > 0 && (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Risk Breakdown</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            {d.riskBreakdown.map((r: any, i: number) => (
              <div key={i} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">{r.category}</span>
                  <span className="font-mono font-medium">{r.score}/{r.maxScore}</span>
                </div>
                <div className="h-2 rounded-md bg-muted overflow-hidden">
                  <div className={`bar-fill h-full rounded-md transition-all ${r.score >= 80 ? 'bg-green-500' : r.score >= 60 ? 'bg-yellow-500' : 'bg-red-500'}`} data-value={String(Math.min(100, Math.round(((r.score / r.maxScore) * 100) / 5) * 5))} />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
      {sortedAssets.length > 0 && (
        <Card>
          <CardHeader className="pb-2 flex flex-row items-center justify-between">
            <CardTitle className="text-sm font-medium">Per-Asset Attack Surface</CardTitle>
            <div className="flex gap-2">
              <button onClick={() => exportAttackSurface("csv")} className="text-xs px-2 py-1 rounded border border-border hover:bg-muted/50 flex items-center gap-1">
                <Download className="w-3 h-3" /> CSV
              </button>
              <button onClick={() => exportAttackSurface("json")} className="text-xs px-2 py-1 rounded border border-border hover:bg-muted/50 flex items-center gap-1">
                <Download className="w-3 h-3" /> JSON
              </button>
            </div>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead></TableHead>
                  <TableHead><button className="font-medium hover:underline" onClick={() => { setSortBy("host"); setSortDesc(sortBy === "host" ? !sortDesc : false); }}>Host</button></TableHead>
                  <TableHead><button className="font-medium hover:underline" onClick={() => { setSortBy("riskScore"); setSortDesc(sortBy === "riskScore" ? !sortDesc : true); }}>Risk</button></TableHead>
                  <TableHead><button className="font-medium hover:underline" onClick={() => { setSortBy("tlsGrade"); setSortDesc(sortBy === "tlsGrade" ? !sortDesc : true); }}>TLS</button></TableHead>
                  <TableHead>Headers</TableHead>
                  <TableHead>WAF</TableHead>
                  <TableHead>CDN</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sortedAssets.map((a) => (
                  <React.Fragment key={a.host}>
                    <TableRow className="cursor-pointer hover:bg-muted/30" onClick={() => setExpandedHost(expandedHost === a.host ? null : a.host)}>
                      <TableCell className="w-8">{expandedHost === a.host ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}</TableCell>
                      <TableCell className="font-mono text-sm">{a.host}</TableCell>
                      <TableCell><Badge variant="outline" className={`text-xs border-0 no-default-hover-elevate no-default-active-elevate ${a.riskScore >= 60 ? "bg-red-600/15 text-red-400" : a.riskScore >= 40 ? "bg-yellow-600/15 text-yellow-400" : "bg-green-600/15 text-green-400"}`}>{a.riskScore}</Badge></TableCell>
                      <TableCell><GradeBadge grade={a.tlsGrade || "N/A"} /></TableCell>
                      <TableCell>{headersByHost.get(a.host)?.missingCount ?? 0} missing</TableCell>
                      <TableCell>{a.waf ? <Badge variant="outline" className="text-xs bg-green-600/15 text-green-400 border-0 no-default-hover-elevate no-default-active-elevate">{a.waf}</Badge> : <span className="text-xs text-muted-foreground">—</span>}</TableCell>
                      <TableCell>{a.cdn && a.cdn !== "None" ? <Badge variant="outline" className="text-xs no-default-hover-elevate no-default-active-elevate">{a.cdn}</Badge> : <span className="text-xs text-muted-foreground">—</span>}</TableCell>
                    </TableRow>
                    {expandedHost === a.host && (
                      <TableRow key={`${a.host}-exp`}>
                        <TableCell colSpan={7} className="bg-muted/20 p-4">
                          <div className="space-y-3 text-sm">
                            {tlsByHost.get(a.host) && (
                              <div>
                                <p className="font-medium text-muted-foreground mb-1">TLS Certificate</p>
                                <p className="font-mono text-xs">Issuer: {(tlsByHost.get(a.host) as any).issuer} · Days remaining: {(tlsByHost.get(a.host) as any).daysRemaining}</p>
                              </div>
                            )}
                            {headersByHost.get(a.host) && (
                              <div>
                                <p className="font-medium text-muted-foreground mb-1">Security Headers</p>
                                <div className="flex flex-wrap gap-2">
                                  {Object.entries(headersByHost.get(a.host)!.headers || {}).map(([k, v]) => (
                                    <Badge key={k} variant="outline" className={`text-xs no-default-hover-elevate no-default-active-elevate ${v.present ? "bg-green-600/15 text-green-400 border-0" : "bg-red-600/15 text-red-400 border-0"}`}>{k}: {v.present ? "✓" : "✗"}</Badge>
                                  ))}
                                </div>
                              </div>
                            )}
                            {leaksByHost.get(a.host)?.leaks?.length ? (
                              <div>
                                <p className="font-medium text-muted-foreground mb-1">Server Info Leaks</p>
                                <p className="font-mono text-xs">{leaksByHost.get(a.host)!.leaks.join("; ")}</p>
                              </div>
                            ) : null}
                          </div>
                        </TableCell>
                      </TableRow>
                    )}
                  </React.Fragment>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Public IPs & Services</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(d.publicIPs || []).map((ip: any, i: number) => {
              const enrichment = ipEnrichment[ip.ip];
              const abuse = enrichment?.abuseipdb;
              const vt = enrichment?.virustotal;
              const score = abuse?.abuseConfidenceScore ?? -1;
              const scoreColor = score < 0 ? "" : score < 25 ? "bg-green-600/15 text-green-400" : score <= 75 ? "bg-yellow-600/15 text-yellow-400" : "bg-red-600/15 text-red-400";
              return (
                <div key={i} className="p-2 rounded-md bg-muted/40 space-y-1">
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <span className="text-sm font-mono font-medium">{ip.ip}</span>
                    <div className="flex items-center gap-2 flex-wrap">
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
                      <span className="text-xs text-muted-foreground">{ip.banner}</span>
                    </div>
                  </div>
                  <div className="flex gap-1 flex-wrap">
                    {(ip.services || []).map((s: string, j: number) => (
                      <Badge key={j} variant="outline" className="text-xs font-mono no-default-hover-elevate no-default-active-elevate">{s}</Badge>
                    ))}
                  </div>
                </div>
              );
            })}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Security Headers</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {Object.entries(headers).map(([key, val]: [string, any]) => (
              <div key={key} className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/40">
                <div className="flex items-center gap-2">
                  <StatusIcon pass={val.present} />
                  <span className="text-sm">{key.replace(/([A-Z])/g, ' $1').replace(/^./, (s: string) => s.toUpperCase())}</span>
                </div>
                <GradeBadge grade={val.grade ?? (val.present ? "A" : "N/A")} />
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// IP Reputation tab (AbuseIPDB / VirusTotal) – standalone panel when we have IPs
function IPReputationPanel() {
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

// Module 7: Brand Signals
function BrandSignalsPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as any;
  return (
    <div className="space-y-4" data-testid="panel-brand-signals">
      <ModuleHeader title="Brand & Public Reputation" icon={Megaphone} confidence={mod.confidence || 0} generatedAt={mod.generatedAt} />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Social Profiles</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(d.socialProfiles || []).map((sp: any, i: number) => (
              <div key={i} className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/40">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium">{sp.platform}</span>
                  {sp.verified && <CheckCircle2 className="w-3 h-3 text-blue-400" />}
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">{sp.followers?.toLocaleString() || sp.repos || sp.subscribers?.toLocaleString()} {sp.repos ? "repos" : sp.subscribers ? "subscribers" : "followers"}</span>
                  <EvidenceLink url={sp.url} />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">App Store Listings</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(d.appStoreListings || []).map((app: any, i: number) => (
              <div key={i} className="p-2 rounded-md bg-muted/40 space-y-1">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-medium">{app.name}</span>
                  <Badge variant="outline" className="text-xs no-default-hover-elevate no-default-active-elevate">{app.platform}</Badge>
                </div>
                <p className="text-xs text-muted-foreground font-mono">{app.bundleId || app.packageName}</p>
                <p className="text-xs text-muted-foreground">Rating: {app.rating}/5 ({app.reviews} reviews)</p>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Public Pages</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(d.publicPages || []).map((p: any, i: number) => (
              <div key={i} className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/40">
                <div className="flex items-center gap-2">
                  <StatusIcon pass={p.operational} />
                  <span className="text-sm">{p.type}</span>
                </div>
                <EvidenceLink url={p.url} label={p.type} />
              </div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">News References</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(d.newsReferences || []).map((n: any, i: number) => (
              <div key={i} className="p-2 rounded-md bg-muted/40 space-y-1">
                <p className="text-sm font-medium">{n.title}</p>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs text-muted-foreground">{n.source} | {n.date}</span>
                  <EvidenceLink url={n.url} />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// Module 8: LinkedIn Company
function LinkedInCompanyPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as any;
  const cp = d.companyPage || {};
  const trend = d.employeeTrend || {};
  return (
    <div className="space-y-4" data-testid="panel-linkedin-company">
      <ModuleHeader title="LinkedIn Org Snapshot" icon={Linkedin} confidence={mod.confidence || 0} generatedAt={mod.generatedAt} />
      <Card>
        <CardContent className="p-4 space-y-3">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h4 className="text-base font-semibold">{cp.name}</h4>
              <p className="text-sm text-muted-foreground">{cp.industry}</p>
            </div>
            <Badge variant="outline" className="text-xs no-default-hover-elevate no-default-active-elevate">{cp.matchConfidence}% match</Badge>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              ["HQ", cp.headquarters],
              ["Size", cp.companySize],
              ["Founded", cp.founded],
              ["Employees", trend.current],
            ].map(([label, value]) => (
              <div key={label as string} className="text-center p-2 rounded-md bg-muted/40">
                <p className="text-sm font-semibold">{String(value)}</p>
                <p className="text-xs text-muted-foreground">{label}</p>
              </div>
            ))}
          </div>
          <div>
            <h5 className="text-xs text-muted-foreground mb-1">Specialties</h5>
            <div className="flex gap-1 flex-wrap">
              {(cp.specialties || []).map((s: string) => (
                <Badge key={s} variant="outline" className="text-xs no-default-hover-elevate no-default-active-elevate">{s}</Badge>
              ))}
            </div>
          </div>
          {trend.growth && (
            <div className="flex items-center gap-2 text-sm text-green-400">
              <TrendingUp className="w-4 h-4" />
              <span>Growth: {trend.growth}</span>
            </div>
          )}
          <EvidenceLink url={d.evidenceUrl} label="LinkedIn Page" />
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Recent Post Themes</CardTitle></CardHeader>
        <CardContent className="space-y-2">
          {(d.recentPosts || []).map((p: any, i: number) => (
            <div key={i} className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/40">
              <span className="text-sm">{p.theme}</span>
              <div className="flex items-center gap-2">
                <Badge variant="outline" className={`text-xs border-0 no-default-hover-elevate no-default-active-elevate ${p.engagement === "high" ? "bg-green-600/15 text-green-400" : "bg-blue-600/15 text-blue-400"}`}>{p.engagement}</Badge>
                <span className="text-xs text-muted-foreground">{p.date}</span>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

// Module 9: LinkedIn People
function LinkedInPeoplePanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as any;
  return (
    <div className="space-y-4" data-testid="panel-linkedin-people">
      <ModuleHeader title="People Intelligence" icon={Users} confidence={mod.confidence || 0} generatedAt={mod.generatedAt} />
      <Card>
        <CardContent className="p-3 text-center"><p className="text-2xl font-semibold">{d.totalEmployees || 0}</p><p className="text-xs text-muted-foreground">Total Employees</p></CardContent>
      </Card>
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Org Chart Heatmap</CardTitle></CardHeader>
        <CardContent className="space-y-2">
          {(d.roleBuckets || []).map((rb: any, i: number) => {
            const maxCount = Math.max(...(d.roleBuckets || []).map((r: any) => r.count));
            return (
              <div key={i} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">{rb.category}</span>
                  <span className="font-mono font-medium">{rb.count}</span>
                </div>
                <div className="h-2 rounded-md bg-muted overflow-hidden">
                  <div className="bar-fill h-full rounded-md bg-primary transition-all" data-value={String(Math.min(100, Math.round(((rb.count / maxCount) * 100) / 5) * 5))} />
                </div>
              </div>
            );
          })}
        </CardContent>
      </Card>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Seniority Distribution</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(d.seniorityDistribution || []).map((s: any, i: number) => (
              <div key={i} className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/40">
                <span className="text-sm">{s.level}</span>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-mono">{s.count}</span>
                  <span className="text-xs text-muted-foreground">({s.percentage}%)</span>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Geographic Distribution</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(d.geoDistribution || []).map((g: any, i: number) => (
              <div key={i} className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/40">
                <div className="flex items-center gap-2">
                  <MapPin className="w-3 h-3 text-muted-foreground" />
                  <span className="text-sm">{g.location}</span>
                </div>
                <span className="text-sm font-mono">{g.count} ({g.percentage}%)</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
      {(d.keyContacts || []).length > 0 && (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Key Contacts</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {d.keyContacts.map((c: any, i: number) => (
              <div key={i} className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/40">
                <div>
                  <p className="text-sm font-medium">{c.role}</p>
                  <p className="text-xs text-muted-foreground">{c.department}</p>
                </div>
                <EvidenceLink url={c.profileUrl} label="Profile" />
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// Module 10: LinkedIn Hiring
function LinkedInHiringPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as any;
  const maturity = d.securityMaturity || {};
  return (
    <div className="space-y-4" data-testid="panel-linkedin-hiring">
      <ModuleHeader title="Hiring & Tech Signals" icon={Briefcase} confidence={mod.confidence || 0} generatedAt={mod.generatedAt} />
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card><CardContent className="p-3 text-center"><p className="text-lg font-semibold">{d.totalOpenRoles || 0}</p><p className="text-xs text-muted-foreground">Open Roles</p></CardContent></Card>
        <Card><CardContent className="p-3 text-center"><p className="text-lg font-semibold">{d.securityRoles || 0}</p><p className="text-xs text-muted-foreground">Security Roles</p></CardContent></Card>
        <Card><CardContent className="p-3 text-center"><Badge variant="outline" className={`text-xs border-0 no-default-hover-elevate no-default-active-elevate ${maturity.maturityLevel === "Established" ? "bg-green-600/15 text-green-400" : "bg-yellow-600/15 text-yellow-400"}`}>{maturity.maturityLevel || "Unknown"}</Badge><p className="text-xs text-muted-foreground mt-1">Security Maturity</p></CardContent></Card>
        <Card><CardContent className="p-3 text-center"><p className="text-lg font-semibold">{Object.values(d.techKeywords || {}).flat().length}</p><p className="text-xs text-muted-foreground">Tech Keywords</p></CardContent></Card>
      </div>
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Active Job Postings</CardTitle></CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Title</TableHead>
                  <TableHead>Location</TableHead>
                  <TableHead>Seniority</TableHead>
                  <TableHead>Tech Keywords</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(d.activePostings || []).map((p: any, i: number) => (
                  <TableRow key={i}>
                    <TableCell className="text-sm font-medium">{p.title}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">{p.location}</TableCell>
                    <TableCell><Badge variant="outline" className="text-xs no-default-hover-elevate no-default-active-elevate">{p.seniority}</Badge></TableCell>
                    <TableCell><div className="flex gap-1 flex-wrap">{(p.keywords || []).map((k: string) => <Badge key={k} variant="outline" className="text-xs font-mono no-default-hover-elevate no-default-active-elevate">{k}</Badge>)}</div></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Tech Keywords by Category</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {Object.entries(d.techKeywords || {}).map(([cat, keywords]: [string, any]) => (
              <div key={cat} className="p-2 rounded-md bg-muted/40 space-y-1">
                <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground capitalize">{cat}</p>
                <div className="flex gap-1 flex-wrap">
                  {keywords.map((k: string) => <Badge key={k} variant="outline" className="text-xs font-mono no-default-hover-elevate no-default-active-elevate">{k}</Badge>)}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Security Maturity Indicators</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {[
              { label: "AppSec Team", present: maturity.hasAppSec },
              { label: "SOC Team", present: maturity.hasSOC },
              { label: "Threat Intelligence", present: maturity.hasThreatIntel },
              { label: "GRC Function", present: maturity.hasGRC },
              { label: "DevSecOps", present: maturity.hasDevSecOps },
            ].map((ind) => (
              <div key={ind.label} className="flex items-center gap-2 p-2 rounded-md bg-muted/40">
                <StatusIcon pass={ind.present} />
                <span className="text-sm">{ind.label}</span>
              </div>
            ))}
            {(maturity.indicators || []).length > 0 && (
              <div className="pt-2 border-t space-y-1">
                {maturity.indicators.map((ind: string, i: number) => (
                  <p key={i} className="text-xs text-muted-foreground flex items-center gap-1.5">
                    <CheckCircle2 className="w-3 h-3 text-green-400 flex-shrink-0" />
                    {ind}
                  </p>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// Module 11: Code Footprint
function CodeFootprintPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as any;
  return (
    <div className="space-y-4" data-testid="panel-code-footprint">
      <ModuleHeader title="Code & Developer Footprint" icon={Code2} confidence={mod.confidence || 0} generatedAt={mod.generatedAt} />
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">GitHub / GitLab Organizations</CardTitle></CardHeader>
        <CardContent className="space-y-2">
          {(d.githubOrgs || []).map((org: any, i: number) => (
            <div key={i} className="flex items-center justify-between gap-3 p-2 rounded-md bg-muted/40">
              <div className="flex items-center gap-2">
                <Code2 className="w-4 h-4 text-muted-foreground" />
                <div>
                  <p className="text-sm font-medium font-mono">{org.name}</p>
                  <p className="text-xs text-muted-foreground">{org.publicRepos} repos, {org.members} members</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {org.verified && <CheckCircle2 className="w-3 h-3 text-blue-400" />}
                <EvidenceLink url={org.url} label="View" />
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Flagged Repositories</CardTitle></CardHeader>
        <CardContent className="space-y-2">
          {(d.flaggedRepos || []).map((repo: any, i: number) => (
            <div key={i} className="p-2 rounded-md bg-muted/40 space-y-1">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <SeverityDot severity={repo.severity} />
                  <span className="text-sm font-mono">{repo.name}</span>
                </div>
                <EvidenceLink url={repo.evidenceUrl} />
              </div>
              <p className="text-xs text-muted-foreground">{repo.issue}</p>
            </div>
          ))}
        </CardContent>
      </Card>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">CI/CD Artifacts</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(d.cicdArtifacts || []).map((a: any, i: number) => (
              <div key={i} className="p-2 rounded-md bg-muted/40 space-y-1">
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className="text-xs no-default-hover-elevate no-default-active-elevate">{a.type}</Badge>
                  <span className="text-sm font-mono">{a.repo}</span>
                </div>
                <div className="flex gap-1 flex-wrap">
                  {(a.badges || []).map((b: string, j: number) => (
                    <Badge key={j} variant="outline" className="text-xs bg-green-600/15 text-green-400 border-0 no-default-hover-elevate no-default-active-elevate">{b}</Badge>
                  ))}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Public Packages</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(d.publicPackages || []).map((p: any, i: number) => (
              <div key={i} className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/40">
                <div>
                  <p className="text-sm font-mono font-medium">{p.name}</p>
                  <p className="text-xs text-muted-foreground">{p.registry} v{p.version} ({p.downloads})</p>
                </div>
                <EvidenceLink url={p.url} label="Registry" />
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// Module 12: Third-Party Surface
function ThirdPartySurfacePanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as any;
  return (
    <div className="space-y-4" data-testid="panel-third-party">
      <ModuleHeader title="Third-Party & Supply Chain" icon={Link2} confidence={mod.confidence || 0} generatedAt={mod.generatedAt} />
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">SaaS Services Detected</CardTitle></CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Service</TableHead>
                  <TableHead>Category</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Confidence</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(d.saasServices || []).map((s: any, i: number) => (
                  <TableRow key={i}>
                    <TableCell className="text-sm font-medium">{s.name}</TableCell>
                    <TableCell><Badge variant="outline" className="text-xs no-default-hover-elevate no-default-active-elevate">{s.category}</Badge></TableCell>
                    <TableCell className="text-sm text-muted-foreground">{s.source}</TableCell>
                    <TableCell className="text-sm font-mono">{s.confidence}%</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Vendor Portals</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(d.vendorPortals || []).map((v: any, i: number) => (
              <div key={i} className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/40">
                <div>
                  <p className="text-sm font-mono">{v.subdomain}</p>
                  <p className="text-xs text-muted-foreground">{v.vendor} - {v.type}</p>
                </div>
                <span className="text-xs text-muted-foreground">{v.source}</span>
              </div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Breach References</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(d.breachReferences || []).map((b: any, i: number) => (
              <div key={i} className="p-2 rounded-md bg-muted/40 space-y-1">
                <div className="flex items-center gap-2">
                  <SeverityDot severity={b.severity} />
                  <span className="text-sm font-medium">{b.source}</span>
                </div>
                <p className="text-xs text-muted-foreground">{b.description}</p>
                <p className="text-xs text-muted-foreground">{b.date}</p>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
      {(d.riskFlags || []).length > 0 && (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Supply Chain Risk Flags</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {d.riskFlags.map((f: any, i: number) => (
              <div key={i} className="flex items-center gap-3 p-2 rounded-md bg-muted/40">
                <SeverityDot severity={f.severity} />
                <div className="flex-1">
                  <span className="text-sm font-medium">{f.service}</span>
                  <p className="text-xs text-muted-foreground">{f.risk}</p>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// Nuclei tab – displays Nuclei scan results (all templates)
function NucleiPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as {
    source?: string;
    hits?: Array<{
      templateId: string;
      templateName?: string;
      severity: string;
      host: string;
      matchedAt?: string;
      info?: { name?: string; description?: string };
      matcherName?: string;
      extractedResults?: string[];
    }>;
    templateCount?: number;
    allTemplatesLoaded?: boolean;
    skipped?: boolean;
    verifiedAt?: string;
  };
  const hits = d?.hits ?? [];
  const allTemplatesLoaded = d?.allTemplatesLoaded ?? false;
  const skipped = d?.skipped ?? false;

  return (
    <div className="space-y-4" data-testid="panel-nuclei">
      <ModuleHeader title="Nuclei Scan" icon={Zap} confidence={mod.confidence || 0} generatedAt={mod.generatedAt} />
      <div className="flex items-center gap-2 flex-wrap">
        {allTemplatesLoaded && (
          <Badge variant="outline" className="bg-green-600/15 text-green-400 border-0 no-default-hover-elevate no-default-active-elevate">
            All templates loaded
          </Badge>
        )}
        <span className="text-sm text-muted-foreground">
          {hits.length} finding{hits.length !== 1 ? "s" : ""} from Nuclei vulnerability scanner
        </span>
      </div>
      <p className="text-sm text-muted-foreground">
        {d?.source ?? "Nuclei scanner (all templates)"}. Template-based vulnerability detection across discovered hosts.
      </p>
      {skipped || hits.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <Zap className="w-12 h-12 text-muted-foreground/40 mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">
              {skipped ? "Nuclei scan was skipped" : "No Nuclei findings for this workspace"}
            </p>
            <p className="text-xs text-muted-foreground mt-1">
              {skipped ? (d?.source ?? "Nuclei CLI not installed. Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest") : "Run a full scan to execute Nuclei (requires Nuclei CLI installed)"}
            </p>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Template</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Host</TableHead>
                  <TableHead>Matched At</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {hits.map((h, i) => (
                  <TableRow key={i}>
                    <TableCell>
                      <div className="space-y-0.5">
                        <span className="font-mono text-xs">{h.templateId}</span>
                        {h.templateName && (
                          <p className="text-xs text-muted-foreground">{h.templateName}</p>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant="outline"
                        className={
                          h.severity === "critical" ? "bg-red-600/15 text-red-400 border-0" :
                          h.severity === "high" ? "bg-orange-600/15 text-orange-400 border-0" :
                          h.severity === "medium" ? "bg-yellow-600/15 text-yellow-400 border-0" :
                          "bg-slate-600/15 text-slate-400 border-0"
                        }
                      >
                        {h.severity}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <a href={h.host.startsWith("http") ? h.host : `https://${h.host}`} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline text-sm">
                        {h.host}
                      </a>
                    </TableCell>
                    <TableCell>
                      {h.matchedAt ? (
                        <a href={h.matchedAt} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline text-xs">
                          <ExternalLink className="w-3 h-3 inline mr-1" />
                          Evidence
                        </a>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// BGP Routing tab (BGPView API) – displays stored bgp_routing recon module
function BGPRoutingPanel({ mod }: { mod: ReconModule }) {
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

const IPReputationPanelWrapper: React.FC<{ mod: ReconModule }> = () => <IPReputationPanel />;

const moduleTypeToPanel: Record<string, { component: React.FC<{ mod: ReconModule }>; label: string; icon: React.ElementType }> = {
  org_identity: { component: OrgIdentityPanel, label: "Org Profile", icon: Building2 },
  web_presence: { component: WebPresencePanel, label: "Web Presence", icon: Globe },
  tech_stack: { component: TechStackPanel, label: "Tech Stack", icon: Cpu },
  cloud_footprint: { component: CloudFootprintPanel, label: "Cloud & Email", icon: Cloud },
  exposed_content: { component: ExposedContentPanel, label: "Exposures", icon: FileWarning },
  attack_surface: { component: AttackSurfacePanel, label: "Attack Surface", icon: ShieldAlert },
  ip_reputation: { component: IPReputationPanelWrapper, label: "IP Reputation", icon: Shield },
  bgp_routing: { component: BGPRoutingPanel, label: "BGP Routing", icon: Network },
  nuclei: { component: NucleiPanel, label: "Nuclei", icon: Zap },
  brand_signals: { component: BrandSignalsPanel, label: "Brand", icon: Megaphone },
  linkedin_company: { component: LinkedInCompanyPanel, label: "LinkedIn Org", icon: Linkedin },
  linkedin_people: { component: LinkedInPeoplePanel, label: "People Intel", icon: Users },
  linkedin_hiring: { component: LinkedInHiringPanel, label: "Hiring Signals", icon: Briefcase },
  code_footprint: { component: CodeFootprintPanel, label: "Code Footprint", icon: Code2 },
  third_party_surface: { component: ThirdPartySurfacePanel, label: "Third-Party", icon: Link2 },
  dns_overview: { component: DNSOverviewPanel, label: "DNS Records", icon: Network },
  redirect_chain: { component: RedirectChainPanel, label: "Redirect Chain", icon: ArrowRightLeft },
  domain_info: { component: DomainInfoPanel, label: "Domain Info", icon: Info },
  website_overview: { component: WebsiteOverviewPanel, label: "Website Overview", icon: LayoutDashboard },
};

const moduleOrder = [
  "org_identity", "web_presence", "tech_stack", "cloud_footprint",
  "exposed_content", "attack_surface", "ip_reputation", "bgp_routing", "nuclei", "brand_signals",
  "dns_overview", "redirect_chain", "domain_info", "website_overview",
  "linkedin_company", "linkedin_people", "linkedin_hiring",
  "code_footprint", "third_party_surface",
];

export default function Intelligence() {
  const { selectedWorkspaceId, workspaces } = useDomain();
  const { data: scans = [] } = useQuery<Scan[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/scans`],
    enabled: !!selectedWorkspaceId,
    refetchInterval: (q) => {
      const d = q.state.data as Scan[] | undefined;
      return d?.some((s) => s.status === "running" || s.status === "pending") ? 2000 : false;
    },
  });
  const hasRunningScans = scans.some((s) => s.status === "running" || s.status === "pending");
  const { data: modules = [], isLoading, isError } = useQuery<ReconModule[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/recon-modules`],
    enabled: !!selectedWorkspaceId,
    refetchInterval: hasRunningScans ? 4000 : false,
  });

  const modulesByType = modules.reduce((acc, mod) => {
    if (!(mod.moduleType in acc)) acc[mod.moduleType] = mod;
    return acc;
  }, {} as Record<string, ReconModule>);

  if (isError) {
    return (
      <div className="p-6">
        <p className="text-destructive text-sm">Failed to load intelligence data. Check that the server is running and try refreshing.</p>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="space-y-6 p-6">
        <Skeleton className="h-8 w-64 mb-2" />
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-96" />
      </div>
    );
  }

  const hasAnyModules = Object.keys(modulesByType).length > 0;
  const availableModules = moduleOrder.filter((t) => (t === "ip_reputation" ? hasAnyModules : modulesByType[t]));
  const defaultTab = availableModules[0] || "org_identity";

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight" data-testid="text-intelligence-title">Intelligence</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Comprehensive reconnaissance data across {availableModules.length} intelligence modules for {selectedWorkspaceId ? (workspaces.find((w) => w.id === selectedWorkspaceId)?.name ?? "this workspace") : "this workspace"}
        </p>
      </div>

      <div className="grid grid-cols-3 sm:grid-cols-4 lg:grid-cols-6 gap-2">
        {availableModules.map((type) => {
          const config = moduleTypeToPanel[type];
          const mod = modulesByType[type];
          return (
            <Card key={type} className="cursor-pointer" data-testid={`card-module-${type}`}>
              <CardContent className="p-3 text-center space-y-1">
                <config.icon className="w-4 h-4 text-primary mx-auto" />
                <p className="text-xs font-medium leading-tight">{config.label}</p>
                <p className="text-xs text-muted-foreground">{mod?.confidence || 0}%</p>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {availableModules.length === 0 ? (
        <Card>
          <CardContent className="py-16 text-center">
            <Search className="w-12 h-12 text-muted-foreground/40 mx-auto mb-4" />
            <p className="text-base font-medium text-muted-foreground">No intelligence data yet</p>
            <p className="text-sm text-muted-foreground mt-1">
              Run a scan to begin gathering intelligence
            </p>
          </CardContent>
        </Card>
      ) : (
        <Tabs defaultValue={defaultTab} className="space-y-4">
          <div className="overflow-x-auto">
            <TabsList className="inline-flex w-auto" data-testid="tabs-intelligence">
              {availableModules.map((type) => {
                const config = moduleTypeToPanel[type];
                return (
                  <TabsTrigger key={type} value={type} data-testid={`tab-${type}`} className="text-xs">
                    <config.icon className="w-3 h-3 mr-1" />
                    {config.label}
                  </TabsTrigger>
                );
              })}
            </TabsList>
          </div>
          {availableModules.map((type) => {
            const config = moduleTypeToPanel[type];
            const mod = modulesByType[type] ?? ({} as ReconModule);
            return (
              <TabsContent key={type} value={type}>
                <config.component mod={mod} />
              </TabsContent>
            );
          })}
        </Tabs>
      )}
    </div>
  );
}
