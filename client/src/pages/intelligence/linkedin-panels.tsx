import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Linkedin,
  Users,
  Briefcase,
  TrendingUp,
  CheckCircle2,
  MapPin,
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
import { ModuleHeader, EvidenceLink, StatusIcon } from "./shared";

// Module 8: LinkedIn Company
export function LinkedInCompanyPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as Record<string, any>;
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
export function LinkedInPeoplePanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as Record<string, any>;
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
export function LinkedInHiringPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as Record<string, any>;
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
