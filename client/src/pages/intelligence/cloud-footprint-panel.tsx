import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Cloud } from "lucide-react";
import type { ReconModule } from "@shared/schema";
import { ModuleHeader, GradeBadge, StatusIcon } from "./shared";

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

export function CloudFootprintPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as Record<string, any>;
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
