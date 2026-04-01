import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Cpu } from "lucide-react";
import type { ReconModule } from "@shared/schema";
import { ModuleHeader, SeverityDot } from "./shared";

export function TechStackPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as Record<string, any>;
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
