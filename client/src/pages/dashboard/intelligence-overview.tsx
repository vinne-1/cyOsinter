import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Globe,
  AlertTriangle,
  ArrowUpRight,
  Brain,
  ShieldAlert,
  Lock,
  Mail,
  Users,
  Shield,
} from "lucide-react";
import type { ReconModule } from "@shared/schema";
import { Link } from "wouter";
import { deriveTlsGradeForOverview, deriveCloudGradeForOverview } from "./helpers";

export function IntelligenceOverview({ modules }: { modules: ReconModule[] }) {
  const modulesByType = modules.reduce((acc, mod) => {
    if (!(mod.moduleType in acc)) acc[mod.moduleType] = mod;
    return acc;
  }, {} as Record<string, ReconModule>);

  /* eslint-disable @typescript-eslint/no-explicit-any -- module data shapes vary by type */
  const attackSurface = modulesByType["attack_surface"]?.data as Record<string, any> | undefined;
  const cloud = modulesByType["cloud_footprint"]?.data as Record<string, any> | undefined;
  const webPresence = modulesByType["web_presence"]?.data as Record<string, any> | undefined;
  const people = modulesByType["linkedin_people"]?.data as Record<string, any> | undefined;
  /* eslint-enable @typescript-eslint/no-explicit-any */
  const avgConfidence = modules.length > 0
    ? Math.round(modules.reduce((sum, m) => sum + (m.confidence || 0), 0) / modules.length)
    : 0;

  const tlsGrade = deriveTlsGradeForOverview(attackSurface);
  const cloudGrade = deriveCloudGradeForOverview(cloud);
  const totalSubdomains = webPresence?.totalSubdomains ?? webPresence?.totalSubdomainsEnumerated ?? 0;
  const assetInventory = (attackSurface?.assetInventory || []) as Array<{ riskScore: number; waf: string }>;
  const totalHosts = assetInventory.length || 0;
  const highRiskHosts = assetInventory.filter((a) => a.riskScore >= 60).length;
  const wafCoverage = totalHosts > 0 ? Math.round((assetInventory.filter((a) => a.waf).length / totalHosts) * 100) : 0;

  const highlights = [
    { icon: ShieldAlert, label: "Surface Risk", value: attackSurface?.surfaceRiskScore != null ? `${attackSurface.surfaceRiskScore}/100` : "N/A", color: attackSurface?.surfaceRiskScore >= 70 ? "text-red-400" : attackSurface?.surfaceRiskScore != null ? "text-yellow-400" : "text-muted-foreground" },
    { icon: Globe, label: "Hosts", value: totalHosts || totalSubdomains, color: "text-primary" },
    { icon: AlertTriangle, label: "High Risk", value: highRiskHosts, color: highRiskHosts > 0 ? "text-orange-400" : "text-muted-foreground" },
    { icon: Shield, label: "WAF Coverage", value: totalHosts > 0 ? `${wafCoverage}%` : "N/A", color: "text-primary" },
    { icon: Lock, label: "TLS Grade", value: tlsGrade, color: "text-green-400" },
    { icon: Mail, label: "Email Security", value: cloudGrade, color: "text-blue-400" },
    { icon: Users, label: "Employees", value: people?.totalEmployees ?? 0, color: "text-primary" },
    { icon: Brain, label: "Intel Modules", value: `${modules.length} (${avgConfidence}%)`, color: "text-primary" },
  ];

  return (
    <Card data-testid="card-intelligence-overview">
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
        <CardTitle className="text-sm font-medium">Intelligence Overview</CardTitle>
        <Link href="/intelligence">
          <Badge variant="outline" className="text-xs cursor-pointer" data-testid="link-view-intelligence">
            Explore
            <ArrowUpRight className="w-3 h-3 ml-1" />
          </Badge>
        </Link>
      </CardHeader>
      <CardContent>
        {modules.length === 0 ? (
          <p className="text-sm text-muted-foreground py-8 text-center">No intelligence data yet. Run a scan to begin.</p>
        ) : (
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            {highlights.map((h) => (
              <div key={h.label} className="flex items-center gap-3 p-3 rounded-md bg-muted/40" data-testid={`intel-stat-${h.label.toLowerCase().replace(/\s/g, "-")}`}>
                <div className="flex items-center justify-center w-8 h-8 rounded-md bg-muted/60 flex-shrink-0">
                  <h.icon className={`w-4 h-4 ${h.color}`} />
                </div>
                <div>
                  <p className={`text-sm font-semibold ${h.color}`}>{h.value}</p>
                  <p className="text-xs text-muted-foreground">{h.label}</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
