import React from "react";
import { useQuery } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { Card, CardContent } from "@/components/ui/card";
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
  Search,
  Network,
  ArrowRightLeft,
  Info,
  LayoutDashboard,
  Shield,
  Zap,
  AlertTriangle,
  Unplug,
  KeyRound,
  ScanLine,
} from "lucide-react";
import type { ReconModule, Scan } from "@shared/schema";

import { OrgIdentityPanel } from "./org-identity-panel";
import { WebPresencePanel } from "./web-presence-panel";
import { TechStackPanel } from "./tech-stack-panel";
import { CloudFootprintPanel } from "./cloud-footprint-panel";
import { ExposedContentPanel } from "./exposed-content-panel";
import { AttackSurfacePanel } from "./attack-surface-panel";
import { IPReputationPanel } from "./ip-reputation-panel";
import { BGPRoutingPanel } from "./bgp-routing-panel";
import { NucleiPanel } from "./nuclei-panel";
import { BrandSignalsPanel } from "./brand-signals-panel";
import { LinkedInCompanyPanel, LinkedInPeoplePanel, LinkedInHiringPanel } from "./linkedin-panels";
import { CodeFootprintPanel } from "./code-footprint-panel";
import { ThirdPartySurfacePanel } from "./third-party-panel";
import { DNSOverviewPanel, RedirectChainPanel, DomainInfoPanel, WebsiteOverviewPanel } from "./osint-panels";
import { TakeoverPanel } from "./takeover-panel";
import { ApiDiscoveryPanel } from "./api-discovery-panel";
import { SecretExposurePanel } from "./secret-exposure-panel";
import { DASTPanel } from "./dast-panel";

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
  subdomain_takeover: { component: TakeoverPanel, label: "Takeover", icon: AlertTriangle },
  api_discovery: { component: ApiDiscoveryPanel, label: "API Security", icon: Unplug },
  secret_exposure: { component: SecretExposurePanel, label: "Secrets", icon: KeyRound },
  dast_lite: { component: DASTPanel, label: "DAST", icon: ScanLine },
};

const moduleOrder = [
  "org_identity", "web_presence", "tech_stack", "cloud_footprint",
  "exposed_content", "attack_surface", "ip_reputation", "bgp_routing", "nuclei", "brand_signals",
  "dns_overview", "redirect_chain", "domain_info", "website_overview",
  "linkedin_company", "linkedin_people", "linkedin_hiring",
  "subdomain_takeover", "api_discovery", "secret_exposure", "dast_lite",
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
