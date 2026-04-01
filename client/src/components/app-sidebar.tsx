import { useLocation, Link } from "wouter";
import {
  Shield,
  LayoutDashboard,
  Globe,
  Search,
  Inbox,
  FileText,
  Brain,
  Plug,
  Upload,
  Sparkles,
  Bell,
  CalendarClock,
  ShieldCheck,
  TrendingUp,
  SlidersHorizontal,
  Route,
  ChevronLeft,
  ChevronRight,
  Layers,
  GitCompare,
  Crosshair,
  BarChart3,
  Radar,
  Key,
  ScrollText,
  Webhook,
  Trash2,
} from "lucide-react";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarHeader,
  SidebarFooter,
  useSidebar,
} from "@/components/ui/sidebar";
import { Button } from "@/components/ui/button";

interface NavItem {
  title: string;
  url: string;
  icon: typeof LayoutDashboard;
}

const navGroups: Array<{ label: string; items: NavItem[] }> = [
  {
    label: "Overview",
    items: [
      { title: "Dashboard", url: "/", icon: LayoutDashboard },
    ],
  },
  {
    label: "Scanning",
    items: [
      { title: "Attack Surface", url: "/easm", icon: Globe },
      { title: "OSINT Discovery", url: "/osint", icon: Search },
      { title: "Scan Profiles", url: "/scan-profiles", icon: SlidersHorizontal },
      { title: "Scheduled Scans", url: "/scheduled-scans", icon: CalendarClock },
    ],
  },
  {
    label: "Analysis",
    items: [
      { title: "Findings", url: "/findings", icon: Inbox },
      { title: "Finding Groups", url: "/finding-groups", icon: Layers },
      { title: "Scan Comparison", url: "/scan-comparison", icon: GitCompare },
      { title: "Intelligence", url: "/intelligence", icon: Brain },
      { title: "Threat Intel", url: "/threat-intel", icon: Radar },
      { title: "AI Insights", url: "/ai-insights", icon: Sparkles },
      { title: "Attack Paths", url: "/attack-paths", icon: Route },
      { title: "Playbooks", url: "/playbooks", icon: Crosshair },
      { title: "Asset Risk", url: "/asset-risk", icon: BarChart3 },
      { title: "Compliance", url: "/compliance", icon: ShieldCheck },
      { title: "Trends", url: "/trends", icon: TrendingUp },
    ],
  },
  {
    label: "Operations",
    items: [
      { title: "Reports", url: "/reports", icon: FileText },
      { title: "Notifications", url: "/alerts", icon: Bell },
      { title: "Webhooks", url: "/webhook-config", icon: Webhook },
      { title: "API Keys", url: "/api-keys", icon: Key },
      { title: "Audit Log", url: "/audit-log", icon: ScrollText },
      { title: "Import Scans", url: "/imports", icon: Upload },
      { title: "Integrations", url: "/integrations", icon: Plug },
      { title: "Retention", url: "/retention", icon: Trash2 },
    ],
  },
];

export function AppSidebar() {
  const [location] = useLocation();
  const { toggleSidebar, open } = useSidebar();

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader className="p-4">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-8 h-8 rounded-md bg-primary/15">
            <Shield className="w-5 h-5 text-primary" />
          </div>
          <span className="text-lg font-semibold tracking-tight group-data-[collapsible=icon]:hidden">
            Cyshield
          </span>
        </div>
      </SidebarHeader>

      <SidebarContent>
        {navGroups.map((group) => (
          <SidebarGroup key={group.label}>
            <SidebarGroupLabel className="text-xs uppercase tracking-wider text-muted-foreground/60">
              {group.label}
            </SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {group.items.map((item) => {
                  const isActive =
                    item.url === "/"
                      ? location === "/"
                      : location.startsWith(item.url);
                  return (
                    <SidebarMenuItem key={item.title}>
                      <SidebarMenuButton
                        asChild
                        isActive={isActive}
                        tooltip={item.title}
                      >
                        <Link href={item.url} data-testid={`link-nav-${item.title.toLowerCase().replace(/\s/g, "-")}`}>
                          <item.icon className="w-4 h-4" />
                          <span>{item.title}</span>
                        </Link>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  );
                })}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        ))}
      </SidebarContent>

      <SidebarFooter className="p-2">
        <Button
          variant="ghost"
          size="icon"
          onClick={toggleSidebar}
          data-testid="button-collapse-sidebar"
          className="w-full"
        >
          {open ? <ChevronLeft className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </Button>
      </SidebarFooter>
    </Sidebar>
  );
}
