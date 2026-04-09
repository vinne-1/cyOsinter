import { useEffect, useState } from "react";
import { useLocation, Link } from "wouter";
import {
  Shield,
  Server,
  HardDrive,
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
  ClipboardList,
  BookOpenText,
  ActivitySquare,
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
import { Badge } from "@/components/ui/badge";
import { buildUrl } from "@/lib/queryClient";

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
      { title: "Risk Register", url: "/risk-register", icon: ClipboardList },
      { title: "Compliance Drift", url: "/compliance-drift", icon: ActivitySquare },
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
      { title: "Questionnaires", url: "/questionnaires", icon: FileText },
      { title: "Policies", url: "/policies", icon: BookOpenText },
      { title: "Retention", url: "/retention", icon: Trash2 },
    ],
  },
];

type ServiceStatus = "up" | "down" | "unknown";

interface SystemStatusResponse {
  backend: "up";
  database: "up" | "down";
  checkedAt: string;
}

interface SystemStatusState {
  backend: ServiceStatus;
  database: ServiceStatus;
  checkedAt: string | null;
}

const POLL_INTERVAL_MS = 15000;

function useSystemStatus(): SystemStatusState {
  const [status, setStatus] = useState<SystemStatusState>({
    backend: "unknown",
    database: "unknown",
    checkedAt: null,
  });

  useEffect(() => {
    let cancelled = false;

    async function pollStatus() {
      try {
        const res = await fetch(buildUrl("/api/system/status"), {
          cache: "no-store",
          credentials: "include",
        });

        if (!res.ok) {
          throw new Error(`HTTP ${res.status}`);
        }

        const data = (await res.json()) as SystemStatusResponse;
        if (cancelled) return;

        setStatus({
          backend: "up",
          database: data.database,
          checkedAt: data.checkedAt,
        });
      } catch {
        if (cancelled) return;

        setStatus({
          backend: "down",
          database: "unknown",
          checkedAt: new Date().toISOString(),
        });
      }
    }

    void pollStatus();
    const intervalId = window.setInterval(() => {
      void pollStatus();
    }, POLL_INTERVAL_MS);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, []);

  return status;
}

function formatStatusLabel(status: ServiceStatus, checkingLabel = "Checking"): string {
  if (status === "up") return "Up";
  if (status === "down") return "Down";
  return checkingLabel;
}

function getStatusBadgeClassName(status: ServiceStatus): string {
  if (status === "up") {
    return "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300";
  }

  if (status === "down") {
    return "border-destructive/30 bg-destructive/10 text-destructive";
  }

  return "border-border bg-muted/40 text-muted-foreground";
}

function getStatusIconClassName(status: ServiceStatus): string {
  if (status === "up") return "text-emerald-600 dark:text-emerald-300";
  if (status === "down") return "text-destructive";
  return "text-muted-foreground";
}

function StatusRow({
  icon: Icon,
  label,
  status,
}: {
  icon: typeof Server;
  label: string;
  status: ServiceStatus;
}) {
  return (
    <div className="flex items-center justify-between gap-2 rounded-md border border-border/60 px-2 py-1.5">
      <div className="flex items-center gap-2 min-w-0">
        <Icon className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
        <span className="truncate text-xs text-muted-foreground">{label}</span>
      </div>
      <Badge
        variant="outline"
        className={getStatusBadgeClassName(status)}
      >
        {formatStatusLabel(status)}
      </Badge>
    </div>
  );
}

function StatusIcon({
  icon: Icon,
  label,
  status,
}: {
  icon: typeof Server;
  label: string;
  status: ServiceStatus;
}) {
  return (
    <div
      className="flex h-8 w-8 items-center justify-center rounded-md border border-border/60 bg-background/40"
      title={`${label}: ${formatStatusLabel(status)}`}
      aria-label={`${label}: ${formatStatusLabel(status)}`}
    >
      <Icon className={`h-4 w-4 ${getStatusIconClassName(status)}`} />
    </div>
  );
}

function SidebarSystemStatus({ open }: { open: boolean }) {
  const status = useSystemStatus();
  const lastChecked = status.checkedAt
    ? new Date(status.checkedAt).toLocaleTimeString([], {
        hour: "numeric",
        minute: "2-digit",
      })
    : null;

  if (!open) {
    return (
      <div className="flex flex-col items-center gap-1">
        <StatusIcon icon={Server} label="Backend" status={status.backend} />
        <StatusIcon icon={HardDrive} label="Database" status={status.database} />
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <div className="space-y-1">
        <StatusRow icon={Server} label="Backend" status={status.backend} />
        <StatusRow icon={HardDrive} label="Database" status={status.database} />
      </div>
      {lastChecked ? (
        <p className="px-1 text-[10px] text-muted-foreground">
          Checked {lastChecked}
        </p>
      ) : null}
    </div>
  );
}

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
        <SidebarSystemStatus open={open} />
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
