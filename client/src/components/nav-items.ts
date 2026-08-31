import {
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
  Layers,
  GitCompare,
  Crosshair,
  BarChart3,
  Radar,
  Key,
  ScrollText,
  Webhook,
  Trash2,
  ShieldAlert,
  Briefcase,
} from "lucide-react";

export interface NavItem {
  title: string;
  url: string;
  icon: typeof LayoutDashboard;
  /** Extra terms matched by the sidebar filter and the command palette. */
  keywords?: string;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

/**
 * The application's navigation, shared by the sidebar and the command palette
 * so the two can never disagree about what pages exist.
 */
export const NAV_GROUPS: NavGroup[] = [
  {
    label: "Overview",
    items: [{ title: "Dashboard", url: "/", icon: LayoutDashboard, keywords: "home posture score overview" }],
  },
  {
    label: "Scanning",
    items: [
      { title: "Attack Surface", url: "/easm", icon: Globe, keywords: "easm assets subdomains ports" },
      { title: "OSINT Discovery", url: "/osint", icon: Search, keywords: "leaks credentials documents" },
      { title: "Scan Profiles", url: "/scan-profiles", icon: SlidersHorizontal, keywords: "presets config" },
      { title: "Scheduled Scans", url: "/scheduled-scans", icon: CalendarClock, keywords: "cron recurring automation" },
    ],
  },
  {
    label: "Analysis",
    items: [
      { title: "Findings", url: "/findings", icon: Inbox, keywords: "vulnerabilities issues triage inbox" },
      { title: "Cases", url: "/cases", icon: Briefcase, keywords: "incident work owner assignee sla deadline ticket" },
      { title: "Finding Groups", url: "/finding-groups", icon: Layers, keywords: "cluster dedupe" },
      { title: "Scan Comparison", url: "/scan-comparison", icon: GitCompare, keywords: "diff delta changes" },
      { title: "Intelligence", url: "/intelligence", icon: Brain, keywords: "recon modules dns tls whois" },
      { title: "Threat Intel", url: "/threat-intel", icon: Radar, keywords: "cve reputation ioc" },
      { title: "Brand Threats", url: "/brand-threats", icon: ShieldAlert, keywords: "typosquat lookalike phishing impersonation domain squatting homoglyph" },
      { title: "AI Insights", url: "/ai-insights", icon: Sparkles, keywords: "llm summary analysis" },
      { title: "Attack Paths", url: "/attack-paths", icon: Route, keywords: "chains kill chain graph" },
      { title: "Playbooks", url: "/playbooks", icon: Crosshair, keywords: "remediation runbook" },
      { title: "Asset Risk", url: "/asset-risk", icon: BarChart3, keywords: "scoring ranking crown jewels" },
      { title: "Compliance", url: "/compliance", icon: ShieldCheck, keywords: "iso soc2 pci nist mapping" },
      { title: "Trends", url: "/trends", icon: TrendingUp, keywords: "history over time chart" },
    ],
  },
  {
    label: "Operations",
    items: [
      { title: "Reports", url: "/reports", icon: FileText, keywords: "export docx pdf evidence" },
      { title: "Notifications", url: "/alerts", icon: Bell, keywords: "alerts inbox" },
      { title: "Webhooks", url: "/webhook-config", icon: Webhook, keywords: "integration callback slack" },
      { title: "API Keys", url: "/api-keys", icon: Key, keywords: "tokens credentials access" },
      { title: "Audit Log", url: "/audit-log", icon: ScrollText, keywords: "activity trail compliance who did" },
      { title: "Import Scans", url: "/imports", icon: Upload, keywords: "nmap nessus upload" },
      { title: "Integrations", url: "/integrations", icon: Plug, keywords: "jira shodan virustotal keys" },
      { title: "Retention", url: "/retention", icon: Trash2, keywords: "purge cleanup data lifecycle" },
    ],
  },
];

/** Flat list of every nav item, useful for search and breadcrumbs. */
export const NAV_ITEMS: NavItem[] = NAV_GROUPS.flatMap((g) => g.items);

/** Resolves a pathname to its nav item, for page titles and breadcrumbs. */
export function navItemForPath(pathname: string): NavItem | undefined {
  if (pathname === "/") return NAV_ITEMS.find((i) => i.url === "/");
  // Longest matching prefix wins, so /scan-profiles never resolves to /scan-comparison.
  return NAV_ITEMS.filter((i) => i.url !== "/" && pathname.startsWith(i.url)).sort(
    (a, b) => b.url.length - a.url.length,
  )[0];
}
