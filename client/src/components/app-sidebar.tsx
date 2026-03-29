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
  ChevronLeft,
  ChevronRight,
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

const navItems = [
  { title: "Dashboard", url: "/", icon: LayoutDashboard },
  { title: "Attack Surface", url: "/easm", icon: Globe },
  { title: "OSINT Discovery", url: "/osint", icon: Search },
  { title: "Intelligence", url: "/intelligence", icon: Brain },
  { title: "AI Insights", url: "/ai-insights", icon: Sparkles },
  { title: "Findings", url: "/findings", icon: Inbox },
  { title: "Reports", url: "/reports", icon: FileText },
  { title: "Import Scans", url: "/imports", icon: Upload },
  { title: "Integrations", url: "/integrations", icon: Plug },
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
        <SidebarGroup>
          <SidebarGroupLabel className="text-xs uppercase tracking-wider text-muted-foreground/60">
            Platform
          </SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {navItems.map((item) => {
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
