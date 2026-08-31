import { useMemo, useState } from "react";
import { useLocation, Link } from "wouter";
import { Shield, ChevronLeft, ChevronRight, Search, X } from "lucide-react";
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
import { NAV_GROUPS, type NavItem } from "@/components/nav-items";
import { cn } from "@/lib/utils";

function matches(item: NavItem, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return (
    item.title.toLowerCase().includes(q) ||
    (item.keywords?.toLowerCase().includes(q) ?? false)
  );
}

export function AppSidebar() {
  const [location] = useLocation();
  const { toggleSidebar, open } = useSidebar();
  const [query, setQuery] = useState("");

  // With ~25 destinations, scanning the list is slower than typing. The filter
  // matches titles and the keyword aliases defined alongside each item.
  const groups = useMemo(
    () =>
      NAV_GROUPS.map((g) => ({ ...g, items: g.items.filter((i) => matches(i, query)) })).filter(
        (g) => g.items.length > 0,
      ),
    [query],
  );

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader className="p-4">
        <div className="flex items-center gap-3">
          <div className="relative flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-brand-from to-brand-to shadow-glow-sm">
            <Shield className="h-4 w-4 text-white" aria-hidden="true" />
          </div>
          <span className="text-lg font-semibold tracking-tight group-data-[collapsible=icon]:hidden">
            Cyshield
          </span>
        </div>

        <div className="relative mt-3 group-data-[collapsible=icon]:hidden">
          <Search
            className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
            aria-hidden="true"
          />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter navigation…"
            aria-label="Filter navigation"
            data-testid="input-nav-filter"
            className={cn(
              "h-8 w-full rounded-md border border-sidebar-border bg-sidebar-accent/40 pl-8 pr-7 text-xs",
              "text-sidebar-foreground placeholder:text-muted-foreground",
              "focus:outline-none focus:ring-1 focus:ring-sidebar-ring",
            )}
          />
          {query && (
            <button
              type="button"
              onClick={() => setQuery("")}
              aria-label="Clear navigation filter"
              className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-sidebar-foreground"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </SidebarHeader>

      <SidebarContent>
        {groups.length === 0 && (
          <p className="px-4 py-6 text-center text-xs text-muted-foreground group-data-[collapsible=icon]:hidden">
            No pages match “{query}”.
          </p>
        )}
        {groups.map((group) => (
          <SidebarGroup key={group.label}>
            {/* No opacity modifier here: /60 stacked on an already-muted token
                measured 2.39:1, far below the 4.5:1 WCAG AA threshold. */}
            <SidebarGroupLabel className="text-xs uppercase tracking-wider text-muted-foreground">
              {group.label}
            </SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {group.items.map((item) => {
                  const isActive =
                    item.url === "/" ? location === "/" : location.startsWith(item.url);
                  return (
                    <SidebarMenuItem key={item.title}>
                      <SidebarMenuButton asChild isActive={isActive} tooltip={item.title}>
                        <Link
                          href={item.url}
                          aria-current={isActive ? "page" : undefined}
                          data-testid={`link-nav-${item.title.toLowerCase().replace(/\s/g, "-")}`}
                        >
                          {/* Active rail — a 2px accent bar reads faster than a
                              background tint alone, especially when collapsed. */}
                          <span
                            aria-hidden="true"
                            className={cn(
                              "absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-r-full transition-all duration-200",
                              isActive ? "bg-sidebar-primary opacity-100" : "opacity-0",
                            )}
                          />
                          <item.icon className="h-4 w-4" aria-hidden="true" />
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
          aria-label={open ? "Collapse sidebar" : "Expand sidebar"}
          data-testid="button-collapse-sidebar"
          className="w-full"
        >
          {open ? <ChevronLeft className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        </Button>
      </SidebarFooter>
    </Sidebar>
  );
}
