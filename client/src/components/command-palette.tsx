import React from "react";
import { useLocation } from "wouter";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
  CommandShortcut,
} from "@/components/ui/command";
import { useDomain } from "@/lib/domain-context";
import { NAV_GROUPS } from "@/components/nav-items";
import { Globe, Moon, Sun } from "lucide-react";
import { useTheme } from "@/components/theme-provider";

/**
 * Global command palette (⌘K / Ctrl-K).
 *
 * With ~25 destinations in the sidebar, keyboard navigation is the difference
 * between "an admin panel" and a tool an analyst can drive at speed. It also
 * gives workspace switching a home that does not depend on finding the header
 * dropdown.
 */
export function CommandPalette() {
  const [open, setOpen] = React.useState(false);
  const [, navigate] = useLocation();
  const { workspaces, setSelectedWorkspace } = useDomain();
  const { theme, setTheme } = useTheme();

  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key.toLowerCase() === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((v) => !v);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  const run = React.useCallback((fn: () => void) => {
    setOpen(false);
    fn();
  }, []);

  return (
    <CommandDialog open={open} onOpenChange={setOpen}>
      <CommandInput placeholder="Search pages, workspaces and actions…" />
      <CommandList>
        <CommandEmpty>No results found.</CommandEmpty>

        {NAV_GROUPS.map((group) => (
          <CommandGroup key={group.label} heading={group.label}>
            {group.items.map((item) => (
              <CommandItem
                key={item.url}
                value={`${group.label} ${item.title}`}
                onSelect={() => run(() => navigate(item.url))}
              >
                <item.icon className="mr-2 h-4 w-4" aria-hidden="true" />
                <span>{item.title}</span>
              </CommandItem>
            ))}
          </CommandGroup>
        ))}

        {workspaces.length > 0 && (
          <>
            <CommandSeparator />
            <CommandGroup heading="Switch workspace">
              {workspaces.slice(0, 12).map((ws) => (
                <CommandItem
                  key={ws.id}
                  value={`workspace ${ws.name} ${ws.domain ?? ""}`}
                  onSelect={() => run(() => setSelectedWorkspace(ws))}
                >
                  <Globe className="mr-2 h-4 w-4" aria-hidden="true" />
                  <span className="font-mono text-sm">{ws.domain || ws.name}</span>
                </CommandItem>
              ))}
            </CommandGroup>
          </>
        )}

        <CommandSeparator />
        <CommandGroup heading="Appearance">
          <CommandItem
            value="toggle theme dark light"
            onSelect={() => run(() => setTheme(theme === "dark" ? "light" : "dark"))}
          >
            {theme === "dark"
              ? <Sun className="mr-2 h-4 w-4" aria-hidden="true" />
              : <Moon className="mr-2 h-4 w-4" aria-hidden="true" />}
            <span>Switch to {theme === "dark" ? "light" : "dark"} theme</span>
            <CommandShortcut>⌘K</CommandShortcut>
          </CommandItem>
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  );
}
