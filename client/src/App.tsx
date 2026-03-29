import React, { Suspense } from "react";
import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/app-sidebar";
import { ThemeProvider, ThemeToggle } from "@/components/theme-provider";
import { DomainProvider } from "@/lib/domain-context";
import { DomainSelector } from "@/components/domain-selector";
import { Loader2 } from "lucide-react";

const NotFound = React.lazy(() => import("@/pages/not-found"));
const Dashboard = React.lazy(() => import("@/pages/dashboard"));
const EASM = React.lazy(() => import("@/pages/easm"));
const OSINT = React.lazy(() => import("@/pages/osint"));
const Findings = React.lazy(() => import("@/pages/findings"));
const Reports = React.lazy(() => import("@/pages/reports"));
const Intelligence = React.lazy(() => import("@/pages/intelligence"));
const Integrations = React.lazy(() => import("@/pages/integrations"));
const Imports = React.lazy(() => import("@/pages/imports"));
const AIInsights = React.lazy(() => import("@/pages/ai-insights"));

function Router() {
  return (
    <Suspense fallback={<div className="flex items-center justify-center h-screen"><Loader2 className="w-8 h-8 animate-spin" /></div>}>
      <Switch>
        <Route path="/" component={Dashboard} />
        <Route path="/easm" component={EASM} />
        <Route path="/osint" component={OSINT} />
        <Route path="/findings" component={Findings} />
        <Route path="/intelligence" component={Intelligence} />
        <Route path="/reports" component={Reports} />
        <Route path="/integrations" component={Integrations} />
        <Route path="/imports" component={Imports} />
        <Route path="/ai-insights" component={AIInsights} />
        <Route component={NotFound} />
      </Switch>
    </Suspense>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <TooltipProvider>
          <DomainProvider>
            <SidebarProvider>
              <div className="flex h-screen w-full">
                <AppSidebar />
                <div className="flex flex-col flex-1 overflow-hidden">
                  <header className="flex items-center justify-between gap-2 p-2 border-b h-12 flex-shrink-0">
                    <SidebarTrigger data-testid="button-sidebar-toggle" />
                    <div className="flex items-center gap-2">
                      <DomainSelector />
                      <ThemeToggle />
                    </div>
                  </header>
                  <main className="flex-1 overflow-y-auto">
                    <Router />
                  </main>
                </div>
              </div>
            </SidebarProvider>
            <Toaster />
          </DomainProvider>
        </TooltipProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;
