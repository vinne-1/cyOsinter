import React, { Suspense } from "react";
import { Switch, Route, Redirect, useLocation } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/app-sidebar";
import { ThemeProvider, ThemeToggle } from "@/components/theme-provider";
import { DomainProvider } from "@/lib/domain-context";
import { DomainSelector } from "@/components/domain-selector";
import { NotificationBell } from "@/components/notification-bell";
import { useAuth } from "@/pages/auth";
import { Loader2, AlertTriangle, RefreshCw } from "lucide-react";

class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean; error: Error | null }
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(_error: Error, _info: React.ErrorInfo) {
    // Error is captured in state via getDerivedStateFromError.
    // Integrate error reporting service (e.g. Sentry) here in production.
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center h-full p-8 gap-4">
          <AlertTriangle className="w-12 h-12 text-destructive" />
          <h2 className="text-lg font-semibold">Something went wrong</h2>
          <p className="text-sm text-muted-foreground max-w-md text-center">
            {this.state.error?.message ?? "An unexpected error occurred"}
          </p>
          <button
            className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-primary text-primary-foreground text-sm hover:bg-primary/90"
            onClick={() => this.setState({ hasError: false, error: null })}
          >
            <RefreshCw className="w-4 h-4" />
            Try Again
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

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
const AlertsPage = React.lazy(() => import("@/pages/alerts"));
const ScheduledScansPage = React.lazy(() => import("@/pages/scheduled-scans"));
const CompliancePage = React.lazy(() => import("@/pages/compliance"));
const TrendsPage = React.lazy(() => import("@/pages/trends"));
const ScanProfilesPage = React.lazy(() => import("@/pages/scan-profiles"));
const AttackPathsPage = React.lazy(() => import("@/pages/attack-paths"));
const AuthPage = React.lazy(() => import("@/pages/auth"));
const AuditLogPage = React.lazy(() => import("@/pages/audit-log"));
const WebhookConfigPage = React.lazy(() => import("@/pages/webhook-config"));
const ApiKeysPage = React.lazy(() => import("@/pages/api-keys-page"));
const FindingGroupsPage = React.lazy(() => import("@/pages/finding-groups"));
const ScanComparisonPage = React.lazy(() => import("@/pages/scan-comparison"));
const ThreatIntelPage = React.lazy(() => import("@/pages/threat-intel"));
const RetentionConfigPage = React.lazy(() => import("@/pages/retention-config"));
const PlaybooksPage = React.lazy(() => import("@/pages/playbooks"));
const AssetRiskPage = React.lazy(() => import("@/pages/asset-risk"));

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
        <Route path="/alerts" component={AlertsPage} />
        <Route path="/scheduled-scans" component={ScheduledScansPage} />
        <Route path="/compliance" component={CompliancePage} />
        <Route path="/trends" component={TrendsPage} />
        <Route path="/scan-profiles" component={ScanProfilesPage} />
        <Route path="/attack-paths" component={AttackPathsPage} />
        <Route path="/auth" component={AuthPage} />
        <Route path="/audit-log" component={AuditLogPage} />
        <Route path="/webhook-config" component={WebhookConfigPage} />
        <Route path="/api-keys" component={ApiKeysPage} />
        <Route path="/finding-groups" component={FindingGroupsPage} />
        <Route path="/scan-comparison" component={ScanComparisonPage} />
        <Route path="/threat-intel" component={ThreatIntelPage} />
        <Route path="/retention" component={RetentionConfigPage} />
        <Route path="/playbooks" component={PlaybooksPage} />
        <Route path="/asset-risk" component={AssetRiskPage} />
        <Route component={NotFound} />
      </Switch>
    </Suspense>
  );
}

function AuthenticatedApp() {
  const { isAuthenticated } = useAuth();
  const [location] = useLocation();

  if (!isAuthenticated && location !== "/auth") {
    return <Redirect to="/auth" />;
  }

  if (isAuthenticated && location === "/auth") {
    return <Redirect to="/" />;
  }

  if (!isAuthenticated) {
    return (
      <Suspense fallback={<div className="flex items-center justify-center h-screen"><Loader2 className="w-8 h-8 animate-spin" /></div>}>
        <AuthPage />
      </Suspense>
    );
  }

  return (
    <DomainProvider>
      <SidebarProvider>
        <div className="flex h-screen w-full">
          <AppSidebar />
          <div className="flex flex-col flex-1 overflow-hidden">
            <header className="flex items-center justify-between gap-2 p-2 border-b h-12 flex-shrink-0">
              <SidebarTrigger data-testid="button-sidebar-toggle" />
              <div className="flex items-center gap-2">
                <DomainSelector />
                <NotificationBell />
                <ThemeToggle />
              </div>
            </header>
            <main className="flex-1 overflow-y-auto">
              <ErrorBoundary>
                <Router />
              </ErrorBoundary>
            </main>
          </div>
        </div>
      </SidebarProvider>
      <Toaster />
    </DomainProvider>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <TooltipProvider>
          <AuthenticatedApp />
        </TooltipProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;
