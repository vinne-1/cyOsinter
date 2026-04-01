import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Unplug, Lock, Unlock, ExternalLink } from "lucide-react";
import { ModuleHeader, SeverityDot } from "./shared";
import type { ReconModule } from "@shared/schema";

export function ApiDiscoveryPanel({ mod }: { mod: ReconModule }) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const d = mod.data as Record<string, any>;
  const endpoints = d.endpoints as Array<{
    path: string;
    type: string;
    status: number;
    authenticated: boolean;
    details: string;
  }> | undefined;
  const openApiSpec = d.openApiSpec as { title: unknown; version: unknown; pathCount: number } | null | undefined;

  const typeColors: Record<string, string> = {
    documentation: "bg-blue-500/10 text-blue-500",
    graphql: "bg-purple-500/10 text-purple-500",
    rest: "bg-green-500/10 text-green-500",
    debug: "bg-red-500/10 text-red-500",
    auth: "bg-yellow-500/10 text-yellow-500",
  };

  return (
    <Card data-testid="panel-api-discovery">
      <CardContent className="p-5">
        <ModuleHeader title="API Security" icon={Unplug} confidence={mod.confidence ?? 0} generatedAt={mod.generatedAt} />

        {openApiSpec && (
          <div className="mb-4 p-3 rounded-md bg-muted/30 border">
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-1">OpenAPI Spec</p>
            <p className="text-sm">
              {String(openApiSpec.title ?? "Unknown API")} <span className="text-muted-foreground">v{String(openApiSpec.version ?? "?")}</span>
            </p>
            <p className="text-xs text-muted-foreground">{openApiSpec.pathCount} endpoint{openApiSpec.pathCount !== 1 ? "s" : ""} documented</p>
          </div>
        )}

        {!endpoints || endpoints.length === 0 ? (
          <p className="text-sm text-muted-foreground">No API endpoints discovered.</p>
        ) : (
          <div className="space-y-2">
            <p className="text-sm text-muted-foreground mb-3">
              {endpoints.length} API endpoint{endpoints.length > 1 ? "s" : ""} discovered
            </p>
            {endpoints.map((ep, i) => (
              <div key={i} className="flex items-center gap-2 p-2 rounded-md bg-muted/20 text-sm">
                {ep.authenticated ? (
                  <Unlock className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />
                ) : (
                  <Lock className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />
                )}
                <span className="font-mono text-xs flex-1 truncate">{ep.path}</span>
                <Badge variant="outline" className={`text-[10px] ${typeColors[ep.type] ?? ""}`}>
                  {ep.type}
                </Badge>
                <span className="text-[10px] text-muted-foreground font-mono">{ep.status}</span>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
