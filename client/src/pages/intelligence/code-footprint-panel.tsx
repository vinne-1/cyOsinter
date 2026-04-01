import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Code2, CheckCircle2 } from "lucide-react";
import type { ReconModule } from "@shared/schema";
import { ModuleHeader, SeverityDot, EvidenceLink } from "./shared";

export function CodeFootprintPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as Record<string, any>;
  return (
    <div className="space-y-4" data-testid="panel-code-footprint">
      <ModuleHeader title="Code & Developer Footprint" icon={Code2} confidence={mod.confidence || 0} generatedAt={mod.generatedAt} />
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">GitHub / GitLab Organizations</CardTitle></CardHeader>
        <CardContent className="space-y-2">
          {(d.githubOrgs || []).map((org: any, i: number) => (
            <div key={i} className="flex items-center justify-between gap-3 p-2 rounded-md bg-muted/40">
              <div className="flex items-center gap-2">
                <Code2 className="w-4 h-4 text-muted-foreground" />
                <div>
                  <p className="text-sm font-medium font-mono">{org.name}</p>
                  <p className="text-xs text-muted-foreground">{org.publicRepos} repos, {org.members} members</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {org.verified && <CheckCircle2 className="w-3 h-3 text-blue-400" />}
                <EvidenceLink url={org.url} label="View" />
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Flagged Repositories</CardTitle></CardHeader>
        <CardContent className="space-y-2">
          {(d.flaggedRepos || []).map((repo: any, i: number) => (
            <div key={i} className="p-2 rounded-md bg-muted/40 space-y-1">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <SeverityDot severity={repo.severity} />
                  <span className="text-sm font-mono">{repo.name}</span>
                </div>
                <EvidenceLink url={repo.evidenceUrl} />
              </div>
              <p className="text-xs text-muted-foreground">{repo.issue}</p>
            </div>
          ))}
        </CardContent>
      </Card>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">CI/CD Artifacts</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(d.cicdArtifacts || []).map((a: any, i: number) => (
              <div key={i} className="p-2 rounded-md bg-muted/40 space-y-1">
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className="text-xs no-default-hover-elevate no-default-active-elevate">{a.type}</Badge>
                  <span className="text-sm font-mono">{a.repo}</span>
                </div>
                <div className="flex gap-1 flex-wrap">
                  {(a.badges || []).map((b: string, j: number) => (
                    <Badge key={j} variant="outline" className="text-xs bg-green-600/15 text-green-400 border-0 no-default-hover-elevate no-default-active-elevate">{b}</Badge>
                  ))}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Public Packages</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(d.publicPackages || []).map((p: any, i: number) => (
              <div key={i} className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/40">
                <div>
                  <p className="text-sm font-mono font-medium">{p.name}</p>
                  <p className="text-xs text-muted-foreground">{p.registry} v{p.version} ({p.downloads})</p>
                </div>
                <EvidenceLink url={p.url} label="Registry" />
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
