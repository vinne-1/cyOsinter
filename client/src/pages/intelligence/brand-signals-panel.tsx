import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Megaphone, CheckCircle2 } from "lucide-react";
import type { ReconModule } from "@shared/schema";
import { ModuleHeader, EvidenceLink, StatusIcon } from "./shared";

export function BrandSignalsPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as Record<string, any>;
  return (
    <div className="space-y-4" data-testid="panel-brand-signals">
      <ModuleHeader title="Brand & Public Reputation" icon={Megaphone} confidence={mod.confidence || 0} generatedAt={mod.generatedAt} />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Social Profiles</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(d.socialProfiles || []).map((sp: any, i: number) => (
              <div key={i} className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/40">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium">{sp.platform}</span>
                  {sp.verified && <CheckCircle2 className="w-3 h-3 text-blue-400" />}
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">{sp.followers?.toLocaleString() || sp.repos || sp.subscribers?.toLocaleString()} {sp.repos ? "repos" : sp.subscribers ? "subscribers" : "followers"}</span>
                  <EvidenceLink url={sp.url} />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">App Store Listings</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(d.appStoreListings || []).map((app: any, i: number) => (
              <div key={i} className="p-2 rounded-md bg-muted/40 space-y-1">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-medium">{app.name}</span>
                  <Badge variant="outline" className="text-xs no-default-hover-elevate no-default-active-elevate">{app.platform}</Badge>
                </div>
                <p className="text-xs text-muted-foreground font-mono">{app.bundleId || app.packageName}</p>
                <p className="text-xs text-muted-foreground">Rating: {app.rating}/5 ({app.reviews} reviews)</p>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Public Pages</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(d.publicPages || []).map((p: any, i: number) => (
              <div key={i} className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/40">
                <div className="flex items-center gap-2">
                  <StatusIcon pass={p.operational} />
                  <span className="text-sm">{p.type}</span>
                </div>
                <EvidenceLink url={p.url} label={p.type} />
              </div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">News References</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(d.newsReferences || []).map((n: any, i: number) => (
              <div key={i} className="p-2 rounded-md bg-muted/40 space-y-1">
                <p className="text-sm font-medium">{n.title}</p>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs text-muted-foreground">{n.source} | {n.date}</span>
                  <EvidenceLink url={n.url} />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
