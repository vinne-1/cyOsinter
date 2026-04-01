import React from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { ReconModule } from "@shared/schema";

interface DASTData {
  testsRun?: number;
  testsPassed?: number;
  duration?: number;
  findings?: Array<{
    title: string;
    severity: string;
    category: string;
    affectedAsset: string;
    remediation: string;
  }>;
}

const SEVERITY_BADGE: Record<string, "destructive" | "default" | "secondary" | "outline"> = {
  critical: "destructive",
  high: "destructive",
  medium: "default",
  low: "secondary",
  info: "outline",
};

export const DASTPanel: React.FC<{ mod: ReconModule }> = ({ mod }) => {
  const data = (mod.data ?? {}) as unknown as DASTData;
  const findings = data.findings ?? [];
  const testsRun = data.testsRun ?? 0;
  const testsPassed = data.testsPassed ?? 0;
  const duration = data.duration ?? 0;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold">{testsRun}</div>
            <div className="text-xs text-muted-foreground">Tests Run</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold text-green-500">{testsPassed}</div>
            <div className="text-xs text-muted-foreground">Passed</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold text-red-500">{findings.length}</div>
            <div className="text-xs text-muted-foreground">Issues Found</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold">{(duration / 1000).toFixed(1)}s</div>
            <div className="text-xs text-muted-foreground">Duration</div>
          </CardContent>
        </Card>
      </div>

      {findings.length === 0 ? (
        <Card>
          <CardContent className="py-8 text-center text-muted-foreground">
            No active security issues detected by DAST-Lite.
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {findings.map((f, i) => (
            <Card key={i}>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm">{f.title}</CardTitle>
                  <Badge variant={SEVERITY_BADGE[f.severity] ?? "outline"}>{f.severity}</Badge>
                </div>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex gap-2">
                  <Badge variant="secondary" className="text-xs">{f.category}</Badge>
                  <span className="text-xs text-muted-foreground">{f.affectedAsset}</span>
                </div>
                {f.remediation && (
                  <p className="text-xs text-muted-foreground"><span className="font-medium">Fix: </span>{f.remediation}</p>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
};
