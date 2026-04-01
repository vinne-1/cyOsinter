import React from "react";
import { Badge } from "@/components/ui/badge";
import {
  CheckCircle2,
  XCircle,
  ExternalLink,
} from "lucide-react";

export function ConfidenceBadge({ confidence }: { confidence: number }) {
  const color = confidence >= 90 ? "bg-green-600/15 text-green-400" :
    confidence >= 70 ? "bg-yellow-600/15 text-yellow-400" :
    "bg-orange-600/15 text-orange-400";
  return (
    <Badge variant="outline" className={`${color} border-0 no-default-hover-elevate no-default-active-elevate text-xs`} data-testid="badge-confidence">
      {confidence}% confidence
    </Badge>
  );
}

export function GradeBadge({ grade }: { grade: string }) {
  const color = grade.startsWith("A") ? "bg-green-600/15 text-green-400" :
    grade.startsWith("B") ? "bg-blue-600/15 text-blue-400" :
    grade.startsWith("C") ? "bg-yellow-600/15 text-yellow-400" :
    "bg-red-600/15 text-red-400";
  return (
    <Badge variant="outline" className={`${color} border-0 no-default-hover-elevate no-default-active-elevate font-mono`} data-testid="badge-grade">
      {grade}
    </Badge>
  );
}

export function SeverityDot({ severity }: { severity: string }) {
  const color = severity === "critical" ? "bg-red-500" :
    severity === "high" ? "bg-orange-500" :
    severity === "medium" ? "bg-yellow-500" :
    severity === "low" ? "bg-blue-500" : "bg-slate-500";
  return <div className={`w-2 h-2 rounded-full flex-shrink-0 ${color}`} />;
}

export function StatusIcon({ pass }: { pass: boolean }) {
  return pass ?
    <CheckCircle2 className="w-4 h-4 text-green-400 flex-shrink-0" /> :
    <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />;
}

export function ModuleHeader({ title, icon: Icon, confidence, generatedAt }: { title: string; icon: React.ElementType; confidence: number; generatedAt?: string | Date | null }) {
  const freshness = generatedAt ? (() => {
    const ago = Date.now() - new Date(generatedAt).getTime();
    if (ago < 3_600_000) return { text: `${Math.max(1, Math.round(ago / 60_000))}m ago`, fresh: true };
    if (ago < 86_400_000) return { text: `${Math.round(ago / 3_600_000)}h ago`, fresh: true };
    if (ago < 604_800_000) return { text: `${Math.round(ago / 86_400_000)}d ago`, fresh: false };
    return { text: `${Math.round(ago / 604_800_000)}w ago`, fresh: false };
  })() : null;
  return (
    <div className="flex items-center justify-between gap-3 mb-4 flex-wrap">
      <div className="flex items-center gap-3">
        <div className="flex items-center justify-center w-9 h-9 rounded-md bg-primary/10 flex-shrink-0">
          <Icon className="w-5 h-5 text-primary" />
        </div>
        <div>
          <h3 className="text-base font-semibold">{title}</h3>
          {freshness && <p className={`text-[10px] ${freshness.fresh ? "text-muted-foreground/50" : "text-yellow-500/70"}`}>{freshness.text}</p>}
        </div>
      </div>
      <ConfidenceBadge confidence={confidence} />
    </div>
  );
}

export function EvidenceLink({ url, label }: { url?: string; label?: string }) {
  if (!url) return null;
  return (
    <a href={url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-primary hover:underline">
      <ExternalLink className="w-3 h-3" />
      {label || "Evidence"}
    </a>
  );
}
