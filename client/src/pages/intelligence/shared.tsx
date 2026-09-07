import React from "react";
import { Badge } from "@/components/ui/badge";
import {
  CheckCircle2,
  XCircle,
  MinusCircle,
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
  // "N/A" is not a failing grade. It means the check could not be made — DKIM,
  // for instance, cannot be verified without knowing the selector — and every
  // non-A/B/C value used to fall through to red. Telling a domain it failed a
  // control nobody was able to test is the same false positive the scanner
  // works to avoid, so it renders neutral.
  const color = grade.startsWith("A") ? "bg-green-600/15 text-green-400" :
    grade.startsWith("B") ? "bg-blue-600/15 text-blue-400" :
    grade.startsWith("C") ? "bg-yellow-600/15 text-yellow-400" :
    /^(N\/A|n\/a|unknown|-)$/.test(grade) ? "bg-muted text-muted-foreground" :
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

/**
 * Pass / fail / not-determined.
 *
 * The third state is the point: a boolean can only say "good" or "bad", so an
 * undetermined check (DKIM with no known selector, a mail control on a domain
 * with no MX) was drawn with the same red cross as a genuine failure.
 */
export function StatusIcon({ pass, unknown = false }: { pass: boolean; unknown?: boolean }) {
  if (unknown) return <MinusCircle className="w-4 h-4 text-muted-foreground flex-shrink-0" />;
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
          {/*
            Tokens, not opacity. `text-muted-foreground/50` measured 2.65:1
            against the panel background — an opacity modifier stacked on
            already-tinted text, which is the documented way contrast regresses
            here. At 10px this is small text, so it needs the full 4.5:1.
          */}
          {freshness && <p className={`text-[10px] ${freshness.fresh ? "text-muted-foreground" : "text-yellow-600 dark:text-yellow-500"}`}>{freshness.text}</p>}
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
