import { Badge } from "@/components/ui/badge";

const severityConfig: Record<string, { className: string; label: string }> = {
  critical: { className: "bg-red-600/15 text-red-400 dark:bg-red-500/15 dark:text-red-400", label: "Critical" },
  high: { className: "bg-orange-600/15 text-orange-500 dark:bg-orange-500/15 dark:text-orange-400", label: "High" },
  medium: { className: "bg-yellow-600/15 text-yellow-600 dark:bg-yellow-500/15 dark:text-yellow-400", label: "Medium" },
  low: { className: "bg-blue-600/15 text-blue-500 dark:bg-blue-500/15 dark:text-blue-400", label: "Low" },
  info: { className: "bg-slate-600/15 text-slate-500 dark:bg-slate-500/15 dark:text-slate-400", label: "Info" },
};

const statusConfig: Record<string, { className: string; label: string }> = {
  open: { className: "bg-red-600/15 text-red-400", label: "Open" },
  in_review: { className: "bg-yellow-600/15 text-yellow-500", label: "In Review" },
  resolved: { className: "bg-green-600/15 text-green-400", label: "Resolved" },
  false_positive: { className: "bg-slate-600/15 text-slate-400", label: "False Positive" },
  accepted_risk: { className: "bg-purple-600/15 text-purple-400", label: "Accepted Risk" },
};

const scanStatusConfig: Record<string, { className: string; label: string }> = {
  pending: { className: "bg-slate-600/15 text-slate-400", label: "Pending" },
  running: { className: "bg-blue-600/15 text-blue-400", label: "In Progress" },
  completed: { className: "bg-green-600/15 text-green-400", label: "Completed" },
  failed: { className: "bg-red-600/15 text-red-400", label: "Failed" },
};

export function SeverityBadge({ severity }: { severity: string }) {
  const config = severityConfig[severity] || severityConfig.info;
  return (
    <Badge variant="outline" className={`${config.className} border-0 no-default-hover-elevate no-default-active-elevate`} data-testid={`badge-severity-${severity}`}>
      {config.label}
    </Badge>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const config = statusConfig[status] || statusConfig.open;
  return (
    <Badge variant="outline" className={`${config.className} border-0 no-default-hover-elevate no-default-active-elevate`} data-testid={`badge-status-${status}`}>
      {config.label}
    </Badge>
  );
}

export function ScanStatusBadge({ status }: { status: string }) {
  const config = scanStatusConfig[status] || scanStatusConfig.pending;
  return (
    <Badge variant="outline" className={`${config.className} border-0 no-default-hover-elevate no-default-active-elevate`} data-testid={`badge-scan-status-${status}`}>
      {config.label}
    </Badge>
  );
}
