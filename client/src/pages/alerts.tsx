import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Bell, CheckCheck, Trash2, AlertCircle, CheckCircle2, Info, XCircle } from "lucide-react";
import { SeverityBadge } from "@/components/severity-badge";
import { useDomain } from "@/lib/domain-context";
import { apiRequest, queryClient } from "@/lib/queryClient";
import type { Alert } from "@shared/schema";
import { useToast } from "@/hooks/use-toast";

const typeIcons: Record<string, typeof AlertCircle> = {
  scan_completed: CheckCircle2,
  scan_failed: XCircle,
  new_critical_finding: AlertCircle,
  new_high_finding: AlertCircle,
  scheduled_scan_triggered: Info,
};

const typeLabels: Record<string, string> = {
  scan_completed: "Scan Complete",
  scan_failed: "Scan Failed",
  new_critical_finding: "Critical Finding",
  new_high_finding: "High Finding",
  scheduled_scan_triggered: "Scheduled Scan",
};

export default function Alerts() {
  const { selectedWorkspaceId } = useDomain();
  const { toast } = useToast();

  const { data: alerts = [], isLoading } = useQuery<Alert[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/alerts`],
    enabled: !!selectedWorkspaceId,
  });

  const markAllRead = useMutation({
    mutationFn: () =>
      apiRequest("POST", `/api/workspaces/${selectedWorkspaceId}/alerts/mark-all-read`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/alerts`] });
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/alerts/unread-count`] });
      toast({ title: "All notifications marked as read" });
    },
  });

  const markRead = useMutation({
    mutationFn: (id: string) =>
      apiRequest("PATCH", `/api/alerts/${id}/read`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/alerts`] });
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/alerts/unread-count`] });
    },
  });

  const deleteAlert = useMutation({
    mutationFn: (id: string) =>
      apiRequest("DELETE", `/api/alerts/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/alerts`] });
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/alerts/unread-count`] });
    },
  });

  const unreadCount = alerts.filter((a) => !a.read).length;

  if (isLoading) {
    return (
      <div className="space-y-6 p-6">
        <Skeleton className="h-8 w-64" />
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-20" />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight" data-testid="text-alerts-title">
            Notifications
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            {unreadCount > 0 ? `${unreadCount} unread notification${unreadCount > 1 ? "s" : ""}` : "All caught up"}
          </p>
        </div>
        {unreadCount > 0 && (
          <Button
            variant="outline"
            size="sm"
            onClick={() => markAllRead.mutate()}
            disabled={markAllRead.isPending}
          >
            <CheckCheck className="w-4 h-4 mr-2" />
            Mark all read
          </Button>
        )}
      </div>

      {alerts.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <Bell className="w-10 h-10 text-muted-foreground/40 mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">No notifications yet</p>
            <p className="text-xs text-muted-foreground mt-1">
              Alerts will appear here when scans complete, fail, or find critical issues
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {alerts.map((alert) => {
            const Icon = typeIcons[alert.type] ?? Info;
            return (
              <Card
                key={alert.id}
                className={`transition-colors ${!alert.read ? "border-primary/30 bg-primary/5" : ""}`}
                data-testid={`card-alert-${alert.id}`}
              >
                <CardContent className="p-4">
                  <div className="flex items-start gap-3">
                    <div className={`flex items-center justify-center w-8 h-8 rounded-md flex-shrink-0 ${
                      alert.severity === "critical" ? "bg-red-500/10 text-red-500" :
                      alert.severity === "high" ? "bg-orange-500/10 text-orange-500" :
                      alert.severity === "info" ? "bg-blue-500/10 text-blue-500" :
                      "bg-muted text-muted-foreground"
                    }`}>
                      <Icon className="w-4 h-4" />
                    </div>
                    <div className="flex-1 min-w-0 space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        {!alert.read && <div className="w-2 h-2 rounded-full bg-primary flex-shrink-0" />}
                        <p className="text-sm font-medium">{alert.title}</p>
                        <SeverityBadge severity={alert.severity} />
                        <Badge variant="outline" className="text-[10px] capitalize">
                          {typeLabels[alert.type] ?? alert.type.replace(/_/g, " ")}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground">{alert.message}</p>
                      <p className="text-[10px] text-muted-foreground/60">
                        {alert.createdAt ? new Date(alert.createdAt).toLocaleString() : ""}
                      </p>
                    </div>
                    <div className="flex items-center gap-1 flex-shrink-0">
                      {!alert.read && (
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7"
                          onClick={() => markRead.mutate(alert.id)}
                          title="Mark as read"
                        >
                          <CheckCheck className="w-3.5 h-3.5" />
                        </Button>
                      )}
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7 text-muted-foreground hover:text-destructive"
                        onClick={() => deleteAlert.mutate(alert.id)}
                        title="Delete"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
