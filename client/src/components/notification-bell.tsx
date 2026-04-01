import { useQuery, useMutation } from "@tanstack/react-query";
import { Bell } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { Badge } from "@/components/ui/badge";
import { useDomain } from "@/lib/domain-context";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { SeverityBadge } from "@/components/severity-badge";
import type { Alert } from "@shared/schema";
import { useWebSocket } from "@/hooks/use-websocket";

export function NotificationBell() {
  const { selectedWorkspaceId } = useDomain();

  // Connect WebSocket for real-time updates
  useWebSocket(selectedWorkspaceId);

  const { data: unreadData } = useQuery<{ count: number }>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/alerts/unread-count`],
    enabled: !!selectedWorkspaceId,
    refetchInterval: 30000,
  });

  const { data: alerts = [] } = useQuery<Alert[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/alerts`, { limit: "10" }],
    enabled: !!selectedWorkspaceId,
  });

  const markAllRead = useMutation({
    mutationFn: () =>
      apiRequest("POST", `/api/workspaces/${selectedWorkspaceId}/alerts/mark-all-read`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/alerts`] });
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/alerts/unread-count`] });
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

  const unreadCount = unreadData?.count ?? 0;

  if (!selectedWorkspaceId) return null;

  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="ghost" size="icon" className="relative" data-testid="button-notification-bell">
          <Bell className="w-4 h-4" />
          {unreadCount > 0 && (
            <span className="absolute -top-0.5 -right-0.5 flex items-center justify-center w-4 h-4 text-[10px] font-bold text-white bg-red-500 rounded-full">
              {unreadCount > 9 ? "9+" : unreadCount}
            </span>
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-80 p-0" align="end">
        <div className="flex items-center justify-between p-3 border-b">
          <p className="text-sm font-medium">Notifications</p>
          {unreadCount > 0 && (
            <Button
              variant="ghost"
              size="sm"
              className="text-xs h-6"
              onClick={() => markAllRead.mutate()}
              disabled={markAllRead.isPending}
            >
              Mark all read
            </Button>
          )}
        </div>
        <div className="max-h-80 overflow-y-auto">
          {alerts.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-8">No notifications yet</p>
          ) : (
            alerts.map((alert) => (
              <div
                key={alert.id}
                className={`flex items-start gap-2 p-3 border-b last:border-b-0 cursor-pointer hover:bg-muted/50 transition-colors ${
                  !alert.read ? "bg-primary/5" : ""
                }`}
                onClick={() => {
                  if (!alert.read) markRead.mutate(alert.id);
                }}
              >
                <div className="flex-1 min-w-0 space-y-1">
                  <div className="flex items-center gap-1.5">
                    {!alert.read && <div className="w-1.5 h-1.5 rounded-full bg-primary flex-shrink-0" />}
                    <p className="text-xs font-medium truncate">{alert.title}</p>
                  </div>
                  <p className="text-[11px] text-muted-foreground line-clamp-2">{alert.message}</p>
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={alert.severity} />
                    <span className="text-[10px] text-muted-foreground">
                      {alert.createdAt ? new Date(alert.createdAt).toLocaleString() : ""}
                    </span>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
        {alerts.length > 0 && (
          <div className="p-2 border-t text-center">
            <a href="/alerts" className="text-xs text-primary hover:underline">
              View all notifications
            </a>
          </div>
        )}
      </PopoverContent>
    </Popover>
  );
}
