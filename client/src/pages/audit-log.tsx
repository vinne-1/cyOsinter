import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ClipboardList, Filter } from "lucide-react";

interface AuditLogEntry {
  id: string;
  timestamp: string;
  userId: string;
  userName: string;
  action: string;
  resource: string;
  ipAddress: string;
  details?: string;
}

const actionColors: Record<string, string> = {
  login: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300",
  logout: "bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300",
  scan_triggered: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300",
  scan_completed: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300",
  finding_updated: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300",
  finding_created: "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300",
  user_created: "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-300",
  api_key_created: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300",
  api_key_revoked: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300",
  settings_updated: "bg-indigo-100 text-indigo-800 dark:bg-indigo-900 dark:text-indigo-300",
};

const filterActions = [
  "all",
  "login",
  "logout",
  "scan_triggered",
  "scan_completed",
  "finding_updated",
  "api_key_created",
  "settings_updated",
];

export default function AuditLog() {
  const [activeFilter, setActiveFilter] = useState("all");

  const { data: logs = [], isLoading, error } = useQuery<AuditLogEntry[]>({
    queryKey: ["/api/audit-logs", { limit: "100" }],
  });

  const filtered = activeFilter === "all"
    ? logs
    : logs.filter((l) => l.action === activeFilter);

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (error) {
    const msg = error instanceof Error ? error.message : "";
    const isAccessDenied = msg.toLowerCase().includes("insufficient") || msg.toLowerCase().includes("forbidden");
    return (
      <div className="p-6">
        <div className="flex items-center gap-3 mb-6">
          <ClipboardList className="w-6 h-6 text-primary" />
          <h1 className="text-2xl font-bold">Audit Log</h1>
        </div>
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-16">
            <ClipboardList className="w-12 h-12 text-muted-foreground mb-4" />
            <p className="text-muted-foreground">
              {isAccessDenied
                ? "You don't have permission to view audit logs. Admin access required."
                : "Failed to load audit logs."}
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ClipboardList className="w-6 h-6 text-primary" />
          <h1 className="text-2xl font-bold">Audit Log</h1>
        </div>
        <Badge variant="outline">{logs.length} entries</Badge>
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        <Filter className="w-4 h-4 text-muted-foreground" />
        {filterActions.map((action) => (
          <Button
            key={action}
            variant={activeFilter === action ? "default" : "outline"}
            size="sm"
            onClick={() => setActiveFilter(action)}
          >
            {action === "all" ? "All" : action.replace(/_/g, " ")}
          </Button>
        ))}
      </div>

      {filtered.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-16">
            <ClipboardList className="w-12 h-12 text-muted-foreground mb-4" />
            <p className="text-muted-foreground">No audit log entries found</p>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>Activity Log</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Timestamp</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Resource</TableHead>
                  <TableHead>IP Address</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((entry) => (
                  <TableRow key={entry.id}>
                    <TableCell className="text-sm text-muted-foreground whitespace-nowrap">
                      {new Date(entry.timestamp).toLocaleString()}
                    </TableCell>
                    <TableCell className="font-medium">{entry.userName}</TableCell>
                    <TableCell>
                      <Badge
                        className={actionColors[entry.action] || "bg-gray-100 text-gray-800"}
                        variant="secondary"
                      >
                        {entry.action.replace(/_/g, " ")}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm">{entry.resource}</TableCell>
                    <TableCell className="text-sm font-mono text-muted-foreground">
                      {entry.ipAddress}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
