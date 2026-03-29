import { Globe, ChevronDown, Plus, Clock, Eraser, Trash2 } from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
} from "@/components/ui/dropdown-menu";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useDomain } from "@/lib/domain-context";
import { Badge } from "@/components/ui/badge";
import { useMutation } from "@tanstack/react-query";
import { apiRequest, apiRequestNoParse, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { Workspace } from "@shared/schema";

function clearWorkspaceDataInCache(workspaceId: string) {
  queryClient.setQueryData([`/api/workspaces/${workspaceId}/assets`], []);
  queryClient.setQueryData([`/api/workspaces/${workspaceId}/scans`], []);
  queryClient.setQueryData([`/api/workspaces/${workspaceId}/findings`], []);
  queryClient.setQueryData([`/api/workspaces/${workspaceId}/reports`], []);
  queryClient.setQueryData([`/api/workspaces/${workspaceId}/recon-modules`], []);
}

export function DomainSelector() {
  const { workspaces, selectedWorkspace, setSelectedWorkspace, isLoading } = useDomain();
  const [createOpen, setCreateOpen] = useState(false);
  const [purgeDialogOpen, setPurgeDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [actionTargetWorkspace, setActionTargetWorkspace] = useState<Workspace | null>(null);
  const [newDomain, setNewDomain] = useState("");
  const [newDescription, setNewDescription] = useState("");
  const { toast } = useToast();

  const workspaceForPurgeOrDelete = actionTargetWorkspace ?? selectedWorkspace;

  const createMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/workspaces", {
        name: newDomain,
        description: newDescription || undefined,
      });
      return res.json() as Promise<Workspace>;
    },
    onSuccess: (ws) => {
      queryClient.invalidateQueries({ queryKey: ["/api/workspaces"] });
      setSelectedWorkspace(ws);
      setCreateOpen(false);
      setNewDomain("");
      setNewDescription("");
      toast({ title: "Workspace created", description: `Workspace for ${ws.name} is ready.` });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to create workspace", description: error.message, variant: "destructive" });
    },
  });

  const purgeMutation = useMutation({
    mutationFn: async (workspaceId: string) => {
      await apiRequestNoParse("POST", `/api/workspaces/${workspaceId}/purge`, {});
      return workspaceId;
    },
    onSuccess: (_, workspaceId) => {
      clearWorkspaceDataInCache(workspaceId);
      setPurgeDialogOpen(false);
      setActionTargetWorkspace(null);
      toast({ title: "Workspace data purged", description: "All assets, scans, findings, reports, and intel for this workspace have been removed." });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to purge workspace", description: error.message, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (workspaceId: string) => {
      await apiRequest("DELETE", `/api/workspaces/${workspaceId}`);
    },
    onSuccess: (_, deletedId) => {
      if (selectedWorkspace?.id === deletedId) {
        const remaining = workspaces.filter((w) => w.id !== deletedId);
        setSelectedWorkspace(remaining[0] ?? null);
      }
      queryClient.invalidateQueries({ queryKey: ["/api/workspaces"] });
      setDeleteDialogOpen(false);
      setActionTargetWorkspace(null);
      toast({ title: "Workspace deleted", description: "The workspace and all its data have been removed." });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to delete workspace", description: error.message, variant: "destructive" });
    },
  });

  if (isLoading) {
    return null;
  }

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="sm" className="gap-2" data-testid="button-domain-selector">
            <Globe className="w-3.5 h-3.5" />
            <span className="max-w-[160px] truncate font-mono text-xs">
              {selectedWorkspace?.name || "Select workspace"}
            </span>
            <ChevronDown className="w-3 h-3 opacity-50" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-64">
          <DropdownMenuLabel className="text-xs text-muted-foreground">Workspaces</DropdownMenuLabel>
          <DropdownMenuSeparator />
          {workspaces.map((ws) => (
            <DropdownMenuSub key={ws.id}>
              <DropdownMenuSubTrigger
                className="gap-2 cursor-pointer"
                data-testid={`workspace-option-${ws.name}`}
                onSelect={(e) => {
                  e.preventDefault();
                  setSelectedWorkspace(ws);
                }}
              >
                <Globe className="w-3.5 h-3.5 flex-shrink-0" />
                <div className="flex-1 min-w-0 text-left">
                  <div className="font-mono text-xs truncate">{ws.name}</div>
                  {ws.description && (
                    <div className="text-xs text-muted-foreground truncate">{ws.description}</div>
                  )}
                </div>
                <div className="flex items-center gap-1.5 flex-shrink-0">
                  {ws.createdAt && (
                    <span className="text-xs text-muted-foreground flex items-center gap-0.5">
                      <Clock className="w-3 h-3" />
                      {new Date(ws.createdAt).toLocaleDateString(undefined, { month: "short", day: "numeric" })}
                    </span>
                  )}
                  {ws.id === selectedWorkspace?.id && (
                    <Badge variant="outline" className="text-xs py-0 px-1.5 no-default-hover-elevate no-default-active-elevate">
                      Active
                    </Badge>
                  )}
                </div>
              </DropdownMenuSubTrigger>
              <DropdownMenuSubContent>
                <DropdownMenuItem
                  className="gap-2"
                  onSelect={(e) => {
                    e.preventDefault();
                    setSelectedWorkspace(ws);
                  }}
                >
                  <Globe className="w-3.5 h-3.5" />
                  Use as active workspace
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  className="gap-2 text-amber-600 focus:text-amber-600 dark:text-amber-400"
                  data-testid={`workspace-purge-${ws.name}`}
                  onSelect={(e) => {
                    e.preventDefault();
                    setActionTargetWorkspace(ws);
                    setPurgeDialogOpen(true);
                  }}
                >
                  <Eraser className="w-3.5 h-3.5" />
                  Purge workspace data
                </DropdownMenuItem>
                <DropdownMenuItem
                  className="gap-2 text-destructive focus:text-destructive"
                  data-testid={`workspace-delete-${ws.name}`}
                  onSelect={(e) => {
                    e.preventDefault();
                    setActionTargetWorkspace(ws);
                    setDeleteDialogOpen(true);
                  }}
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  Delete workspace
                </DropdownMenuItem>
              </DropdownMenuSubContent>
            </DropdownMenuSub>
          ))}
          <DropdownMenuSeparator />
          {selectedWorkspace && (
            <>
              <DropdownMenuLabel className="text-xs text-muted-foreground">Current workspace actions</DropdownMenuLabel>
              <DropdownMenuItem
                onSelect={(e) => {
                  e.preventDefault();
                  setActionTargetWorkspace(selectedWorkspace);
                  setPurgeDialogOpen(true);
                }}
                className="gap-2 cursor-pointer text-amber-600 focus:text-amber-600 dark:text-amber-400"
                data-testid="button-purge-workspace"
              >
                <Eraser className="w-3.5 h-3.5" />
                <span className="text-xs">Purge workspace data</span>
              </DropdownMenuItem>
              <DropdownMenuItem
                onSelect={(e) => {
                  e.preventDefault();
                  setActionTargetWorkspace(selectedWorkspace);
                  setDeleteDialogOpen(true);
                }}
                className="gap-2 cursor-pointer text-destructive focus:text-destructive"
                data-testid="button-delete-workspace"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span className="text-xs">Delete workspace</span>
              </DropdownMenuItem>
              <DropdownMenuSeparator />
            </>
          )}
          <DropdownMenuItem
            onClick={() => setCreateOpen(true)}
            className="gap-2 cursor-pointer"
            data-testid="button-create-workspace"
          >
            <Plus className="w-3.5 h-3.5" />
            <span className="text-xs">New Workspace</span>
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Create Workspace</DialogTitle>
            <DialogDescription>
              Create a new workspace for a target domain. All scans, findings, and reports will be organized here.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 pt-2">
            <div className="space-y-2">
              <label className="text-sm font-medium">Domain</label>
              <Input
                placeholder="example.com"
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
                data-testid="input-workspace-domain"
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Description (optional)</label>
              <Textarea
                placeholder="Brief description of this workspace..."
                value={newDescription}
                onChange={(e) => setNewDescription(e.target.value)}
                className="resize-none"
                data-testid="input-workspace-description"
              />
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setCreateOpen(false)} data-testid="button-cancel-workspace">
                Cancel
              </Button>
              <Button
                onClick={() => createMutation.mutate()}
                disabled={!newDomain.trim() || createMutation.isPending}
                data-testid="button-confirm-create-workspace"
              >
                {createMutation.isPending ? "Creating..." : "Create Workspace"}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      <AlertDialog open={purgeDialogOpen} onOpenChange={setPurgeDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Purge workspace data</AlertDialogTitle>
            <AlertDialogDescription>
              Remove all assets, scans, findings, reports, and intelligence data for <strong>{workspaceForPurgeOrDelete?.name}</strong>. The workspace itself will remain so you can run new scans. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault();
                if (workspaceForPurgeOrDelete && !purgeMutation.isPending) purgeMutation.mutate(workspaceForPurgeOrDelete.id);
              }}
              disabled={purgeMutation.isPending}
              className="bg-amber-600 hover:bg-amber-700 focus:ring-amber-600"
            >
              {purgeMutation.isPending ? "Purging..." : "Purge data"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete workspace</AlertDialogTitle>
            <AlertDialogDescription>
              Permanently delete the workspace <strong>{workspaceForPurgeOrDelete?.name}</strong> and all its data (assets, scans, findings, reports). This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault();
                if (workspaceForPurgeOrDelete && !deleteMutation.isPending) deleteMutation.mutate(workspaceForPurgeOrDelete.id);
              }}
              disabled={deleteMutation.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteMutation.isPending ? "Deleting..." : "Delete workspace"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
