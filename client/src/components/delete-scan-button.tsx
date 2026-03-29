import { useState } from "react";
import { Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
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
import { useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { Scan } from "@shared/schema";

interface DeleteScanButtonProps {
  scan: Scan;
  workspaceId: string;
  variant?: "ghost" | "outline";
  size?: "sm" | "icon" | "default";
  className?: string;
}

export function DeleteScanButton({ scan, workspaceId, variant = "ghost", size = "icon", className }: DeleteScanButtonProps) {
  const [open, setOpen] = useState(false);
  const { toast } = useToast();

  const deleteMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("DELETE", `/api/scans/${scan.id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceId}/scans`] });
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceId}/findings`] });
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceId}/recon-modules`] });
      setOpen(false);
      toast({ title: "Scan deleted", description: `Scan for ${scan.target} (${scan.type}) has been removed.` });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to delete scan", description: error.message, variant: "destructive" });
    },
  });

  return (
    <>
      <Button
        variant={variant}
        size={size}
        className={className}
        onClick={() => setOpen(true)}
        data-testid={`button-delete-scan-${scan.id}`}
        aria-label="Delete scan"
      >
        <Trash2 className="w-4 h-4 text-destructive" />
      </Button>
      <AlertDialog open={open} onOpenChange={setOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete scan</AlertDialogTitle>
            <AlertDialogDescription>
              Remove this scan record? Target <strong>{scan.target}</strong> ({scan.type}, {scan.findingsCount ?? 0} findings). The scan record will be deleted; findings already in the workspace remain. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault();
                if (!deleteMutation.isPending) deleteMutation.mutate();
              }}
              disabled={deleteMutation.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteMutation.isPending ? "Deleting..." : "Delete scan"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
