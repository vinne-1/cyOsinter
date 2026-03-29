import { useState, useCallback } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Upload,
  FileText,
  Trash2,
  Sparkles,
  Loader2,
  Inbox,
} from "lucide-react";
import type { UploadedScan } from "@shared/schema";
import { apiRequest, queryClient, buildUrl } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

export default function Imports() {
  const { selectedWorkspaceId } = useDomain();
  const { toast } = useToast();
  const [dragActive, setDragActive] = useState(false);
  const [fileType, setFileType] = useState<"nmap" | "nikto" | "generic">("nmap");

  const { data: scans = [], isLoading } = useQuery<UploadedScan[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/imports`],
    enabled: !!selectedWorkspaceId,
  });

  const uploadMutation = useMutation({
    mutationFn: async (file: File) => {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("fileType", fileType);
      const url = buildUrl(`/api/workspaces/${selectedWorkspaceId}/imports`);
      const res = await fetch(url, {
        method: "POST",
        body: formData,
        credentials: "include",
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || res.statusText);
      }
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/imports`] });
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/findings`] });
      toast({ title: "File uploaded", description: "Scan results imported successfully" });
    },
    onError: (err: Error) => {
      toast({ title: "Upload failed", description: err.message, variant: "destructive" });
    },
  });

  const consolidateMutation = useMutation({
    mutationFn: async (scanId: string) => {
      const res = await apiRequest("POST", `/api/workspaces/${selectedWorkspaceId}/imports/${scanId}/consolidate`);
      return res.json();
    },
    onSuccess: (data: { newCount: number; mergedCount: number }) => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/imports`] });
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/findings`] });
      toast({
        title: "Consolidation complete",
        description: `${data.newCount} new findings, ${data.mergedCount} merged`,
      });
    },
    onError: (err: Error) => {
      toast({ title: "Consolidation failed", description: err.message, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (scanId: string) => {
      await apiRequest("DELETE", `/api/workspaces/${selectedWorkspaceId}/imports/${scanId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/imports`] });
      toast({ title: "Import deleted" });
    },
    onError: (err: Error) => {
      toast({ title: "Delete failed", description: err.message, variant: "destructive" });
    },
  });

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragActive(false);
      const file = e.dataTransfer.files[0];
      if (file && selectedWorkspaceId) {
        uploadMutation.mutate(file);
      }
    },
    [selectedWorkspaceId, uploadMutation]
  );

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
  }, []);

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file && selectedWorkspaceId) {
      uploadMutation.mutate(file);
    }
    e.target.value = "";
  };

  if (!selectedWorkspaceId) {
    return (
      <div className="p-6">
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-16">
            <Inbox className="w-12 h-12 text-muted-foreground mb-4" />
            <p className="text-muted-foreground">Select a workspace to import scan results</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Import Scan Results</h1>
        <p className="text-muted-foreground text-sm mt-1">
          Upload nmap, nikto, or generic scan output. Use AI consolidation to merge into findings.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Upload file</CardTitle>
          <div className="flex items-center gap-2">
            <Select value={fileType} onValueChange={(v) => setFileType(v as "nmap" | "nikto" | "generic")}>
              <SelectTrigger className="w-32">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="nmap">Nmap</SelectItem>
                <SelectItem value="nikto">Nikto</SelectItem>
                <SelectItem value="generic">Generic</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent>
          <div
            className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
              dragActive ? "border-primary bg-primary/5" : "border-muted-foreground/25"
            }`}
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
          >
            <input
              type="file"
              id="file-upload"
              className="hidden"
              accept=".txt,.xml,.json,.nmap,.gnmap"
              onChange={handleFileSelect}
            />
            <Upload className="w-10 h-10 mx-auto text-muted-foreground mb-3" />
            <p className="text-sm text-muted-foreground mb-2">
              Drag and drop a file here, or click to browse
            </p>
            <p className="text-xs text-muted-foreground mb-4">
              Accepts .txt, .xml, .json (nmap -oN, -oX, etc.). Max 10MB.
            </p>
            <Button
              variant="outline"
              onClick={() => document.getElementById("file-upload")?.click()}
              disabled={uploadMutation.isPending}
            >
              {uploadMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Upload className="w-4 h-4" />}
              {uploadMutation.isPending ? "Uploading..." : "Choose file"}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Uploaded scans</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <Skeleton className="h-24 w-full" />
          ) : scans.length === 0 ? (
            <p className="text-sm text-muted-foreground py-8 text-center">No uploads yet</p>
          ) : (
            <div className="space-y-2">
              {scans.map((scan) => (
                <div
                  key={scan.id}
                  className="flex items-center justify-between gap-4 p-3 rounded-lg border bg-card"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <FileText className="w-5 h-5 text-muted-foreground flex-shrink-0" />
                    <div className="min-w-0">
                      <p className="font-medium truncate">{scan.filename}</p>
                      <div className="flex items-center gap-2 text-xs text-muted-foreground">
                        <Badge variant="outline" className="text-[10px]">
                          {scan.fileType}
                        </Badge>
                        <span>
                          {scan.createdAt ? new Date(scan.createdAt).toLocaleString() : ""}
                        </span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => consolidateMutation.mutate(scan.id)}
                      disabled={consolidateMutation.isPending}
                    >
                      {consolidateMutation.isPending && consolidateMutation.variables === scan.id ? (
                        <Loader2 className="w-4 h-4 animate-spin" />
                      ) : (
                        <Sparkles className="w-4 h-4" />
                      )}
                      Consolidate
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => deleteMutation.mutate(scan.id)}
                      disabled={deleteMutation.isPending}
                    >
                      <Trash2 className="w-4 h-4 text-destructive" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
