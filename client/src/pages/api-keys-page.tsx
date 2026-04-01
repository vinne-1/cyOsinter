import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Key, Plus, Trash2, Copy, CheckCircle2 } from "lucide-react";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  scope: string;
  createdAt: string;
  lastUsed?: string;
  status: string;
}

const scopeColors: Record<string, string> = {
  read: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300",
  scan: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300",
  full: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300",
};

function CreateKeyDialog() {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [scope, setScope] = useState("read");
  const [expiry, setExpiry] = useState("");
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const { toast } = useToast();

  const create = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/api-keys", {
        name,
        scope,
        expiresAt: expiry || undefined,
      });
      return res.json();
    },
    onSuccess: (data: { key: string }) => {
      queryClient.invalidateQueries({ queryKey: ["/api/api-keys"] });
      setCreatedKey(data.key);
    },
    onError: (err: Error) => {
      toast({ title: "Failed to create API key", description: err.message, variant: "destructive" });
    },
  });

  function handleClose(isOpen: boolean) {
    if (!isOpen) {
      setName(""); setScope("read"); setExpiry(""); setCreatedKey(null); setCopied(false);
    }
    setOpen(isOpen);
  }

  async function copyKey() {
    if (createdKey) {
      await navigator.clipboard.writeText(createdKey);
      setCopied(true);
      toast({ title: "API key copied to clipboard" });
    }
  }

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogTrigger asChild>
        <Button><Plus className="w-4 h-4 mr-2" />Create API Key</Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader><DialogTitle>{createdKey ? "API Key Created" : "Create API Key"}</DialogTitle></DialogHeader>
        {createdKey ? (
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Copy this key now. It will not be shown again.
            </p>
            <div className="flex items-center gap-2">
              <Input value={createdKey} readOnly className="font-mono text-sm" />
              <Button size="sm" variant="outline" onClick={copyKey}>
                {copied ? <CheckCircle2 className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
              </Button>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Name</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="My API key" />
            </div>
            <div className="space-y-2">
              <Label>Scope</Label>
              <Select value={scope} onValueChange={setScope}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="read">Read</SelectItem>
                  <SelectItem value="scan">Scan</SelectItem>
                  <SelectItem value="full">Full</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Expiry Date (optional)</Label>
              <Input type="date" value={expiry} onChange={(e) => setExpiry(e.target.value)} />
            </div>
            <Button onClick={() => create.mutate()} disabled={!name || create.isPending} className="w-full">
              {create.isPending ? "Creating..." : "Create Key"}
            </Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

export default function ApiKeysPage() {
  const { toast } = useToast();

  const { data: keys = [], isLoading } = useQuery<ApiKey[]>({
    queryKey: ["/api/api-keys"],
  });

  const revoke = useMutation({
    mutationFn: (id: string) => apiRequest("DELETE", `/api/api-keys/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/api-keys"] });
      toast({ title: "API key revoked" });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to revoke key", description: err.message, variant: "destructive" });
    },
  });

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Key className="w-6 h-6 text-primary" />
          <h1 className="text-2xl font-bold">API Keys</h1>
        </div>
        <CreateKeyDialog />
      </div>

      {keys.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-16">
            <Key className="w-12 h-12 text-muted-foreground mb-4" />
            <p className="text-muted-foreground">No API keys created yet</p>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader><CardTitle>Your API Keys</CardTitle></CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Prefix</TableHead>
                  <TableHead>Scope</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Last Used</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {keys.map((k) => (
                  <TableRow key={k.id}>
                    <TableCell className="font-medium">{k.name}</TableCell>
                    <TableCell className="font-mono text-sm">{k.prefix}...</TableCell>
                    <TableCell>
                      <Badge className={scopeColors[k.scope] || ""} variant="secondary">
                        {k.scope}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {new Date(k.createdAt).toLocaleDateString()}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {k.lastUsed ? new Date(k.lastUsed).toLocaleDateString() : "Never"}
                    </TableCell>
                    <TableCell>
                      <Badge variant={k.status === "active" ? "default" : "secondary"}>
                        {k.status}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Button
                        size="sm"
                        variant="destructive"
                        onClick={() => revoke.mutate(k.id)}
                        disabled={revoke.isPending}
                      >
                        <Trash2 className="w-3 h-3 mr-1" />Revoke
                      </Button>
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
