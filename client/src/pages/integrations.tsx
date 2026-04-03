import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Plug, Shield, CheckCircle2, XCircle, Loader2, Cpu, Search, PowerOff, TicketCheck, Github } from "lucide-react";
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
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

interface IntegrationsStatus {
  abuseipdb: { configured: boolean };
  virustotal: { configured: boolean };
  tavily: { configured: boolean };
  ollama: { configured: boolean; baseUrl: string; model: string; enabled: boolean };
}

const OLLAMA_MODEL_OPTIONS = [
  { value: "smollm2:135m", label: "smollm2:135m (271MB, smallest)" },
  { value: "tinyllama", label: "tinyllama (637MB, default)" },
  { value: "smollm2:360m", label: "smollm2:360m (726MB, better quality)" },
  { value: "custom", label: "Custom" },
] as const;

export default function Integrations() {
  const [abuseipdbKey, setAbuseipdbKey] = useState("");
  const [virustotalKey, setVirustotalKey] = useState("");
  const [tavilyKey, setTavilyKey] = useState("");
  const [showAbuseipdbInput, setShowAbuseipdbInput] = useState(false);
  const [showVirustotalInput, setShowVirustotalInput] = useState(false);
  const [showTavilyInput, setShowTavilyInput] = useState(false);
  const [ollamaBaseUrl, setOllamaBaseUrl] = useState("http://localhost:11434");
  const [ollamaModelSelect, setOllamaModelSelect] = useState<string>("tinyllama");
  const [ollamaModelCustom, setOllamaModelCustom] = useState("");
  const [ollamaEnabled, setOllamaEnabled] = useState(false);
  const [shutdownDialogOpen, setShutdownDialogOpen] = useState(false);
  const [shutdownPending, setShutdownPending] = useState(false);
  // Jira/GitHub ticketing state
  const [jiraBaseUrl, setJiraBaseUrl] = useState("");
  const [jiraEmail, setJiraEmail] = useState("");
  const [jiraToken, setJiraToken] = useState("");
  const [jiraProjectKey, setJiraProjectKey] = useState("");
  const [ghToken, setGhToken] = useState("");
  const [ghOwner, setGhOwner] = useState("");
  const [ghRepo, setGhRepo] = useState("");
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data: status, isLoading } = useQuery<IntegrationsStatus>({
    queryKey: ["/api/integrations/status"],
  });

  const { data: ticketingStatus } = useQuery<{
    jira: { configured: boolean; projectKey: string | null };
    github: { configured: boolean; owner: string | null; repo: string | null };
  }>({
    queryKey: ["/api/integrations/ticketing"],
  });

  const { data: ollamaStatus, refetch: refetchOllamaStatus } = useQuery<{ reachable: boolean; modelLoaded?: boolean }>({
    queryKey: ["/api/ollama/status"],
    refetchInterval: status?.ollama?.enabled ? 10000 : false,
  });

  useEffect(() => {
    if (status?.ollama) {
      setOllamaBaseUrl(status.ollama.baseUrl || "http://localhost:11434");
      const model = status.ollama.model || "tinyllama";
      const preset = OLLAMA_MODEL_OPTIONS.find((o) => o.value !== "custom" && (model === o.value || model.startsWith(o.value + ":")));
      setOllamaModelSelect(preset ? preset.value : "custom");
      setOllamaModelCustom(preset ? "" : model);
      setOllamaEnabled(status.ollama.enabled ?? false);
    }
  }, [status]);

  const updateMutation = useMutation({
    mutationFn: async (keys: { abuseipdb?: string; virustotal?: string; tavily?: string; ollamaBaseUrl?: string; ollamaModel?: string; ollamaEnabled?: boolean }) => {
      const res = await apiRequest("POST", "/api/integrations", keys);
      const text = await res.text();
      if (!text || text.trim() === "") return {} as IntegrationsStatus;
      const trimmed = text.trim();
      if (trimmed.startsWith("<")) {
        throw new Error(
          "Server returned a page instead of API. Ensure the app is running with 'npm run dev' and the API is reachable."
        );
      }
      try {
        return JSON.parse(text) as IntegrationsStatus;
      } catch {
        throw new Error(`Invalid response from server: ${trimmed.slice(0, 80)}${trimmed.length > 80 ? "…" : ""}`);
      }
    },
    onSuccess: (data: IntegrationsStatus, variables) => {
      if (data && typeof data === "object" && "tavily" in data) {
        qc.setQueryData(["/api/integrations/status"], data);
      }
      qc.invalidateQueries({ queryKey: ["/api/integrations/status"] });
      qc.invalidateQueries({ queryKey: ["/api/ollama/status"] });
      if (variables.ollamaBaseUrl !== undefined || variables.ollamaModel !== undefined || variables.ollamaEnabled !== undefined) {
        toast({ title: variables.ollamaEnabled ? "Ollama enabled" : "Ollama settings saved", description: variables.ollamaEnabled ? "AI features are now active" : "Toggle Enable AI and save to activate" });
      } else if (variables.abuseipdb === "" || variables.virustotal === "" || variables.tavily === "") {
        toast({ title: "API key removed" });
      } else if (variables.abuseipdb !== undefined || variables.virustotal !== undefined || variables.tavily !== undefined) {
        toast({ title: "API key saved" });
      }
      if (variables.abuseipdb !== undefined) {
        setAbuseipdbKey("");
        setShowAbuseipdbInput(false);
      }
      if (variables.virustotal !== undefined) {
        setVirustotalKey("");
        setShowVirustotalInput(false);
      }
      if (variables.tavily !== undefined) {
        setTavilyKey("");
        setShowTavilyInput(false);
      }
    },
    onError: (err: Error) => {
      toast({ title: "Failed to save", description: err.message, variant: "destructive" });
    },
  });

  const handleSaveAbuseipdb = () => {
    if (!abuseipdbKey.trim()) {
      toast({ title: "Enter API key", variant: "destructive" });
      return;
    }
    updateMutation.mutate({ abuseipdb: abuseipdbKey.trim() });
  };

  const handleSaveVirustotal = () => {
    if (!virustotalKey.trim()) {
      toast({ title: "Enter API key", variant: "destructive" });
      return;
    }
    updateMutation.mutate({ virustotal: virustotalKey.trim() });
  };

  const handleSaveTavily = () => {
    if (!tavilyKey.trim()) {
      toast({ title: "Enter API key", variant: "destructive" });
      return;
    }
    updateMutation.mutate({ tavily: tavilyKey.trim() });
  };

  const handleRemoveAbuseipdb = () => updateMutation.mutate({ abuseipdb: "" });
  const handleRemoveVirustotal = () => updateMutation.mutate({ virustotal: "" });
  const handleRemoveTavily = () => updateMutation.mutate({ tavily: "" });

  const resolvedOllamaModel = ollamaModelSelect === "custom" ? ollamaModelCustom.trim() || "tinyllama" : ollamaModelSelect;

  const handleSaveOllama = () => {
    updateMutation.mutate({
      ollamaBaseUrl: ollamaBaseUrl.trim() || "http://localhost:11434",
      ollamaModel: resolvedOllamaModel,
      ollamaEnabled,
    });
  };

  const isSaving = updateMutation.isPending;

  const ollamaConfigured = status?.ollama?.enabled && ollamaStatus?.reachable;
  const ollamaReachable = ollamaStatus?.reachable === true;

  if (isLoading) {
    return (
      <div className="space-y-6 p-6">
        <Skeleton className="h-8 w-48 mb-2" />
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Skeleton className="h-40" />
          <Skeleton className="h-40" />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight" data-testid="text-integrations-title">
          API Integrations
        </h1>
        <p className="text-sm text-muted-foreground mt-1">
          Configure threat intelligence APIs to enrich reports and attack surface data
        </p>
      </div>

      <div>
        <h2 className="text-sm font-medium uppercase tracking-wider text-muted-foreground mb-3">
          Threat Intelligence APIs
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Card data-testid="card-abuseipdb">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between gap-2">
                <CardTitle className="text-base flex items-center gap-2">
                  <Shield className="w-4 h-4" />
                  AbuseIPDB
                </CardTitle>
                <Badge
                  variant="outline"
                  className={`text-xs border-0 no-default-hover-elevate no-default-active-elevate ${
                    status?.abuseipdb?.configured ? "bg-green-600/15 text-green-400" : "bg-slate-600/15 text-slate-400"
                  }`}
                >
                  {status?.abuseipdb?.configured ? (
                    <>
                      <CheckCircle2 className="w-3 h-3 mr-1" />
                      Configured
                    </>
                  ) : (
                    <>
                      <XCircle className="w-3 h-3 mr-1" />
                      Not configured
                    </>
                  )}
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-sm text-muted-foreground">
                IP abuse and reputation data for enriching reports and attack surface.
              </p>
              {status?.abuseipdb?.configured && !showAbuseipdbInput ? (
                <div className="flex items-center gap-2">
                  <p className="text-xs text-muted-foreground">Configured.</p>
                  <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => setShowAbuseipdbInput(true)}>
                    Update key
                  </Button>
                </div>
              ) : (
                <div className="flex flex-wrap gap-2">
                  <Input
                    type="password"
                    placeholder="Enter AbuseIPDB API key"
                    value={abuseipdbKey}
                    onChange={(e) => setAbuseipdbKey(e.target.value)}
                    className="flex-1 min-w-[200px] font-mono text-sm"
                    data-testid="input-abuseipdb-key"
                  />
                  <Button
                    size="sm"
                    onClick={handleSaveAbuseipdb}
                    disabled={isSaving || !abuseipdbKey.trim()}
                    data-testid="button-save-abuseipdb"
                  >
                    {isSaving ? <Loader2 className="w-4 h-4 animate-spin" /> : "Save"}
                  </Button>
                  {status?.abuseipdb?.configured && (
                    <>
                      <Button variant="ghost" size="sm" onClick={() => setShowAbuseipdbInput(false)}>
                        Cancel
                      </Button>
                      <Button variant="ghost" size="sm" className="text-destructive hover:text-destructive" onClick={handleRemoveAbuseipdb} disabled={isSaving}>
                        Remove key
                      </Button>
                    </>
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          <Card data-testid="card-virustotal">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between gap-2">
                <CardTitle className="text-base flex items-center gap-2">
                  <Shield className="w-4 h-4" />
                  VirusTotal
                </CardTitle>
                <Badge
                  variant="outline"
                  className={`text-xs border-0 no-default-hover-elevate no-default-active-elevate ${
                    status?.virustotal?.configured ? "bg-green-600/15 text-green-400" : "bg-slate-600/15 text-slate-400"
                  }`}
                >
                  {status?.virustotal?.configured ? (
                    <>
                      <CheckCircle2 className="w-3 h-3 mr-1" />
                      Configured
                    </>
                  ) : (
                    <>
                      <XCircle className="w-3 h-3 mr-1" />
                      Not configured
                    </>
                  )}
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Malware and threat detection for enriching reports and attack surface.
              </p>
              {status?.virustotal?.configured && !showVirustotalInput ? (
                <div className="flex items-center gap-2">
                  <p className="text-xs text-muted-foreground">Configured.</p>
                  <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => setShowVirustotalInput(true)}>
                    Update key
                  </Button>
                </div>
              ) : (
                <div className="flex flex-wrap gap-2">
                  <Input
                    type="password"
                    placeholder="Enter VirusTotal API key"
                    value={virustotalKey}
                    onChange={(e) => setVirustotalKey(e.target.value)}
                    className="flex-1 min-w-[200px] font-mono text-sm"
                    data-testid="input-virustotal-key"
                  />
                  <Button
                    size="sm"
                    onClick={handleSaveVirustotal}
                    disabled={isSaving || !virustotalKey.trim()}
                    data-testid="button-save-virustotal"
                  >
                    {isSaving ? <Loader2 className="w-4 h-4 animate-spin" /> : "Save"}
                  </Button>
                  {status?.virustotal?.configured && (
                    <>
                      <Button variant="ghost" size="sm" onClick={() => setShowVirustotalInput(false)}>
                        Cancel
                      </Button>
                      <Button variant="ghost" size="sm" className="text-destructive hover:text-destructive" onClick={handleRemoveVirustotal} disabled={isSaving}>
                        Remove key
                      </Button>
                    </>
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          <Card data-testid="card-tavily">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between gap-2">
                <CardTitle className="text-base flex items-center gap-2">
                  <Search className="w-4 h-4" />
                  Tavily
                </CardTitle>
                <Badge
                  variant="outline"
                  className={`text-xs border-0 no-default-hover-elevate no-default-active-elevate ${
                    status?.tavily?.configured ? "bg-green-600/15 text-green-400" : "bg-slate-600/15 text-slate-400"
                  }`}
                >
                  {status?.tavily?.configured ? (
                    <>
                      <CheckCircle2 className="w-3 h-3 mr-1" />
                      Configured
                    </>
                  ) : (
                    <>
                      <XCircle className="w-3 h-3 mr-1" />
                      Not configured
                    </>
                  )}
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Web search for external threat intelligence to enrich AI insights.
              </p>
              {status?.tavily?.configured && !showTavilyInput ? (
                <div className="flex items-center gap-2">
                  <p className="text-xs text-muted-foreground">Configured.</p>
                  <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => setShowTavilyInput(true)}>
                    Update key
                  </Button>
                </div>
              ) : (
                <div className="flex flex-wrap gap-2">
                  <Input
                    type="password"
                    placeholder="Enter Tavily API key"
                    value={tavilyKey}
                    onChange={(e) => setTavilyKey(e.target.value)}
                    className="flex-1 min-w-[200px] font-mono text-sm"
                    data-testid="input-tavily-key"
                  />
                  <Button
                    size="sm"
                    onClick={handleSaveTavily}
                    disabled={isSaving || !tavilyKey.trim()}
                    data-testid="button-save-tavily"
                  >
                    {isSaving ? <Loader2 className="w-4 h-4 animate-spin" /> : "Save"}
                  </Button>
                  {status?.tavily?.configured && (
                    <>
                      <Button variant="ghost" size="sm" onClick={() => setShowTavilyInput(false)}>
                        Cancel
                      </Button>
                      <Button variant="ghost" size="sm" className="text-destructive hover:text-destructive" onClick={handleRemoveTavily} disabled={isSaving}>
                        Remove key
                      </Button>
                    </>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      <div>
        <h2 className="text-sm font-medium uppercase tracking-wider text-muted-foreground mb-3">
          AI (Ollama / DeepSeek R1 Abliterated)
        </h2>
        <Card data-testid="card-ollama">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between gap-2">
              <CardTitle className="text-base flex items-center gap-2">
                <Cpu className="w-4 h-4" />
                Ollama
              </CardTitle>
              <Badge
                variant="outline"
                className={`text-xs border-0 no-default-hover-elevate no-default-active-elevate ${
                  ollamaConfigured ? "bg-green-600/15 text-green-400" : ollamaStatus?.reachable === false ? "bg-red-600/15 text-red-400" : "bg-slate-600/15 text-slate-400"
                }`}
              >
                {ollamaConfigured ? (
                  <>
                    <CheckCircle2 className="w-3 h-3 mr-1" />
                    Configured
                  </>
                ) : ollamaStatus?.reachable === false ? (
                  <>
                    <XCircle className="w-3 h-3 mr-1" />
                    Ollama unreachable
                  </>
                ) : (
                  <>
                    <XCircle className="w-3 h-3 mr-1" />
                    Not configured
                  </>
                )}
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Local AI for finding enrichment, automated reports, and scan consolidation. Uses Ollama (fast on CPU).
            </p>
            <div className="rounded-md bg-muted/50 p-3 text-xs text-muted-foreground space-y-1">
              <p className="font-medium text-foreground">Setup:</p>
              <ol className="list-decimal list-inside space-y-0.5">
                <li>Install Ollama and run <code className="bg-muted px-1 rounded">ollama serve</code></li>
                <li>Pull a model: <code className="bg-muted px-1 rounded">ollama pull smollm2:135m</code> (smallest) or <code className="bg-muted px-1 rounded">ollama pull tinyllama</code></li>
                <li>Toggle <strong>Enable AI</strong> on and click Save</li>
              </ol>
            </div>
            <div className="space-y-2">
              <Label className="text-xs">Base URL</Label>
              <p className="text-xs text-muted-foreground">Use localhost for best performance. Remote Ollama may cause timeouts.</p>
              <Input
                placeholder="http://localhost:11434"
                value={ollamaBaseUrl}
                onChange={(e) => setOllamaBaseUrl(e.target.value)}
                className="font-mono text-sm"
                data-testid="input-ollama-url"
              />
            </div>
            <div className="space-y-2">
              <Label className="text-xs">Model</Label>
              <p className="text-xs text-muted-foreground">smollm2:135m is smallest; run <code className="bg-muted px-1 rounded">ollama pull smollm2:135m</code> to use.</p>
              <Select value={ollamaModelSelect} onValueChange={setOllamaModelSelect} data-testid="select-ollama-model">
                <SelectTrigger className="font-mono text-sm">
                  <SelectValue placeholder="Select model" />
                </SelectTrigger>
                <SelectContent>
                  {OLLAMA_MODEL_OPTIONS.map((opt) => (
                    <SelectItem key={opt.value} value={opt.value}>
                      {opt.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {ollamaModelSelect === "custom" && (
                <Input
                  placeholder="e.g. llama3.2:latest"
                  value={ollamaModelCustom}
                  onChange={(e) => setOllamaModelCustom(e.target.value)}
                  className="font-mono text-sm"
                  data-testid="input-ollama-model-custom"
                />
              )}
            </div>
            <div className={`flex items-center justify-between rounded-md border p-3 ${!ollamaEnabled ? "bg-amber-500/10 border-amber-500/30" : "bg-muted/30"}`}>
              <div>
                <Label className="text-sm font-medium">Enable AI</Label>
                <p className="text-xs text-muted-foreground mt-0.5">
                  {ollamaEnabled ? "AI features are active" : "Turn ON and click Save—required for AI Insights"}
                </p>
              </div>
              <Switch
                checked={ollamaEnabled}
                onCheckedChange={setOllamaEnabled}
                data-testid="switch-ollama-enabled"
              />
            </div>
            <div className="flex items-center gap-2">
              <Button
                size="sm"
                onClick={handleSaveOllama}
                disabled={isSaving}
                data-testid="button-save-ollama"
              >
                {isSaving ? <Loader2 className="w-4 h-4 animate-spin" /> : "Save"}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={async () => {
                  const { data } = await refetchOllamaStatus();
                  if (data?.reachable) {
                    toast({ title: "Ollama reachable", description: data.modelLoaded ? "Model loaded" : "Model may need to be pulled" });
                  } else {
                    toast({ title: "Ollama unreachable", description: "Ensure ollama serve is running", variant: "destructive" });
                  }
                }}
                disabled={!ollamaBaseUrl.trim()}
              >
                Test connection
              </Button>
            </div>
            {!ollamaReachable && ollamaEnabled && (
              <p className="text-xs text-amber-600 dark:text-amber-500">
                Ollama is enabled but unreachable. Ensure <code className="bg-muted px-1 rounded">ollama serve</code> is running.
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      <div>
        <h2 className="text-sm font-medium uppercase tracking-wider text-muted-foreground mb-3">
          Ticketing Integrations
        </h2>
        <p className="text-sm text-muted-foreground mb-3">
          Create tickets from findings directly in Jira or GitHub Issues.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Card>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between gap-2">
                <CardTitle className="text-base flex items-center gap-2">
                  <TicketCheck className="w-4 h-4" />
                  Jira
                </CardTitle>
                <Badge
                  variant="outline"
                  className={`text-xs border-0 ${ticketingStatus?.jira?.configured ? "bg-green-600/15 text-green-400" : "bg-slate-600/15 text-slate-400"}`}
                >
                  {ticketingStatus?.jira?.configured ? (
                    <><CheckCircle2 className="w-3 h-3 mr-1" /> Configured</>
                  ) : (
                    <><XCircle className="w-3 h-3 mr-1" /> Not configured</>
                  )}
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Create Jira issues from findings with severity-based priority mapping.
              </p>
              <div className="space-y-2">
                <Input placeholder="Jira Base URL (e.g. https://myorg.atlassian.net)" value={jiraBaseUrl} onChange={(e) => setJiraBaseUrl(e.target.value)} className="text-sm" />
                <Input placeholder="Email" value={jiraEmail} onChange={(e) => setJiraEmail(e.target.value)} className="text-sm" />
                <Input type="password" placeholder="API Token" value={jiraToken} onChange={(e) => setJiraToken(e.target.value)} className="text-sm font-mono" />
                <Input placeholder="Project Key (e.g. SEC)" value={jiraProjectKey} onChange={(e) => setJiraProjectKey(e.target.value)} className="text-sm font-mono" />
              </div>
              <div className="flex gap-2">
                <Button size="sm" disabled={!jiraBaseUrl.trim() || !jiraToken.trim()} onClick={async () => {
                  try {
                    await apiRequest("PUT", "/api/integrations/ticketing/jira", { baseUrl: jiraBaseUrl.trim(), email: jiraEmail.trim(), apiToken: jiraToken.trim(), projectKey: jiraProjectKey.trim() });
                    qc.invalidateQueries({ queryKey: ["/api/integrations/ticketing"] });
                    toast({ title: "Jira configured" });
                    setJiraToken("");
                  } catch (err) { toast({ title: "Error", description: err instanceof Error ? err.message : "Failed", variant: "destructive" }); }
                }}>Save</Button>
                {ticketingStatus?.jira?.configured && (
                  <Button variant="ghost" size="sm" className="text-destructive" onClick={async () => {
                    try {
                      await apiRequest("DELETE", "/api/integrations/ticketing/jira");
                      qc.invalidateQueries({ queryKey: ["/api/integrations/ticketing"] });
                      toast({ title: "Jira config removed" });
                    } catch (err) { toast({ title: "Error", description: err instanceof Error ? err.message : "Failed", variant: "destructive" }); }
                  }}>Remove</Button>
                )}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between gap-2">
                <CardTitle className="text-base flex items-center gap-2">
                  <Github className="w-4 h-4" />
                  GitHub Issues
                </CardTitle>
                <Badge
                  variant="outline"
                  className={`text-xs border-0 ${ticketingStatus?.github?.configured ? "bg-green-600/15 text-green-400" : "bg-slate-600/15 text-slate-400"}`}
                >
                  {ticketingStatus?.github?.configured ? (
                    <><CheckCircle2 className="w-3 h-3 mr-1" /> Configured</>
                  ) : (
                    <><XCircle className="w-3 h-3 mr-1" /> Not configured</>
                  )}
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Create GitHub issues from findings with security labels.
              </p>
              <div className="space-y-2">
                <Input type="password" placeholder="Personal Access Token" value={ghToken} onChange={(e) => setGhToken(e.target.value)} className="text-sm font-mono" />
                <Input placeholder="Repository Owner" value={ghOwner} onChange={(e) => setGhOwner(e.target.value)} className="text-sm" />
                <Input placeholder="Repository Name" value={ghRepo} onChange={(e) => setGhRepo(e.target.value)} className="text-sm" />
              </div>
              <div className="flex gap-2">
                <Button size="sm" disabled={!ghToken.trim() || !ghOwner.trim() || !ghRepo.trim()} onClick={async () => {
                  try {
                    await apiRequest("PUT", "/api/integrations/ticketing/github", { token: ghToken.trim(), owner: ghOwner.trim(), repo: ghRepo.trim() });
                    qc.invalidateQueries({ queryKey: ["/api/integrations/ticketing"] });
                    toast({ title: "GitHub configured" });
                    setGhToken("");
                  } catch (err) { toast({ title: "Error", description: err instanceof Error ? err.message : "Failed", variant: "destructive" }); }
                }}>Save</Button>
                {ticketingStatus?.github?.configured && (
                  <Button variant="ghost" size="sm" className="text-destructive" onClick={async () => {
                    try {
                      await apiRequest("DELETE", "/api/integrations/ticketing/github");
                      qc.invalidateQueries({ queryKey: ["/api/integrations/ticketing"] });
                      toast({ title: "GitHub config removed" });
                    } catch (err) { toast({ title: "Error", description: err instanceof Error ? err.message : "Failed", variant: "destructive" }); }
                  }}>Remove</Button>
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      <div>
        <h2 className="text-sm font-medium uppercase tracking-wider text-muted-foreground mb-3">
          System
        </h2>
        <Card>
          <CardContent className="py-6">
            <div className="flex items-center justify-between gap-4">
              <div>
                <p className="text-sm font-medium">Shutdown</p>
                <p className="text-xs text-muted-foreground mt-0.5">
                  Stop the application and all associated processes (scanners, API server, etc.)
                </p>
              </div>
              <Button
                variant="destructive"
                size="sm"
                onClick={() => setShutdownDialogOpen(true)}
                disabled={shutdownPending}
                data-testid="button-shutdown"
              >
                {shutdownPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <PowerOff className="w-4 h-4" />}
                <span className="ml-2">{shutdownPending ? "Shutting down..." : "Shutdown"}</span>
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>

      <AlertDialog open={shutdownDialogOpen} onOpenChange={setShutdownDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Shutdown application</AlertDialogTitle>
            <AlertDialogDescription>
              This will stop the Cyshield server and all associated processes (scanners, API, etc.). You will need to
              restart the application manually. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={async (e) => {
                e.preventDefault();
                setShutdownPending(true);
                setShutdownDialogOpen(false);
                try {
                  await apiRequest("POST", "/api/admin/shutdown");
                  toast({ title: "Shutting down...", description: "The application will stop shortly." });
                } catch (err) {
                  const msg = err instanceof Error ? err.message : String(err);
                  if (msg.includes("fetch") || msg.includes("network") || msg.includes("Failed to fetch") || msg.includes("Connection")) {
                    toast({ title: "Shutting down...", description: "The server is stopping." });
                  } else {
                    setShutdownPending(false);
                    toast({ title: "Shutdown failed", description: msg, variant: "destructive" });
                  }
                }
              }}
              disabled={shutdownPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Shutdown
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
