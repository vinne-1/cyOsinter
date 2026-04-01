import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Swords,
  Play,
  ChevronDown,
  ChevronUp,
  CheckCircle2,
  XCircle,
  AlertTriangle,
} from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

interface PlaybookStep {
  name: string;
  description: string;
  technique: string;
}

interface Playbook {
  id: string;
  name: string;
  description: string;
  category: string;
  mitreTactics: string[];
  steps: PlaybookStep[];
}

interface SimulationResult {
  exploitable: boolean;
  matchedSteps: number;
  totalSteps: number;
  riskScore: number;
  recommendations: string[];
}

const categoryColors: Record<string, string> = {
  reconnaissance: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300",
  "initial-access": "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300",
  persistence: "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-300",
  "privilege-escalation": "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300",
  "lateral-movement": "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300",
};

function PlaybookCard({
  playbook,
  onSimulate,
  isSimulating,
}: {
  playbook: Playbook;
  onSimulate: (id: string) => void;
  isSimulating: boolean;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between">
          <CardTitle className="text-base">{playbook.name}</CardTitle>
          <Badge
            className={categoryColors[playbook.category] || "bg-gray-100 text-gray-800"}
            variant="secondary"
          >
            {playbook.category}
          </Badge>
        </div>
        <p className="text-sm text-muted-foreground">{playbook.description}</p>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex flex-wrap gap-1">
          {playbook.mitreTactics.map((tactic) => (
            <Badge key={tactic} variant="outline" className="text-xs">
              {tactic}
            </Badge>
          ))}
        </div>
        <div className="flex items-center justify-between pt-1">
          <span className="text-sm text-muted-foreground">
            {playbook.steps.length} steps
          </span>
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={() => setExpanded(!expanded)}
            >
              {expanded ? (
                <ChevronUp className="w-4 h-4 mr-1" />
              ) : (
                <ChevronDown className="w-4 h-4 mr-1" />
              )}
              {expanded ? "Hide Steps" : "View Steps"}
            </Button>
            <Button
              size="sm"
              onClick={() => onSimulate(playbook.id)}
              disabled={isSimulating}
            >
              <Play className="w-4 h-4 mr-1" />
              {isSimulating ? "Running..." : "Run Simulation"}
            </Button>
          </div>
        </div>
        {expanded && (
          <div className="space-y-2 pt-2 border-t">
            {playbook.steps.map((step, idx) => (
              <div
                key={`${step.technique}-${idx}`}
                className="flex items-start gap-3 p-3 rounded-md border bg-muted/50"
              >
                <span className="text-xs font-bold text-muted-foreground mt-0.5">
                  {idx + 1}
                </span>
                <div>
                  <p className="text-sm font-medium">{step.name}</p>
                  <p className="text-xs text-muted-foreground">{step.description}</p>
                  <Badge variant="outline" className="text-xs mt-1">
                    {step.technique}
                  </Badge>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default function Playbooks() {
  const { toast } = useToast();
  const [simResult, setSimResult] = useState<SimulationResult | null>(null);
  const [simDialogOpen, setSimDialogOpen] = useState(false);

  const { data: playbooks = [], isLoading } = useQuery<Playbook[]>({
    queryKey: ["/api/playbooks"],
  });

  const simulate = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiRequest("POST", `/api/playbooks/${id}/simulate`);
      return res.json();
    },
    onSuccess: (data: SimulationResult) => {
      setSimResult(data);
      setSimDialogOpen(true);
    },
    onError: (err: Error) => {
      toast({
        title: "Simulation failed",
        description: err.message,
        variant: "destructive",
      });
    },
  });

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-48" />
        <div className="grid gap-4 md:grid-cols-2">
          {[1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-48" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-3">
        <Swords className="w-6 h-6 text-primary" />
        <div>
          <h1 className="text-2xl font-bold">Attack Playbooks</h1>
          <p className="text-sm text-muted-foreground">
            Browse and simulate attack scenarios based on MITRE ATT&CK
          </p>
        </div>
      </div>

      {playbooks.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-16">
            <Swords className="w-12 h-12 text-muted-foreground mb-4" />
            <p className="text-muted-foreground">No playbooks available</p>
            <p className="text-sm text-muted-foreground mt-1">
              Playbooks will appear once attack simulations are configured
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          {playbooks.map((pb) => (
            <PlaybookCard
              key={pb.id}
              playbook={pb}
              onSimulate={(id) => simulate.mutate(id)}
              isSimulating={simulate.isPending}
            />
          ))}
        </div>
      )}

      <Dialog open={simDialogOpen} onOpenChange={setSimDialogOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Simulation Results</DialogTitle>
          </DialogHeader>
          {simResult && (
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                {simResult.exploitable ? (
                  <XCircle className="w-6 h-6 text-red-500" />
                ) : (
                  <CheckCircle2 className="w-6 h-6 text-green-500" />
                )}
                <span className="text-lg font-semibold">
                  {simResult.exploitable ? "Exploitable" : "Not Exploitable"}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <Card>
                  <CardContent className="py-3">
                    <p className="text-xs text-muted-foreground">Matched Steps</p>
                    <p className="text-lg font-bold">
                      {simResult.matchedSteps} / {simResult.totalSteps}
                    </p>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="py-3">
                    <p className="text-xs text-muted-foreground">Risk Score</p>
                    <p
                      className={`text-lg font-bold ${
                        simResult.riskScore >= 80
                          ? "text-red-600"
                          : simResult.riskScore >= 50
                            ? "text-orange-600"
                            : "text-green-600"
                      }`}
                    >
                      {simResult.riskScore} / 100
                    </p>
                  </CardContent>
                </Card>
              </div>

              {simResult.recommendations.length > 0 && (
                <div className="space-y-2">
                  <p className="text-sm font-medium flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-yellow-500" />
                    Recommendations
                  </p>
                  <ul className="space-y-1">
                    {simResult.recommendations.map((rec, idx) => (
                      <li
                        key={idx}
                        className="text-sm text-muted-foreground pl-4 border-l-2 border-yellow-300"
                      >
                        {rec}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
