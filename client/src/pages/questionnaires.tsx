import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { Loader2 } from "lucide-react";

interface QuestionnaireRun {
  id: string;
  questionnaireType: string;
  totalQuestions: number;
  autoAnswered: number;
  manualRequired: number;
  coveragePct: number;
  answers: Array<{
    questionId: string;
    question: string;
    answer: string;
    confidence: string;
    notes: string;
  }>;
  createdAt: string;
}

export default function QuestionnairesPage() {
  const { selectedWorkspaceId } = useDomain();
  const { toast } = useToast();
  const qc = useQueryClient();

  const queryKey = [`/api/workspaces/${selectedWorkspaceId}/questionnaires`];
  const { data: runs = [], isLoading } = useQuery<QuestionnaireRun[]>({
    queryKey,
    enabled: !!selectedWorkspaceId,
  });

  const runMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/workspaces/${selectedWorkspaceId}/questionnaires`, { type: "security_baseline" });
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Questionnaire generated" });
      qc.invalidateQueries({ queryKey });
    },
    onError: (err: Error) => toast({ title: "Failed to generate questionnaire", description: err.message, variant: "destructive" }),
  });

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Questionnaires</h1>
          <p className="text-sm text-muted-foreground">Deterministic auto-fill backed by findings and policy evidence.</p>
        </div>
        <Button onClick={() => runMutation.mutate()} disabled={!selectedWorkspaceId || runMutation.isPending}>
          {runMutation.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : null}
          Run Security Baseline
        </Button>
      </div>

      {!selectedWorkspaceId ? (
        <Card><CardContent className="py-10 text-center text-sm text-muted-foreground">Select a workspace to run questionnaires.</CardContent></Card>
      ) : null}

      {isLoading ? <p className="text-sm text-muted-foreground">Loading questionnaire runs...</p> : null}

      {selectedWorkspaceId && !isLoading && runs.length === 0 ? (
        <Card><CardContent className="py-10 text-center text-sm text-muted-foreground">No questionnaire runs yet.</CardContent></Card>
      ) : null}

      {runs.map((run) => (
        <Card key={run.id}>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              {run.questionnaireType}
              <Badge variant="outline">Coverage {run.coveragePct}%</Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <p className="text-sm text-muted-foreground">
              {run.autoAnswered}/{run.totalQuestions} auto-answered, {run.manualRequired} manual review required
            </p>
            {run.answers?.slice(0, 8).map((answer) => (
              <div key={answer.questionId} className="rounded-md border p-3">
                <div className="flex items-center justify-between gap-2">
                  <p className="text-sm font-medium">{answer.question}</p>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline">{answer.answer}</Badge>
                    <Badge variant="secondary">{answer.confidence}</Badge>
                  </div>
                </div>
                <p className="text-xs text-muted-foreground mt-1">{answer.notes}</p>
              </div>
            ))}
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

