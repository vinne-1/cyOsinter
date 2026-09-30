import { useEffect, useRef, useState } from "react";
import { useLocation } from "wouter";
import { useMutation } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { apiRequest, ApiError } from "@/lib/queryClient";
import { CatHead, type CatMood } from "@/components/cat-head";
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from "@/components/ui/sheet";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { Send, Loader2, Sparkles } from "lucide-react";

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
  /** Set on a failed assistant turn so it renders as an error bubble. */
  error?: boolean;
}

const MAX_HISTORY_SENT = 10;

const SUGGESTIONS = [
  "What are my most critical open findings?",
  "Explain what I'm looking at on this page",
  "What's my current security score, and why?",
];

/**
 * A floating, always-available assistant. It only ever answers from this
 * workspace's own scanned data — see server/ai-chat.ts for the grounding and
 * prompt-injection defenses behind the API it calls. There is no client-side
 * enforcement of that; the server is the only trust boundary that matters.
 */
export function AssistantWidget() {
  const { selectedWorkspaceId, selectedDomain } = useDomain();
  const [location] = useLocation();
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const bottomRef = useRef<HTMLDivElement>(null);
  const workspaceIdRef = useRef(selectedWorkspaceId);

  // A conversation is scoped to one workspace's data — switching workspaces
  // mid-chat would otherwise answer new questions from a stale context while
  // still displaying the old workspace's history.
  useEffect(() => {
    if (workspaceIdRef.current !== selectedWorkspaceId) {
      workspaceIdRef.current = selectedWorkspaceId;
      setMessages([]);
    }
  }, [selectedWorkspaceId]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [messages, open]);

  const chatMutation = useMutation({
    mutationFn: async (message: string) => {
      const history = messages.slice(-MAX_HISTORY_SENT).map((m) => ({ role: m.role, content: m.content }));
      const res = await apiRequest(
        "POST",
        `/api/workspaces/${selectedWorkspaceId}/assistant/chat`,
        { message, history, page: location },
        { timeoutMs: 70000 },
      );
      return (await res.json()) as { reply: string };
    },
    onSuccess: (data) => {
      setMessages((prev) => [...prev, { role: "assistant", content: data.reply }]);
    },
    onError: (err: Error) => {
      const message =
        err instanceof ApiError && err.status === 503
          ? "The assistant isn't enabled yet — an administrator needs to set up GLM in Integrations."
          : err instanceof ApiError && err.status === 429
            ? "That's a lot of questions at once — give it a moment and try again."
            : err.message || "The assistant couldn't answer that. Try again.";
      setMessages((prev) => [...prev, { role: "assistant", content: message, error: true }]);
    },
  });

  const send = (text: string) => {
    const trimmed = text.trim();
    if (!trimmed || !selectedWorkspaceId || chatMutation.isPending) return;
    setMessages((prev) => [...prev, { role: "user", content: trimmed }]);
    setInput("");
    chatMutation.mutate(trimmed);
  };

  const mood: CatMood = chatMutation.isPending
    ? "thinking"
    : messages.length > 0 && messages[messages.length - 1]?.error
      ? "sad"
      : messages.length > 0
        ? "happy"
        : "idle";

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        aria-label="Open CyShield assistant"
        data-testid="button-assistant-widget"
        className="fixed bottom-5 right-5 z-40 flex h-14 w-14 items-center justify-center rounded-full bg-primary text-primary-foreground shadow-lg transition-transform hover:scale-105 active:scale-95"
        style={{ ["--cat-eye" as string]: "hsl(var(--primary-foreground))", ["--cat-pupil" as string]: "hsl(var(--primary))" }}
      >
        <CatHead mood={open ? "idle" : mood} size={32} />
        {!open && messages.length === 0 && (
          <span className="absolute -right-0.5 -top-0.5 flex h-3.5 w-3.5">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-accent opacity-75" />
            <span className="relative inline-flex h-3.5 w-3.5 rounded-full bg-accent" />
          </span>
        )}
      </button>

      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent side="right" className="flex w-full flex-col gap-0 p-0 sm:max-w-md">
          <SheetHeader className="border-b border-hairline px-4 py-3 text-left">
            <SheetTitle className="flex items-center gap-2 text-base">
              <span className="flex h-8 w-8 items-center justify-center rounded-full bg-primary text-primary-foreground" style={{ ["--cat-eye" as string]: "hsl(var(--primary-foreground))", ["--cat-pupil" as string]: "hsl(var(--primary))" }}>
                <CatHead mood={mood} size={22} />
              </span>
              CyShield Assistant
            </SheetTitle>
            <SheetDescription>
              {selectedDomain ? `Answers only from ${selectedDomain}'s scanned data.` : "Select a workspace to start."}
            </SheetDescription>
          </SheetHeader>

          <ScrollArea className="flex-1 px-4 py-3">
            {messages.length === 0 ? (
              <div className="flex flex-col items-center gap-4 py-8 text-center">
                <Sparkles className="h-8 w-8 text-muted-foreground/50" aria-hidden="true" />
                <p className="text-sm text-muted-foreground">
                  Ask about findings, scores, scans, or whatever's on the current page — grounded strictly in this
                  workspace's own scanned data.
                </p>
                <div className="flex w-full flex-col gap-2">
                  {SUGGESTIONS.map((s) => (
                    <button
                      key={s}
                      type="button"
                      onClick={() => send(s)}
                      disabled={!selectedWorkspaceId}
                      data-testid={`button-assistant-suggestion-${s.slice(0, 10).replace(/\W+/g, "-")}`}
                      className="rounded-lg border border-hairline bg-surface-2 px-3 py-2 text-left text-xs text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground disabled:opacity-50"
                    >
                      {s}
                    </button>
                  ))}
                </div>
              </div>
            ) : (
              <div className="space-y-3 pb-2">
                {messages.map((m, i) => (
                  <div key={i} className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}>
                    <div
                      data-testid={`text-assistant-message-${i}`}
                      className={`max-w-[85%] rounded-lg px-3 py-2 text-sm leading-relaxed ${
                        m.role === "user"
                          ? "bg-primary text-primary-foreground"
                          : m.error
                            ? "bg-destructive/10 text-destructive"
                            : "bg-muted"
                      }`}
                    >
                      {m.content}
                    </div>
                  </div>
                ))}
                {chatMutation.isPending && (
                  <div className="flex justify-start">
                    <div className="flex items-center gap-2 rounded-lg bg-muted px-3 py-2 text-sm text-muted-foreground">
                      <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                      Thinking...
                    </div>
                  </div>
                )}
                <div ref={bottomRef} />
              </div>
            )}
          </ScrollArea>

          <form
            className="flex items-end gap-2 border-t border-hairline p-3"
            onSubmit={(e) => {
              e.preventDefault();
              send(input);
            }}
          >
            <Textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  send(input);
                }
              }}
              placeholder={selectedWorkspaceId ? "Ask about this workspace..." : "Select a workspace first"}
              disabled={!selectedWorkspaceId}
              rows={1}
              maxLength={2000}
              className="min-h-[40px] flex-1 resize-none"
              data-testid="input-assistant-message"
            />
            <Button
              type="submit"
              size="icon"
              disabled={!selectedWorkspaceId || !input.trim() || chatMutation.isPending}
              data-testid="button-assistant-send"
            >
              <Send className="h-4 w-4" aria-hidden="true" />
            </Button>
          </form>
        </SheetContent>
      </Sheet>
    </>
  );
}
