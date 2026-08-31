import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";
import { AlertTriangle, Lock, Info, Clock } from "lucide-react";

/**
 * Persistent, in-form explanation of why a sign-in failed.
 *
 * A toast was the only feedback before, which is exactly wrong for this case: it
 * disappears, and a locked account is precisely the situation where the user
 * needs to keep reading the message. Someone who gets a generic "try again
 * later" has no way to know whether they have the wrong password, whether the
 * account is locked, or how long to wait — so they retry, which extends the
 * lockout.
 */

export type AuthAlertKind = "invalid" | "locked" | "rate-limited" | "error";

export interface AuthAlertState {
  kind: AuthAlertKind;
  message: string;
  /** Seconds remaining; drives the countdown and re-enables the form at zero. */
  retryAfterSeconds?: number;
}

/**
 * Classifies a failed sign-in from its status and message.
 *
 * The server sends 429 for BOTH a per-account lockout and a per-IP rate limit,
 * and they mean different things to the person reading it: one is about this
 * account, the other about this network. The wording distinguishes them.
 */
export function classifyAuthError(
  status: number | undefined,
  message: string,
  retryAfterSeconds?: number,
): AuthAlertState {
  const text = message.toLowerCase();

  if (status === 429 && /failed sign-in|locked|too many failed/.test(text)) {
    // The message's duration wins over the header. When an ACCOUNT is locked,
    // the IP limiter is not what is blocking you, yet it still stamps its own
    // RateLimit-Reset on the response — using that would show a countdown that
    // expires while the account is still locked.
    return { kind: "locked", message, retryAfterSeconds: parseMinutes(message) ?? retryAfterSeconds };
  }
  if (status === 429) {
    return { kind: "rate-limited", message, retryAfterSeconds };
  }
  if (status === 401) {
    return { kind: "invalid", message };
  }
  return { kind: "error", message };
}

/** Recovers a countdown from "Try again in 2 minute(s)" or "... 45 second(s)". */
function parseMinutes(message: string): number | undefined {
  const mins = message.match(/(\d+)\s*minute/i);
  if (mins) return Number(mins[1]) * 60;
  const secs = message.match(/(\d+)\s*second/i);
  return secs ? Number(secs[1]) : undefined;
}

const STYLES: Record<AuthAlertKind, { icon: typeof Lock; ring: string; text: string; bg: string; title: string }> = {
  locked: {
    icon: Lock,
    ring: "ring-severity-critical/30",
    text: "text-severity-critical",
    bg: "bg-severity-critical/10",
    title: "Account temporarily locked",
  },
  "rate-limited": {
    icon: Clock,
    ring: "ring-severity-medium/30",
    text: "text-severity-medium",
    bg: "bg-severity-medium/10",
    title: "Too many attempts from this network",
  },
  invalid: {
    icon: AlertTriangle,
    ring: "ring-severity-high/30",
    text: "text-severity-high",
    bg: "bg-severity-high/10",
    title: "Sign-in failed",
  },
  error: {
    icon: Info,
    ring: "ring-hairline",
    text: "text-foreground",
    bg: "bg-surface-3",
    title: "Something went wrong",
  },
};

function formatRemaining(seconds: number): string {
  if (seconds >= 60) {
    const m = Math.ceil(seconds / 60);
    return `${m} minute${m === 1 ? "" : "s"}`;
  }
  return `${seconds} second${seconds === 1 ? "" : "s"}`;
}

export function AuthAlert({
  state,
  onExpire,
}: {
  state: AuthAlertState;
  /** Fired when a countdown reaches zero, so the form can re-enable itself. */
  onExpire?: () => void;
}) {
  const [remaining, setRemaining] = useState(state.retryAfterSeconds ?? 0);

  useEffect(() => {
    setRemaining(state.retryAfterSeconds ?? 0);
  }, [state.retryAfterSeconds, state.message]);

  useEffect(() => {
    if (remaining <= 0) return;
    const id = setInterval(() => {
      setRemaining((s) => {
        if (s <= 1) {
          clearInterval(id);
          onExpire?.();
          return 0;
        }
        return s - 1;
      });
    }, 1000);
    return () => clearInterval(id);
  }, [remaining > 0, onExpire]);

  const style = STYLES[state.kind];
  const Icon = style.icon;

  return (
    <div
      // assertive: this is the result of an action the user just took and it
      // blocks them, so it should interrupt rather than wait its turn.
      role="alert"
      aria-live="assertive"
      data-testid="auth-alert"
      className={cn("flex items-start gap-3 rounded-lg p-3 ring-1 ring-inset", style.bg, style.ring)}
    >
      <Icon className={cn("mt-0.5 h-4 w-4 shrink-0", style.text)} aria-hidden="true" />
      <div className="min-w-0">
        <p className={cn("text-sm font-medium", style.text)}>{style.title}</p>
        <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">
          {state.kind === "locked"
            ? "Too many failed attempts. Signing in is blocked for this account for a short period — further attempts will not work until it clears."
            : state.message}
        </p>

        {remaining > 0 && (
          <p className={cn("mt-1.5 text-xs font-medium tabular-nums", style.text)}>
            Try again in {formatRemaining(remaining)}
          </p>
        )}

        {state.kind === "invalid" && (
          <p className="mt-1.5 text-xs text-muted-foreground">
            After 5 failed attempts the account is locked for a short period.
          </p>
        )}
      </div>
    </div>
  );
}
