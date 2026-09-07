import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ShieldCheck } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

/** Mirrors PASSWORD_MIN_LENGTH in server/password-policy.ts. */
const MIN_LENGTH = 12;

interface ChangePasswordResponse {
  success: boolean;
  token: string;
  refreshToken: string;
}

/**
 * Account security.
 *
 * There was no way for a user to change their password anywhere in the product
 * — the endpoint did not exist and neither did a screen for it. Someone who
 * believed their password was compromised had no recourse.
 *
 * Two details that are easy to get wrong:
 *  - Changing the password revokes every session, including this one, so the
 *    server hands back a fresh token that must be stored immediately. Without
 *    that the user is silently signed out by their own successful action.
 *  - The inputs are plain `type="password"` with no paste blocking and no
 *    composition hints, per ASVS V6.2.6/V6.2.7: password managers must work, and
 *    telling people to add a symbol produces `Password1!`.
 */
export default function AccountPage() {
  const { toast } = useToast();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const mismatch = confirmPassword.length > 0 && newPassword !== confirmPassword;
  const tooShort = newPassword.length > 0 && newPassword.length < MIN_LENGTH;
  const canSubmit =
    currentPassword.length > 0 &&
    newPassword.length >= MIN_LENGTH &&
    newPassword === confirmPassword;

  const change = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/auth/change-password", {
        currentPassword,
        newPassword,
      });
      return (await res.json()) as ChangePasswordResponse;
    },
    onSuccess: (data) => {
      // The old token was just revoked server-side along with every other
      // session; store the replacement before anything else fires a request.
      if (data.token) localStorage.setItem("auth_token", data.token);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      toast({
        title: "Password changed",
        description: "All other sessions have been signed out.",
      });
    },
    onError: (err: Error) => {
      toast({
        title: "Could not change password",
        description: err.message,
        variant: "destructive",
      });
    },
  });

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Account Security</h1>
        <p className="text-muted-foreground mt-1 text-sm">
          Manage the credentials for your own account.
        </p>
      </div>

      <Card className="max-w-xl">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5" aria-hidden="true" />
            Change password
          </CardTitle>
          <CardDescription>
            Changing your password signs out every other session, including any device you no
            longer have.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              if (canSubmit) change.mutate();
            }}
          >
            <div className="space-y-2">
              <Label htmlFor="current-password">Current password</Label>
              <Input
                id="current-password"
                type="password"
                autoComplete="current-password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="new-password">New password</Label>
              <Input
                id="new-password"
                type="password"
                autoComplete="new-password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                aria-describedby="new-password-hint"
              />
              {/*
                Length only. No "must contain a number" — that rule is what
                ASVS V6.2.5 exists to remove, and the server screens against
                known-common passwords instead, which is the check that
                actually correlates with strength.
              */}
              <p id="new-password-hint" className="text-muted-foreground text-xs">
                At least {MIN_LENGTH} characters. A memorable phrase of several words is stronger
                than a short password with symbols in it.
              </p>
              {tooShort && (
                <p className="text-destructive text-xs">
                  Must be at least {MIN_LENGTH} characters.
                </p>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="confirm-password">Confirm new password</Label>
              <Input
                id="confirm-password"
                type="password"
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                aria-describedby={mismatch ? "confirm-error" : undefined}
              />
              {mismatch && (
                <p id="confirm-error" className="text-destructive text-xs">
                  Passwords do not match.
                </p>
              )}
            </div>

            <Button type="submit" disabled={!canSubmit || change.isPending}>
              {change.isPending ? "Changing..." : "Change password"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
