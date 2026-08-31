import { useState } from "react";
import { useLocation } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Shield, LogIn, UserPlus, Radar, Lock, Globe, Activity } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";

export function useAuth() {
  const token = localStorage.getItem("auth_token");
  let user: unknown = null;
  try { user = JSON.parse(localStorage.getItem("auth_user") || "null"); } catch { /* corrupted storage */ }
  const isAuthenticated = !!token;

  function login(token: string, refreshToken: string, user: unknown) {
    localStorage.setItem("auth_token", token);
    localStorage.setItem("auth_refresh_token", refreshToken);
    localStorage.setItem("auth_user", JSON.stringify(user));
  }

  function logout() {
    fetch("/api/auth/logout", {
      headers: { Authorization: `Bearer ${token}` },
      method: "POST",
    });
    localStorage.removeItem("auth_token");
    localStorage.removeItem("auth_refresh_token");
    localStorage.removeItem("auth_user");
    window.location.href = "/auth";
  }

  return { token, user, isAuthenticated, login, logout };
}

function LoginForm() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const { toast } = useToast();
  const { login } = useAuth();
  const [, navigate] = useLocation();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!email || !password) {
      toast({ title: "Please fill in all fields", variant: "destructive" });
      return;
    }
    setLoading(true);
    try {
      const res = await apiRequest("POST", "/api/auth/login", { email, password });
      const data = await res.json();
      login(data.token, data.refreshToken, data.user);
      toast({ title: "Login successful" });
      navigate("/");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Login failed";
      toast({ title: "Login failed", description: msg, variant: "destructive" });
    } finally {
      setLoading(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="login-email">Email</Label>
        <Input
          id="login-email"
          type="email"
          placeholder="you@example.com"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="login-password">Password</Label>
        <Input
          id="login-password"
          type="password"
          placeholder="Enter your password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </div>
      <Button type="submit" className="w-full" disabled={loading}>
        <LogIn className="w-4 h-4 mr-2" />
        {loading ? "Signing in..." : "Sign In"}
      </Button>
    </form>
  );
}

function RegisterForm() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const { toast } = useToast();
  const { login } = useAuth();
  const [, navigate] = useLocation();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!name || !email || !password) {
      toast({ title: "Please fill in all fields", variant: "destructive" });
      return;
    }
    setLoading(true);
    try {
      const res = await apiRequest("POST", "/api/auth/register", { name, email, password });
      const data = await res.json();
      login(data.token, data.refreshToken, data.user);
      toast({ title: "Registration successful" });
      navigate("/");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Registration failed";
      toast({ title: "Registration failed", description: msg, variant: "destructive" });
    } finally {
      setLoading(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="reg-name">Name</Label>
        <Input
          id="reg-name"
          placeholder="Your name"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="reg-email">Email</Label>
        <Input
          id="reg-email"
          type="email"
          placeholder="you@example.com"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="reg-password">Password</Label>
        <Input
          id="reg-password"
          type="password"
          placeholder="Create a password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </div>
      <Button type="submit" className="w-full" disabled={loading}>
        <UserPlus className="w-4 h-4 mr-2" />
        {loading ? "Creating account..." : "Create Account"}
      </Button>
    </form>
  );
}

export default function AuthPage() {
  return (
    <div className="grid min-h-screen lg:grid-cols-[1.1fr_1fr]">
      {/* ── Brand panel ──
          Hidden below lg so the form is never pushed off a small screen. */}
      <aside className="relative hidden overflow-hidden bg-surface-inset lg:flex lg:flex-col lg:justify-between lg:p-12">
        <div
          aria-hidden="true"
          className="pointer-events-none absolute -left-32 -top-32 h-[32rem] w-[32rem] rounded-full opacity-25 blur-3xl"
          style={{ background: "radial-gradient(circle, hsl(var(--brand-from)), transparent 70%)" }}
        />
        <div
          aria-hidden="true"
          className="pointer-events-none absolute -bottom-40 -right-24 h-[28rem] w-[28rem] rounded-full opacity-20 blur-3xl"
          style={{ background: "radial-gradient(circle, hsl(var(--brand-to)), transparent 70%)" }}
        />
        {/* Faint grid, evoking a radar sweep without animating anything costly. */}
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-0 opacity-[0.055]"
          style={{
            backgroundImage:
              "linear-gradient(hsl(var(--foreground)) 1px, transparent 1px), linear-gradient(90deg, hsl(var(--foreground)) 1px, transparent 1px)",
            backgroundSize: "56px 56px",
          }}
        />

        <div className="relative flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-brand-from to-brand-to shadow-glow">
            <Shield className="h-5 w-5 text-white" aria-hidden="true" />
          </div>
          <span className="text-xl font-semibold tracking-tight">Cyshield Pro</span>
        </div>

        <div className="relative max-w-lg">
          <h1 className="text-4xl font-semibold leading-tight tracking-tight">
            Know your attack surface
            <br />
            <span className="bg-gradient-to-r from-brand-from to-brand-to bg-clip-text text-transparent">
              before someone else does.
            </span>
          </h1>
          <p className="mt-4 text-base leading-relaxed text-muted-foreground">
            Continuous external attack surface management and OSINT reconnaissance —
            subdomains, exposed services, TLS and DNS posture, leaked secrets and CVE
            correlation, in one self-hosted platform.
          </p>

          {/* A list, not a <dl>: these are feature blurbs rather than
              term/definition pairs, and dt/dd must be direct children of the dl,
              which the two-line layout below cannot satisfy. */}
          <ul className="mt-10 grid grid-cols-2 gap-x-6 gap-y-5">
            {[
              { icon: Globe, label: "Asset discovery", copy: "Subdomains, IPs, services, certificates" },
              { icon: Radar, label: "OSINT recon", copy: "Leaked credentials and exposed documents" },
              { icon: Lock, label: "Posture scoring", copy: "TLS, DNS and email security grading" },
              { icon: Activity, label: "Continuous monitoring", copy: "Scheduled scans with change alerts" },
            ].map((f) => (
              <li key={f.label} className="flex gap-3">
                <f.icon className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
                <div>
                  <p className="text-sm font-medium">{f.label}</p>
                  <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{f.copy}</p>
                </div>
              </li>
            ))}
          </ul>
        </div>

        <p className="relative text-xs text-muted-foreground">
          Self-hosted · Your data never leaves your infrastructure
        </p>
      </aside>

      {/* ── Form panel ── */}
      <main className="flex items-center justify-center bg-background p-6">
        <div className="w-full max-w-sm">
          <div className="mb-8 flex items-center gap-3 lg:hidden">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-brand-from to-brand-to">
              <Shield className="h-4 w-4 text-white" aria-hidden="true" />
            </div>
            <span className="text-lg font-semibold tracking-tight">Cyshield Pro</span>
          </div>

          <h2 className="text-2xl font-semibold tracking-tight">Welcome back</h2>
          <p className="mt-1 text-sm text-muted-foreground">
            Sign in to continue to your workspace.
          </p>

          <Tabs defaultValue="login" className="mt-8">
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="login">Login</TabsTrigger>
              <TabsTrigger value="register">Register</TabsTrigger>
            </TabsList>
            <TabsContent value="login" className="mt-6">
              <LoginForm />
            </TabsContent>
            <TabsContent value="register" className="mt-6">
              <RegisterForm />
            </TabsContent>
          </Tabs>
        </div>
      </main>
    </div>
  );
}
