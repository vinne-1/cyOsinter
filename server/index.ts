import "dotenv/config";
import express, { type Request, Response, NextFunction } from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { createLogger } from "./logger";
import { registerRoutes } from "./routes";
import { serveStatic } from "./static";
import { createServer } from "http";
import { seedDatabase } from "./seed";
import { initNotifications } from "./notifications";
import { startScheduler, registerScanTrigger, stopScheduler } from "./scan-scheduler";
import { triggerScan } from "./scan-trigger";
import { startQueuePoller, stopQueuePoller } from "./scan-queue";
import { startSlaMonitor, stopSlaMonitor } from "./sla-monitor";
import { startRetentionSweep, stopRetentionSweep } from "./retention-sweep";
import { pool } from "./db";
import { PostgresRateLimitStore, startRateLimitCleanup, stopRateLimitCleanup } from "./rate-limit-store";

const app = express();
const httpServer = createServer(app);

/*
 * Whether to believe `X-Forwarded-For`.
 *
 * This is off by default and MUST be turned on when the app runs behind a
 * reverse proxy, because everything that identifies a caller by address depends
 * on it. Express sets `req.ip` from the socket unless told otherwise, so behind
 * a proxy every request appears to come from the proxy:
 *
 *  - the per-IP limiters (login 10/min, register 3/min) collapse into ONE bucket
 *    for the entire deployment — the login limiter exists to slow credential
 *    stuffing, and shared like that it instead locks out every legitimate user
 *    once any attacker spends the budget;
 *  - `audit_logs.ip_address` records the proxy for every entry, so the trail
 *    cannot say where an action came from.
 *
 * It is not simply enabled by default because that is the opposite failure: with
 * no proxy in front, `X-Forwarded-For` is attacker-controlled, and trusting it
 * lets anyone bypass those same per-IP limits by varying a header. Only the
 * operator knows which deployment this is, so only the operator can say.
 *
 * Accepts express's own syntax: `true`, a hop count, or a comma-separated list
 * of trusted IPs/CIDRs (preferred — `TRUST_PROXY=10.0.0.0/8`).
 */
const trustProxy = process.env.TRUST_PROXY?.trim();
if (trustProxy) {
  const value = trustProxy === "true"
    ? true
    : /^\d+$/.test(trustProxy)
      ? Number(trustProxy)
      : trustProxy.split(",").map((v) => v.trim()).filter(Boolean);
  app.set("trust proxy", value);
}

declare module "http" {
  interface IncomingMessage {
    rawBody: unknown;
  }
}

// Security headers — disable CSP in dev (Vite HMR needs full access), enforce in production.
// NOTE: helmet injects `upgrade-insecure-requests` into its default CSP. This app is
// self-hosted and routinely served over plain HTTP on a LAN IP/host, where that directive
// forces the browser to fetch same-origin assets over HTTPS (which the HTTP server can't
// answer) → ERR_SSL_PROTOCOL_ERROR and a blank page. `localhost` is exempt; a bare IP is
// not. We disable that one directive (set to null) so the rest of the CSP still applies.
// HSTS is likewise disabled: over HTTP it's ignored anyway, and it would pin HTTPS on hosts
// that have no TLS. Front this app with a TLS-terminating reverse proxy for HTTPS in prod.
/*
 * HSTS is applied only to responses that actually arrived over TLS.
 *
 * It used to be off unconditionally, with sound reasoning: this app is often
 * self-hosted over plain HTTP on a LAN, and an HSTS header pins HTTPS for a year
 * on a host that may have no TLS at all — locking operators out of their own
 * install. But "off always" also means an operator who DOES front it with a
 * TLS-terminating proxy gets no HSTS, which is exactly the deployment that needs
 * it (ASVS 5.0 V3.4.1).
 *
 * `req.secure` answers the question directly and per-request: true for a direct
 * TLS connection, and true behind a proxy that sets `X-Forwarded-Proto: https`
 * — provided TRUST_PROXY is configured, which that deployment must set anyway
 * for rate limiting and audit attribution to work. A plain-HTTP LAN install
 * never sees the header, so nothing is pinned and nobody is locked out.
 *
 * A browser ignores HSTS on a plain-HTTP response anyway, so this is not merely
 * caution — sending it there would be meaningless as well as risky.
 */
const hstsPolicy = helmet.hsts({
  maxAge: 31_536_000, // one year — the ASVS V3.4.1 minimum
  includeSubDomains: true,
  preload: false, // preloading is irreversible for a domain; the operator's call
});
app.use((req, res, next) => (req.secure ? hstsPolicy(req, res, next) : next()));

app.use(
  helmet({
    // Handled per-request above, so helmet's unconditional header is off here.
    hsts: false,
    contentSecurityPolicy: process.env.NODE_ENV === "production" ? {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "blob:"],
        connectSrc: ["'self'", "ws:", "wss:"],
        upgradeInsecureRequests: null,
      },
    } : false,
  }),
);

app.use(
  express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  }),
);

app.use(express.urlencoded({ extended: false }));

// ── Rate limiting ──
// The general throttle stays in-memory on purpose: it is approximate by nature,
// and a database round trip on EVERY api request is not worth the precision.
//
// 600/min, not 100. This is a data-dense SPA: the dashboard alone fires 10
// queries, and browsing eight pages measured 51 requests in 12 seconds — about
// 254/min at a normal pace. At 100 an analyst hit 429 after roughly fifteen
// page views, which looked like the app breaking. This is a blunt
// denial-of-service guard, NOT an authentication control: login, register and
// scan each have their own far tighter limits backed by a shared Postgres
// counter, so raising this ceiling costs no real protection.
app.use("/api/", rateLimit({ windowMs: 60_000, max: 600, standardHeaders: true, legacyHeaders: false }));

// The sensitive limiters are shared through Postgres. With the default
// MemoryStore these were per-process, so "5 login attempts per minute" became
// 5 × replicas — precisely backwards for the one limit whose job is to slow
// credential stuffing.
// 10/min, NOT 5. The per-account lockout in server/auth.ts also trips at 5
// failures, and this middleware runs first — so at an equal threshold the IP
// limiter always fired first and replaced the lockout's actionable message
// ("Try again in 1 minute") with a generic one, leaving the user no idea why
// they were blocked or for how long. Leaving headroom lets the precise control
// speak. This limiter stays as the blunt guard against a single IP spraying
// many different accounts, which the per-account lockout cannot see.
app.use("/api/auth/login", rateLimit({
  windowMs: 60_000, max: 10,
  store: new PostgresRateLimitStore("login"),
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Too many sign-in attempts from this address. Wait a minute and try again." },
}));
// SSO is an unauthenticated, session-minting surface reached over the same
// threat model as password login, so it gets the same shared-store treatment.
// The path-prefix limiter above does NOT cover it: `/api/auth/sso/login` does
// not start with `/api/auth/login`, so without this it had only the blunt
// 600/min guard. `/sso/login` also starts an outbound round trip to the IdP and
// records a pending-login entry, so an unlimited one is a way to spend somebody
// else's IdP quota as well as this server's memory.
app.use("/api/auth/sso", rateLimit({
  windowMs: 60_000, max: 20,
  store: new PostgresRateLimitStore("sso"),
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Too many single sign-on attempts from this address. Wait a minute and try again." },
}));
// Anti-automation on password change (ASVS V6.3.1). Authenticated, so this is
// not the credential-stuffing surface login is — but it verifies a password, and
// an endpoint that verifies a password is an oracle for guessing one.
app.use("/api/auth/change-password", rateLimit({
  windowMs: 60_000, max: 10,
  store: new PostgresRateLimitStore("change-password"),
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Too many password change attempts. Wait a minute and try again." },
}));
app.use("/api/auth/register", rateLimit({
  windowMs: 60_000, max: 3,
  store: new PostgresRateLimitStore("register"),
  message: { message: "Too many registration attempts, please try again later" },
}));
app.use("/api/scans", rateLimit({
  windowMs: 60_000, max: 5,
  store: new PostgresRateLimitStore("scans"),
  message: { message: "Too many scan requests, please try again later" },
}));
// Brand-threat sweep limiters moved to routes/brand-threats.ts, applied
// directly to each POST handler rather than mounted here by path.
//
// `app.use(path, limiter)` matches every HTTP method at that path, and
// GET and POST are the SAME path for brand-threats/ransomware-exposure/
// code-leaks (differentiated only by verb, unlike ai-insights's GET
// `/ai-insights` vs POST `/ai-insights/summary`, where a longer sub-path
// let the limiter target just the POST). Mounting here meant the cheap
// read-only GET — which just returns the last stored recon_module, no
// external call — shared its budget with the expensive sweep: reading
// your own code-leak result twice inside a minute answered "Too many code
// leak sweeps, please try again later" for a request that ran no sweep at
// all. Same failure this file already documents for `/ai-insights`.

// Stricter rate limits for AI/enrichment endpoints (expensive, long-running)
const aiRateLimit = rateLimit({ windowMs: 60_000, max: 3, message: { message: "Too many AI requests, please try again later" } });
/*
 * Limit the INFERENCE path, not the panel's data fetch.
 *
 * `app.use` mounts by PREFIX, so `/ai-insights` also covered
 * `GET /ai-insights` — which runs no model at all, it reads findings and recon
 * modules out of Postgres and returns them. Sharing a 3/min budget with a
 * 30-minute Ollama call meant an operator flipping between four workspaces in a
 * minute got **"Too many AI requests"** for requests that used no AI, and the
 * message sent them to debug the wrong thing — the same failure this codebase
 * documents for `no-domain` vs `corpus-unreachable`.
 *
 * Every path listed below calls a model; `GET .../attack-paths` (the
 * deterministic playbook match, no AI) is deliberately NOT listed, for the
 * same reason.
 */
app.use("/api/workspaces/:id/ai-insights/summary", aiRateLimit);
app.use("/api/workspaces/:id/findings/enrich-all", aiRateLimit);
app.use("/api/workspaces/:id/imports/:id/consolidate", aiRateLimit);
app.use("/api/workspaces/:id/attack-paths/:playbookId/explain", aiRateLimit);
app.use("/api/workspaces/:id/compliance/:framework/explain", aiRateLimit);
app.use("/api/reports/:id/qa-review", aiRateLimit);
app.use("/api/workspaces/:id/trends/explain", aiRateLimit);
app.use("/api/workspaces/:id/brand-threats/explain", aiRateLimit);
app.use("/api/scans/:id1/diff/:id2/explain", aiRateLimit);
app.use("/api/asset-risk/explain", aiRateLimit);
app.use("/api/workspaces/:id/assistant/chat", aiRateLimit);

const httpLog = createLogger("http");

export function log(message: string, source = "express") {
  httpLog.info({ source }, message);
}

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      const size = res.getHeader("content-length") ?? "?";
      log(`${req.method} ${path} ${res.statusCode} in ${duration}ms :: ${size}b`);
    }
  });

  next();
});

(async () => {
  await seedDatabase();

  // Reconcile orphaned scans: any scan left "running"/"pending" by a previous
  // process (crash, deploy, or container restart) can never resume and would
  // otherwise block new scans for the same target forever. Mark them failed.
  try {
    const { rowCount } = await pool.query(
      "UPDATE scans SET status = 'failed', error_message = 'Interrupted by server restart', completed_at = now() WHERE status IN ('running', 'pending')",
    );
    if (rowCount && rowCount > 0) {
      createLogger("startup").info({ count: rowCount }, "Reconciled orphaned scans left running from a previous process");
    }
  } catch (err) {
    createLogger("startup").error({ err }, "Failed to reconcile orphaned scans on startup");
  }

  initNotifications(httpServer);
  registerScanTrigger(triggerScan);
  await registerRoutes(httpServer, app);
  startScheduler();
  // The poller was never started, so the queue table would only ever be drained
  // by the instance that enqueued the job. It also reclaims leases from workers
  // that died mid-scan.
  startQueuePoller();
  // Marks findings that blow their remediation deadline. The sweep existed but
  // was never scheduled, so every finding read sla_breached = false forever.
  startSlaMonitor();

  // Applies each workspace's configured data-retention policy. Without this
  // the policy was only ever enforced if a superadmin called the admin route
  // by hand, i.e. never — see server/retention-sweep.ts.
  startRetentionSweep();
  startRateLimitCleanup();

  app.use((err: any, _req: Request, res: Response, next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    httpLog.error({ err, status }, "Internal Server Error");

    if (res.headersSent) {
      return next(err);
    }

    return res.status(status).json({ message });
  });

  // importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (process.env.NODE_ENV === "production") {
    serveStatic(app);
  } else {
    const { setupVite } = await import("./vite");
    await setupVite(httpServer, app);
  }

  // ALWAYS serve the app on the port specified in the environment variable PORT
  // Other ports are firewalled. Default to 5000 if not specified.
  // this serves both the API and the client.
  // It is the only port that is not firewalled.
  const rawPort = parseInt(process.env.PORT || "5000", 10);
  const port = (rawPort >= 1 && rawPort <= 65535) ? rawPort : 5000;
  httpServer.listen(
    {
      port,
      host: "0.0.0.0",
    },
    () => {
      log(`serving on port ${port}`);
    },
  ).on("error", (err: NodeJS.ErrnoException) => {
    if (err.code === "EADDRINUSE") {
      httpLog.error({ port }, "Port is already in use. Set a different PORT env variable.");
    } else {
      httpLog.error({ err }, "Server listen error");
    }
    process.exit(1);
  });

  // ── Graceful shutdown ──
  let shuttingDown = false;
  async function shutdown(signal: string) {
    if (shuttingDown) return;
    shuttingDown = true;
    httpLog.info({ signal }, "Shutting down gracefully…");

    const timeout = setTimeout(() => {
      httpLog.error("Shutdown timed out after 10s, forcing exit");
      process.exit(1);
    }, 10_000);

    try {
      stopScheduler();
      stopQueuePoller();
      stopSlaMonitor();
      // Was omitted while its four siblings were stopped, so the daily interval
      // kept the event loop alive past shutdown.
      stopRetentionSweep();
      stopRateLimitCleanup();
      await new Promise<void>((resolve) => httpServer.close(() => resolve()));
      await pool.end();
      httpLog.info("Shutdown complete");
    } catch (err) {
      httpLog.error({ err }, "Error during shutdown");
    } finally {
      clearTimeout(timeout);
      process.exit(0);
    }
  }

  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("unhandledRejection", (reason) => {
    httpLog.error({ err: reason }, "Unhandled promise rejection");
  });
})();
