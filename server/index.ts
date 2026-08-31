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
import { pool } from "./db";
import { PostgresRateLimitStore, startRateLimitCleanup, stopRateLimitCleanup } from "./rate-limit-store";

const app = express();
const httpServer = createServer(app);

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
app.use(
  helmet({
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
app.use("/api/", rateLimit({ windowMs: 60_000, max: 100, standardHeaders: true, legacyHeaders: false }));

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
// Lookalike sweeps fan out hundreds of DNS lookups; limit them like scans.
app.use("/api/workspaces/:id/brand-threats", rateLimit({ windowMs: 60_000, max: 5, message: { message: "Too many brand threat scans, please try again later" } }));
// The leak-site corpus is a large third-party download; be a good citizen.
app.use("/api/workspaces/:id/ransomware-exposure", rateLimit({ windowMs: 60_000, max: 5, message: { message: "Too many exposure checks, please try again later" } }));
// GitHub code search allows 10 requests/minute; stay well inside it.
app.use("/api/workspaces/:id/code-leaks", rateLimit({ windowMs: 60_000, max: 2, message: { message: "Too many code leak sweeps, please try again later" } }));

// Stricter rate limits for AI/enrichment endpoints (expensive, long-running)
const aiRateLimit = rateLimit({ windowMs: 60_000, max: 3, message: { message: "Too many AI requests, please try again later" } });
app.use("/api/workspaces/:id/ai-insights", aiRateLimit);
app.use("/api/workspaces/:id/findings/enrich-all", aiRateLimit);
app.use("/api/workspaces/:id/imports/:id/consolidate", aiRateLimit);

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
