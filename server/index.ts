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
import { startScheduler, registerScanTrigger } from "./scan-scheduler";
import { triggerScan } from "./scan-trigger";

const app = express();
const httpServer = createServer(app);

declare module "http" {
  interface IncomingMessage {
    rawBody: unknown;
  }
}

// Security headers — disable CSP in dev (Vite HMR needs full access), enforce in production
app.use(
  helmet({
    contentSecurityPolicy: process.env.NODE_ENV === "production" ? {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "blob:"],
        connectSrc: ["'self'", "ws:", "wss:"],
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

// Rate limiting
app.use("/api/", rateLimit({ windowMs: 60_000, max: 100, standardHeaders: true, legacyHeaders: false }));
app.use("/api/scans", rateLimit({ windowMs: 60_000, max: 5, message: { message: "Too many scan requests, please try again later" } }));

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
  initNotifications(httpServer);
  registerScanTrigger(triggerScan);
  await registerRoutes(httpServer, app);
  startScheduler();

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
  const port = parseInt(process.env.PORT || "5000", 10);
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
})();
