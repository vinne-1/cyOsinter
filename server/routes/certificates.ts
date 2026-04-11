import { Router } from "express";
import { z } from "zod";
import { storage } from "../storage";
import { createLogger } from "../logger";
import { requireWorkspaceRole } from "./auth-middleware";
import { rebuildCertInventory } from "../enrichment/cert-inventory";
import { sendError } from "./response";

const log = createLogger("routes:certificates");
export const certificatesRouter = Router();

// GET /api/workspaces/:workspaceId/certificates
certificatesRouter.get(
  "/workspaces/:workspaceId/certificates",
  requireWorkspaceRole("owner", "admin", "analyst", "viewer"),
  async (req, res) => {
    try {
      const workspaceId = String(req.params.workspaceId);
      const expiringWithinDays = req.query.expiringWithin
        ? parseInt(String(req.query.expiringWithin), 10)
        : undefined;

      const certs = await storage.getCertificates(workspaceId, { expiringWithinDays });
      res.json(certs);
    } catch (err) {
      log.error({ err }, "List certificates error");
      return sendError(res, 500, "Internal error");
    }
  },
);

// GET /api/workspaces/:workspaceId/certificates/expiry-calendar
certificatesRouter.get(
  "/workspaces/:workspaceId/certificates/expiry-calendar",
  requireWorkspaceRole("owner", "admin", "analyst", "viewer"),
  async (req, res) => {
    try {
      const workspaceId = String(req.params.workspaceId);
      const certs = await storage.getCertificates(workspaceId);
      const now = Date.now();

      const buckets: Record<string, typeof certs> = {
        expired: [],
        days7: [],
        days14: [],
        days30: [],
        days60: [],
        days90: [],
        healthy: [],
      };

      for (const cert of certs) {
        if (!cert.validTo) continue;
        const days = Math.ceil((new Date(cert.validTo).getTime() - now) / 86_400_000);
        if (days <= 0) buckets.expired.push(cert);
        else if (days <= 7) buckets.days7.push(cert);
        else if (days <= 14) buckets.days14.push(cert);
        else if (days <= 30) buckets.days30.push(cert);
        else if (days <= 60) buckets.days60.push(cert);
        else if (days <= 90) buckets.days90.push(cert);
        else buckets.healthy.push(cert);
      }

      res.json({
        total: certs.length,
        buckets: Object.fromEntries(
          Object.entries(buckets).map(([k, v]) => [k, { count: v.length, certs: v }]),
        ),
      });
    } catch (err) {
      log.error({ err }, "Expiry calendar error");
      return sendError(res, 500, "Internal error");
    }
  },
);

// GET /api/workspaces/:workspaceId/certificates/shared
// Returns certs where the same fingerprint is seen on multiple hosts
certificatesRouter.get(
  "/workspaces/:workspaceId/certificates/shared",
  requireWorkspaceRole("owner", "admin", "analyst", "viewer"),
  async (req, res) => {
    try {
      const workspaceId = String(req.params.workspaceId);
      const certs = await storage.getCertificates(workspaceId);

      const byFingerprint = new Map<string, typeof certs>();
      for (const c of certs) {
        if (!c.fingerprint) continue;
        const existing = byFingerprint.get(c.fingerprint) ?? [];
        existing.push(c);
        byFingerprint.set(c.fingerprint, existing);
      }

      const shared = Array.from(byFingerprint.values())
        .filter((group) => group.length > 1)
        .map((group) => ({ fingerprint: group[0].fingerprint, hosts: group.map((c) => c.host), cert: group[0] }));

      res.json(shared);
    } catch (err) {
      log.error({ err }, "Shared certs error");
      return sendError(res, 500, "Internal error");
    }
  },
);

// POST /api/workspaces/:workspaceId/certificates/refresh
// Trigger manual rebuild of certificate inventory
certificatesRouter.post(
  "/workspaces/:workspaceId/certificates/refresh",
  requireWorkspaceRole("owner", "admin", "analyst"),
  async (req, res) => {
    try {
      const workspaceId = String(req.params.workspaceId);
      rebuildCertInventory(workspaceId).catch((err) =>
        log.warn({ err, workspaceId }, "Manual cert refresh failed"),
      );
      res.json({ message: "Certificate inventory refresh started" });
    } catch (err) {
      log.error({ err }, "Cert refresh trigger error");
      return sendError(res, 500, "Internal error");
    }
  },
);
