import { Router } from "express";
import { storage } from "../storage";
import { createLogger } from "../logger";
import { requireWorkspaceRole } from "./auth-middleware";
import { rebuildTechInventory } from "../enrichment/tech-inventory";
import { sendError } from "./response";

const log = createLogger("routes:tech-inventory");
export const techInventoryRouter = Router();

// GET /api/workspaces/:workspaceId/tech-inventory
techInventoryRouter.get(
  "/workspaces/:workspaceId/tech-inventory",
  requireWorkspaceRole("owner", "admin", "analyst", "viewer"),
  async (req, res) => {
    try {
      const workspaceId = String(req.params.workspaceId);
      const items = await storage.getTechInventory(workspaceId);

      // Group by product for easier consumption
      const byProduct = new Map<string, {
        product: string;
        versions: Array<{ version: string | null; hosts: string[]; eol: boolean; source: string }>;
        eolCount: number;
      }>();

      for (const item of items) {
        const entry = byProduct.get(item.product) ?? { product: item.product, versions: [], eolCount: 0 };
        entry.versions.push({ version: item.version, hosts: [item.host], eol: item.eol ?? false, source: item.source });
        if (item.eol) entry.eolCount++;
        byProduct.set(item.product, entry);
      }

      res.json({
        total: items.length,
        products: Array.from(byProduct.values()).sort((a, b) => b.eolCount - a.eolCount || a.product.localeCompare(b.product)),
        items,
      });
    } catch (err) {
      log.error({ err }, "Tech inventory error");
      return sendError(res, 500, "Internal error");
    }
  },
);

// GET /api/workspaces/:workspaceId/tech-inventory/eol
techInventoryRouter.get(
  "/workspaces/:workspaceId/tech-inventory/eol",
  requireWorkspaceRole("owner", "admin", "analyst", "viewer"),
  async (req, res) => {
    try {
      const workspaceId = String(req.params.workspaceId);
      const items = await storage.getTechInventory(workspaceId);
      const eolItems = items.filter((i) => i.eol);
      res.json(eolItems);
    } catch (err) {
      log.error({ err }, "EOL tech inventory error");
      return sendError(res, 500, "Internal error");
    }
  },
);

// GET /api/workspaces/:workspaceId/tech-inventory/sprawl
// Products with more than one distinct version
techInventoryRouter.get(
  "/workspaces/:workspaceId/tech-inventory/sprawl",
  requireWorkspaceRole("owner", "admin", "analyst", "viewer"),
  async (req, res) => {
    try {
      const workspaceId = String(req.params.workspaceId);
      const items = await storage.getTechInventory(workspaceId);

      const versionsByProduct = new Map<string, Set<string>>();
      for (const item of items) {
        if (!item.version) continue;
        const s = versionsByProduct.get(item.product) ?? new Set();
        s.add(item.version);
        versionsByProduct.set(item.product, s);
      }

      const sprawl = Array.from(versionsByProduct.entries())
        .filter(([, v]) => v.size > 1)
        .map(([product, versions]) => ({ product, versionCount: versions.size, versions: Array.from(versions) }))
        .sort((a, b) => b.versionCount - a.versionCount);

      res.json(sprawl);
    } catch (err) {
      log.error({ err }, "Tech sprawl error");
      return sendError(res, 500, "Internal error");
    }
  },
);

// POST /api/workspaces/:workspaceId/tech-inventory/refresh
techInventoryRouter.post(
  "/workspaces/:workspaceId/tech-inventory/refresh",
  requireWorkspaceRole("owner", "admin", "analyst"),
  async (req, res) => {
    try {
      const workspaceId = String(req.params.workspaceId);
      rebuildTechInventory(workspaceId).catch((err) =>
        log.warn({ err, workspaceId }, "Manual tech inventory refresh failed"),
      );
      res.json({ message: "Tech inventory refresh started" });
    } catch (err) {
      log.error({ err }, "Tech inventory refresh trigger error");
      return sendError(res, 500, "Internal error");
    }
  },
);
