/**
 * Tech Inventory Enrichment (SBOM)
 *
 * Extracts tech stack / version data from recon_modules and upserts into tech_inventory.
 * Uses two detection strategies:
 *   1. Wappalyzer (simple-wappalyzer, MIT) — 1500+ tech fingerprints from headers + HTML
 *   2. version-parser.ts — precise version extraction from Server/X-Powered-By headers
 */
import { createLogger } from "../logger";
import { storage } from "../storage";
import { extractFromBanner, extractFromHeaders, isEol, type DetectedTech } from "./version-parser";
import { analyzeHosts } from "./wappalyzer-engine";
import type { ReconModule } from "@shared/schema";

const log = createLogger("enrichment:tech-inventory");

interface TechStackData {
  technologies?: string[];
  serverBanners?: Record<string, string>; // host → banner
  allHeaders?: Record<string, Record<string, string>>; // host → headers
  serverInfo?: { server?: string; poweredBy?: string; headers?: Record<string, string> };
}

interface AttackSurfaceData {
  /** Grading-wrapper shape from security header analysis — DO NOT pass to extractFromHeaders */
  perAssetHeaders?: Record<string, Record<string, unknown>>;
  serverBanners?: Record<string, string>;
  /** Flat raw header map added by easm-scan for SBOM enrichment */
  rawHeadersByHost?: Record<string, Record<string, string>>;
  /** Truncated HTML body per host for Wappalyzer */
  htmlByHost?: Record<string, string>;
}

/** Extract tech detections from a single recon module using version-parser. */
export function extractTechFromModule(module: ReconModule): Array<DetectedTech & { host: string }> {
  const results: Array<DetectedTech & { host: string }> = [];
  const target = module.target;

  if (module.moduleType === "tech_stack") {
    const data = module.data as TechStackData;

    // serverBanners: { "api.example.com": "nginx/1.18.0 openssl/1.1.1k", ... }
    const banners = data.serverBanners ?? {};
    for (const [host, banner] of Object.entries(banners)) {
      for (const tech of extractFromBanner(String(banner), "server_banner")) {
        results.push({ ...tech, host });
      }
    }

    // allHeaders: { "example.com": { "server": "nginx/1.18", ... }, ... }
    const allHeaders = data.allHeaders ?? {};
    for (const [host, headers] of Object.entries(allHeaders)) {
      for (const tech of extractFromHeaders(headers as Record<string, string>)) {
        results.push({ ...tech, host });
      }
    }

    // Root serverInfo
    const si = data.serverInfo;
    if (si) {
      if (si.server) {
        for (const tech of extractFromBanner(si.server, "server_header")) {
          results.push({ ...tech, host: target });
        }
      }
      if (si.poweredBy) {
        for (const tech of extractFromBanner(`x-powered-by: ${si.poweredBy}`, "header")) {
          results.push({ ...tech, host: target });
        }
      }
      if (si.headers) {
        for (const tech of extractFromHeaders(si.headers)) {
          results.push({ ...tech, host: target });
        }
      }
    }
  }

  if (module.moduleType === "attack_surface") {
    const data = module.data as AttackSurfaceData;

    // rawHeadersByHost: flat string map (correct shape for extractFromHeaders)
    const rawHeaders = data.rawHeadersByHost ?? {};
    for (const [host, headers] of Object.entries(rawHeaders)) {
      for (const tech of extractFromHeaders(headers)) {
        results.push({ ...tech, host });
      }
    }

    // serverBanners: host → banner string
    const banners = data.serverBanners ?? {};
    for (const [host, banner] of Object.entries(banners)) {
      for (const tech of extractFromBanner(String(banner), "server_banner")) {
        results.push({ ...tech, host });
      }
    }

    // perAssetHeaders is the grading-wrapper shape {header: {present, value}} — skip for version-parser
    // but extract server/x-powered-by value fields defensively
    const perAssetHeaders = data.perAssetHeaders ?? {};
    for (const [host, headers] of Object.entries(perAssetHeaders)) {
      for (const [headerName, val] of Object.entries(headers)) {
        if (val && typeof val === "object" && "value" in val && typeof (val as Record<string, unknown>).value === "string") {
          const value = (val as Record<string, string>).value;
          if (value && (headerName === "server" || headerName === "x-powered-by")) {
            for (const tech of extractFromBanner(`${headerName}: ${value}`, "header")) {
              results.push({ ...tech, host });
            }
          }
        }
      }
    }
  }

  return results;
}

/** Rebuild the tech inventory for a workspace. */
export async function rebuildTechInventory(workspaceId: string): Promise<void> {
  try {
    const [techModules, surfaceModules] = await Promise.all([
      storage.getReconModulesByType(workspaceId, "tech_stack"),
      storage.getReconModulesByType(workspaceId, "attack_surface"),
    ]);

    const allModules = [...techModules, ...surfaceModules];
    const seen = new Set<string>();
    let upserted = 0;

    // Strategy 1: version-parser (precise version extraction)
    for (const module of allModules) {
      const detections = extractTechFromModule(module);
      for (const det of detections) {
        const key = `${det.host}::${det.product}::${det.version ?? ""}`;
        if (seen.has(key)) continue;
        seen.add(key);

        await storage.upsertTechInventory({
          workspaceId,
          host: det.host,
          product: det.product,
          version: det.version ?? null,
          source: det.source,
          confidence: det.confidence,
          eol: isEol(det.product, det.version),
        });
        upserted++;
      }
    }

    // Strategy 2: Wappalyzer (broader coverage from headers + HTML)
    for (const module of surfaceModules) {
      const data = module.data as AttackSurfaceData;
      const rawHeaders = data.rawHeadersByHost ?? {};
      const htmlByHost = data.htmlByHost ?? {};

      if (Object.keys(rawHeaders).length === 0) continue;

      const wapResults = await analyzeHosts(rawHeaders, htmlByHost);

      for (const [host, techs] of Array.from(wapResults.entries())) {
        for (const tech of techs) {
          // Normalize: use slug as product key, lowercased
          const product = tech.slug.toLowerCase();
          const key = `${host}::${product}::${tech.version ?? ""}`;
          if (seen.has(key)) continue;
          seen.add(key);

          await storage.upsertTechInventory({
            workspaceId,
            host,
            product,
            version: tech.version,
            source: "wappalyzer",
            confidence: tech.confidence,
            eol: isEol(product, tech.version ?? null),
          });
          upserted++;
        }
      }
    }

    log.info({ workspaceId, upserted }, "Tech inventory rebuilt");
  } catch (err) {
    log.error({ err, workspaceId }, "Tech inventory rebuild failed");
  }
}
