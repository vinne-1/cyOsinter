/**
 * Pluggable browser engine for evidence capture.
 *
 * Stealth tooling moves fast and each option carries a different licence and a
 * different Docker footprint, so the engine is selected at runtime rather than
 * hardcoded. Every option exposes Playwright's API, so the calling code is
 * identical whichever is chosen.
 *
 * ── The options, and what each actually costs ───────────────────────────────
 *
 *  stock        Bundled Playwright plus our own patches (browser-stealth.ts).
 *               Apache-2.0, no extra download, already in the image.
 *               Measured: removes 6/6 common automation signals.
 *               DEFAULT — nothing to install, nothing to license.
 *
 *  patchright   Apache-2.0, npm `patchright`. A patched Playwright driver that
 *               runs STOCK Chromium (it reuses the Playwright browser already in
 *               the image — no extra download) and hides the CDP control channel.
 *
 *               TRADE-OFF, measured on 1.62.2: because it removes the
 *               `Runtime.enable` domain, `addInitScript` silently becomes a
 *               no-op. Our page-level patches — plugins, languages, permissions,
 *               WebGL vendor — therefore do NOT apply under it, and on a
 *               side-by-side probe stock+patches scored better on those surfaces
 *               than patchright did. It is a genuine upgrade only for targets
 *               that fingerprint the CDP channel itself, and only once the page
 *               patches are re-applied through CDP directly.
 *
 *  cloakbrowser npm `cloakbrowser`. The WRAPPER is MIT, but the Chromium binary
 *               is NOT: per its BINARY-LICENSE, v146 is free for use while
 *               v148+ requires a paid Pro subscription, and REDISTRIBUTION IS
 *               NOT PERMITTED in any version.
 *
 *               Three consequences, all deliberate reasons this is not the
 *               default:
 *                 1. We cannot bake the binary into our Docker image — that is
 *                    redistribution. It must self-download (~200MB) at runtime.
 *                 2. Current versions are a recurring cost, which conflicts
 *                    with keeping this platform free to self-host.
 *                 3. It is a third-party binary executing inside a security
 *                    product. It is signature-verified by its own installer,
 *                    but that is the vendor attesting to itself.
 *
 *               Enable it deliberately, never by default.
 *
 * Selection: CYSHIELD_BROWSER_ENGINE = stock | patchright | cloakbrowser
 */

import { createLogger } from "../logger";

const log = createLogger("browser-engine");

export type EngineName = "stock" | "patchright" | "cloakbrowser";

/** The slice of Playwright's API the evidence capture actually uses. */
export interface BrowserLauncher {
  launch(options: {
    headless?: boolean;
    executablePath?: string;
    args?: string[];
  }): Promise<unknown>;
}

export interface ResolvedEngine {
  name: EngineName;
  chromium: BrowserLauncher;
  /**
   * True when the engine patches automation signals in the driver or the binary
   * itself, rather than from the page.
   */
  enginePatched: boolean;
  /**
   * Whether `context.addInitScript` actually executes.
   *
   * MEASURED, not assumed: patchright 1.62.2 accepts an init script without
   * error and then never runs it, because it patches out the `Runtime.enable`
   * CDP domain that init scripts depend on. `page.evaluate` still works, so the
   * failure is completely silent — flipping the engine would drop every
   * page-level patch (plugins, languages, permissions, WebGL) with no warning
   * and no error.
   *
   * The caller must check this before relying on init-script patches.
   */
  supportsInitScript: boolean;
  /** Why this engine was chosen, or why a requested one was not used. */
  note: string;
}

function requestedEngine(): EngineName {
  const raw = (process.env.CYSHIELD_BROWSER_ENGINE ?? "stock").trim().toLowerCase();
  if (raw === "patchright" || raw === "cloakbrowser" || raw === "stock") return raw;
  log.warn({ raw }, "Unknown CYSHIELD_BROWSER_ENGINE; falling back to stock");
  return "stock";
}

let cached: ResolvedEngine | null = null;

/**
 * Resolves the configured engine, falling back to stock when the requested one
 * is not installed.
 *
 * Falling back rather than throwing is deliberate: evidence capture is already
 * fail-soft, and a missing optional dependency must degrade the screenshots,
 * never break report generation.
 */
export async function resolveBrowserEngine(): Promise<ResolvedEngine> {
  if (cached) return cached;

  const want = requestedEngine();

  if (want !== "stock") {
    try {
      // Imported by name at runtime so the package is a genuine optional
      // dependency: absent from package.json, absent from the image, and the
      // build does not require it to exist.
      const mod = (await import(/* @vite-ignore */ want)) as { chromium?: BrowserLauncher };
      if (!mod?.chromium) throw new Error(`${want} did not export a chromium launcher`);

      cached = {
        name: want,
        chromium: mod.chromium,
        enginePatched: true,
        // patchright disables init scripts as a side effect of removing
        // Runtime.enable. CloakBrowser patches the binary and leaves CDP alone,
        // so init scripts still run there.
        supportsInitScript: want !== "patchright",
        note:
          want === "cloakbrowser"
            ? "CloakBrowser active — binary is separately licensed and self-downloaded, not redistributed in this image"
            : "Patchright active — driver-level stealth over stock Chromium. NOTE: addInitScript is silently a no-op, so page-level patches do not apply.",
      };
      log.info({ engine: want }, "Stealth browser engine active");
      return cached;
    } catch (err) {
      log.warn(
        { engine: want, err: err instanceof Error ? err.message : String(err) },
        `${want} is not installed; falling back to stock Playwright`,
      );
    }
  }

  const { chromium } = await import("playwright");
  cached = {
    name: "stock",
    chromium: chromium as unknown as BrowserLauncher,
    enginePatched: false,
    supportsInitScript: true,
    note:
      want === "stock"
        ? "Stock Playwright with page-level stealth patches"
        : `Requested ${want} but it is not installed; using stock Playwright`,
  };
  return cached;
}

/** Clears the memoised engine. For tests and for config reloads. */
export function __resetEngineCache(): void {
  cached = null;
}

/** Engine status, for the admin doctor endpoint. */
export async function browserEngineStatus(): Promise<{
  requested: EngineName;
  active: EngineName;
  enginePatched: boolean;
  supportsInitScript: boolean;
  note: string;
}> {
  const resolved = await resolveBrowserEngine();
  return {
    requested: requestedEngine(),
    active: resolved.name,
    enginePatched: resolved.enginePatched,
    supportsInitScript: resolved.supportsInitScript,
    note: resolved.note,
  };
}
