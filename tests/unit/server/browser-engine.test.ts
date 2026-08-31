import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * The failure this guards against is silent: selecting an engine that does not
 * execute init scripts drops every page-level stealth patch with no error
 * anywhere. `supportsInitScript` is what the caller checks, so it must be
 * correct per engine.
 */

const chromiumStub = { launch: vi.fn() };
vi.mock("playwright", () => ({ chromium: chromiumStub }));

let engine: typeof import("../../../server/evidence/browser-engine");
const originalEnv = process.env.CYSHIELD_BROWSER_ENGINE;

beforeEach(async () => {
  vi.resetModules();
  delete process.env.CYSHIELD_BROWSER_ENGINE;
  engine = await import("../../../server/evidence/browser-engine");
  engine.__resetEngineCache();
});

afterEach(() => {
  if (originalEnv === undefined) delete process.env.CYSHIELD_BROWSER_ENGINE;
  else process.env.CYSHIELD_BROWSER_ENGINE = originalEnv;
});

describe("engine selection", () => {
  it("defaults to stock Playwright", async () => {
    const resolved = await engine.resolveBrowserEngine();
    expect(resolved.name).toBe("stock");
    expect(resolved.enginePatched).toBe(false);
  });

  it("stock executes init scripts, so page-level patches apply", async () => {
    const resolved = await engine.resolveBrowserEngine();
    expect(resolved.supportsInitScript).toBe(true);
  });

  it("falls back to stock when an unknown engine is configured", async () => {
    process.env.CYSHIELD_BROWSER_ENGINE = "not-a-real-engine";
    engine.__resetEngineCache();
    expect((await engine.resolveBrowserEngine()).name).toBe("stock");
  });

  it("falls back to stock when the requested engine is not installed", async () => {
    // Evidence capture is fail-soft: a missing optional dependency must degrade
    // the screenshots, never break report generation.
    process.env.CYSHIELD_BROWSER_ENGINE = "cloakbrowser";
    engine.__resetEngineCache();
    const resolved = await engine.resolveBrowserEngine();
    expect(resolved.name).toBe("stock");
    expect(resolved.note).toMatch(/not installed/i);
  });

  it("memoises the resolved engine", async () => {
    const a = await engine.resolveBrowserEngine();
    const b = await engine.resolveBrowserEngine();
    expect(a).toBe(b);
  });

  it("reports both what was requested and what is active", async () => {
    process.env.CYSHIELD_BROWSER_ENGINE = "cloakbrowser";
    engine.__resetEngineCache();
    const status = await engine.browserEngineStatus();
    // The gap between the two is the thing an operator needs to see.
    expect(status.requested).toBe("cloakbrowser");
    expect(status.active).toBe("stock");
  });

  it("exposes a launcher with Playwright's shape", async () => {
    const resolved = await engine.resolveBrowserEngine();
    expect(typeof resolved.chromium.launch).toBe("function");
  });
});

describe("patchright init-script trap", () => {
  it("marks patchright as NOT supporting init scripts", async () => {
    // Measured on patchright 1.62.2: addInitScript resolves without error and
    // the script never runs, because Runtime.enable is patched out. Reporting
    // this as supported would silently disable every page-level patch.
    vi.doMock("patchright", () => ({ chromium: { launch: vi.fn() } }));
    process.env.CYSHIELD_BROWSER_ENGINE = "patchright";
    vi.resetModules();

    const mod = await import("../../../server/evidence/browser-engine");
    mod.__resetEngineCache();
    const resolved = await mod.resolveBrowserEngine();

    expect(resolved.name).toBe("patchright");
    expect(resolved.enginePatched).toBe(true);
    expect(resolved.supportsInitScript).toBe(false);
    expect(resolved.note).toMatch(/no-op/i);
  });

  it("marks cloakbrowser as supporting init scripts", async () => {
    // It patches the binary and leaves the CDP domains intact.
    vi.doMock("cloakbrowser", () => ({ chromium: { launch: vi.fn() } }));
    process.env.CYSHIELD_BROWSER_ENGINE = "cloakbrowser";
    vi.resetModules();

    const mod = await import("../../../server/evidence/browser-engine");
    mod.__resetEngineCache();
    const resolved = await mod.resolveBrowserEngine();

    expect(resolved.name).toBe("cloakbrowser");
    expect(resolved.supportsInitScript).toBe(true);
    // The licence constraint must stay visible to whoever turns this on.
    expect(resolved.note).toMatch(/licen[cs]ed/i);
  });
});
