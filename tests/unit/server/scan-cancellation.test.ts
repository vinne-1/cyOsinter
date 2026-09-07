/**
 * Scan cancellation.
 *
 * The scanner was threaded for this end to end — `checkAborted(signal)` between
 * phases, `signal` passed into every `runWithConcurrency` — but
 * `scanOptions.signal` was hardcoded `undefined` and no route ever asked to
 * cancel. The entire mechanism was unreachable, so a Gold scan aimed at the
 * wrong domain ran its full thirty-plus minutes with no way to stop the
 * outbound traffic it was generating.
 *
 * These cover the registry and the abort semantics the scanner relies on. The
 * route's authorization is covered by `bare-id-authorization.test.ts`, which
 * scans for exactly this shape of route.
 */
import { describe, it, expect, vi } from "vitest";

vi.mock("../../../server/logger", () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));
vi.mock("../../../server/db", () => ({ db: {}, pool: {} }));
vi.mock("../../../server/storage", () => ({ storage: {} }));

/*
 * Imported statically, NOT via `vi.resetModules()` + dynamic import in a
 * `beforeEach`.
 *
 * That pattern re-imported scan-trigger's whole transitive graph — the entire
 * scanner — once per test, and the cost grows every time a module is added to
 * the engine. Adding the client-side library check was enough to push the hook
 * past its 10s timeout under parallel workers, producing an intermittent
 * failure with no relation to the code under test. The same trap was already
 * hit once by the SLA monitor's tests.
 *
 * Nothing here mutates scan-trigger's module state, so there was never anything
 * for the reset to isolate.
 */
import * as trigger from "../../../server/scan-trigger";

describe("cancellation registry", () => {
  it("reports a scan it does not know about as not running here", () => {
    expect(trigger.isScanRunningHere("never-started")).toBe(false);
  });

  /**
   * The caller has to be able to tell "I stopped it" from "it was not running",
   * because the two need different follow-up: the first lets the scan's own
   * error path write the final row, the second means the route must write it.
   */
  it("returns false when asked to cancel a scan that is not running here", () => {
    expect(trigger.requestScanCancellation("not-running")).toBe(false);
  });
});

/**
 * The contract the scanner depends on: `checkAborted` throws a message
 * containing "aborted", and the trigger keys the `cancelled` status off that.
 * If either side changes wording independently, a cancellation silently becomes
 * a failure again — which is what puts a deliberate operator action into the
 * failure count every dashboard reads.
 */
describe("abort signalling contract", () => {
  it("checkAborted throws only once the signal fires, with an 'aborted' message", async () => {
    const { checkAborted } = await import("../../../server/scanner/constants");
    const controller = new AbortController();

    expect(() => checkAborted(controller.signal)).not.toThrow();
    controller.abort();
    expect(() => checkAborted(controller.signal)).toThrow(/abort/i);
  });

  it("treats no signal at all as 'not aborted' rather than throwing", async () => {
    const { checkAborted } = await import("../../../server/scanner/constants");
    expect(() => checkAborted(undefined)).not.toThrow();
  });

  it("the message a cancelled scan produces is classified as cancelled, not failed", async () => {
    const { checkAborted } = await import("../../../server/scanner/constants");
    const controller = new AbortController();
    controller.abort();

    let raw = "";
    try { checkAborted(controller.signal); } catch (e) { raw = e instanceof Error ? e.message : String(e); }

    // Mirrors the discriminator in scan-trigger's catch block.
    expect(/aborted/i.test(raw)).toBe(true);
    // And must NOT look like the DNS-failure case, which is a real failure.
    expect(/ENOTFOUND|EAI_AGAIN|getaddrinfo/i.test(raw)).toBe(false);
  });
});

/**
 * `runWithConcurrency` is where most of a scan's outbound work happens, so an
 * abort has to stop it rather than merely being recorded.
 */
describe("in-flight work stops on abort", () => {
  it("stops dispatching new work once the signal fires", async () => {
    const { runWithConcurrency } = await import("../../../server/scanner/utils");
    const controller = new AbortController();
    const started: number[] = [];

    const items = Array.from({ length: 50 }, (_, i) => i);
    const run = runWithConcurrency(items, 2, async (i) => {
      started.push(i);
      if (started.length === 4) controller.abort();
      return i;
    }, controller.signal);

    await run.catch(() => { /* abort may reject; either is acceptable */ });

    // The point: it stopped early rather than working through all fifty.
    expect(started.length).toBeLessThan(items.length);
  });
});
