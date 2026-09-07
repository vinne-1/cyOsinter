/**
 * API key scope enforcement.
 *
 * `api_keys.scope` was validated on create, stored, returned by the list
 * endpoint and rendered as a badge in the UI — and enforced nowhere. A key an
 * operator deliberately created as "read" carried its owner's full authority,
 * so it could delete workspaces and revoke other keys. The UI showing "read"
 * next to it made that worse than having no scopes: the product asserted a
 * restriction it did not apply.
 *
 * These tests are mostly REFUSALS, because the whole value of the feature is
 * what it stops.
 */
import { describe, it, expect, vi } from "vitest";
import { isAllowedForScope, enforceApiKeyScope } from "../../../server/routes/api-key-scope";

describe("isAllowedForScope", () => {
  describe("read", () => {
    it("allows safe methods", () => {
      for (const m of ["GET", "HEAD", "OPTIONS", "get"]) {
        expect(isAllowedForScope("read", m, "/workspaces"), m).toBe(true);
      }
    });

    /** The escalation itself. */
    it("refuses every state-changing method", () => {
      for (const m of ["POST", "PATCH", "PUT", "DELETE"]) {
        expect(isAllowedForScope("read", m, "/workspaces/abc"), m).toBe(false);
      }
    });

    it("refuses starting a scan", () => {
      expect(isAllowedForScope("read", "POST", "/scans")).toBe(false);
    });
  });

  describe("scan", () => {
    it("allows starting and cancelling a scan", () => {
      expect(isAllowedForScope("scan", "POST", "/scans")).toBe(true);
      expect(isAllowedForScope("scan", "POST", "/scans/abc-123/cancel")).toBe(true);
    });

    it("still allows reads", () => {
      expect(isAllowedForScope("scan", "GET", "/findings")).toBe(true);
    });

    /**
     * A scan key exists to start scans, not to act on their results. Without
     * this the "scan" tier would be indistinguishable from "full" for anything
     * whose path merely began with /scans.
     */
    it("refuses writes outside the scan-trigger routes", () => {
      expect(isAllowedForScope("scan", "DELETE", "/scans/abc-123")).toBe(false);
      expect(isAllowedForScope("scan", "PATCH", "/findings/f1")).toBe(false);
      expect(isAllowedForScope("scan", "POST", "/workspaces")).toBe(false);
      expect(isAllowedForScope("scan", "DELETE", "/workspaces/w1")).toBe(false);
    });

    it("does not let a lookalike path through", () => {
      expect(isAllowedForScope("scan", "POST", "/scans/abc/cancel/../../workspaces")).toBe(false);
      expect(isAllowedForScope("scan", "POST", "/scans-export")).toBe(false);
    });
  });

  describe("full", () => {
    it("permits ordinary writes", () => {
      expect(isAllowedForScope("full", "DELETE", "/workspaces/w1")).toBe(true);
      expect(isAllowedForScope("full", "PATCH", "/findings/f1")).toBe(true);
    });
  });

  /**
   * A leaked key that can mint another key survives its own revocation, so key
   * management needs an interactive session at EVERY scope — including reads,
   * which are the reconnaissance step for exactly that move.
   */
  describe("key management is closed to API keys at every scope", () => {
    it("refuses minting, listing and revoking", () => {
      for (const scope of ["read", "scan", "full"]) {
        expect(isAllowedForScope(scope, "POST", "/api-keys"), scope).toBe(false);
        expect(isAllowedForScope(scope, "GET", "/api-keys"), scope).toBe(false);
        expect(isAllowedForScope(scope, "DELETE", "/api-keys/k1"), scope).toBe(false);
      }
    });
  });

  /** Fail closed: a scope added to the schema later must not mean "allow". */
  describe("unknown scope", () => {
    it("is treated as least privileged, not most", () => {
      expect(isAllowedForScope("admin", "DELETE", "/workspaces/w1")).toBe(false);
      expect(isAllowedForScope("", "POST", "/scans")).toBe(false);
      expect(isAllowedForScope("FULL", "DELETE", "/workspaces/w1")).toBe(false); // case-sensitive on purpose
    });

    it("still permits reads, so a misconfigured key degrades rather than breaks", () => {
      expect(isAllowedForScope("admin", "GET", "/workspaces")).toBe(true);
    });
  });
});

describe("enforceApiKeyScope middleware", () => {
  const mkRes = () => {
    const res = { statusCode: 0, body: undefined as unknown };
    return {
      status(code: number) { res.statusCode = code; return this; },
      json(b: unknown) { res.body = b; return this; },
      captured: res,
    };
  };

  /** Session auth must be untouched — this narrows keys, it is not the authz model. */
  it("passes a session-authenticated request straight through", () => {
    const next = vi.fn();
    const res = mkRes();
    enforceApiKeyScope({ method: "DELETE", path: "/workspaces/w1" } as never, res as never, next);
    expect(next).toHaveBeenCalledOnce();
    expect(res.captured.statusCode).toBe(0);
  });

  it("passes a permitted API-key request through", () => {
    const next = vi.fn();
    const res = mkRes();
    enforceApiKeyScope({ method: "GET", path: "/findings", apiKeyScope: "read" } as never, res as never, next);
    expect(next).toHaveBeenCalledOnce();
  });

  it("refuses an over-scoped request with 403 and does not call next", () => {
    const next = vi.fn();
    const res = mkRes();
    enforceApiKeyScope({ method: "DELETE", path: "/workspaces/w1", apiKeyScope: "read" } as never, res as never, next);

    expect(next).not.toHaveBeenCalled();
    // 403 not 404: the caller is authenticated, and naming the reason is what
    // lets an integration author fix their key.
    expect(res.captured.statusCode).toBe(403);
    expect(String((res.captured.body as { error: string }).error)).toContain("read");
  });
});
