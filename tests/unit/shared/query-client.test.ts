/**
 * Unit tests for client/src/lib/queryClient.ts — parseApiError utility.
 *
 * parseApiError extracts a human-readable message from API JSON error envelopes
 * so toast notifications show clean strings instead of raw JSON blobs.
 */

import { describe, it, expect } from "vitest";
import { parseApiError } from "../../../client/src/lib/queryClient";

describe("parseApiError", () => {
  it("extracts .error field from JSON envelope", () => {
    const json = JSON.stringify({ success: false, error: "Authentication error", statusCode: 401 });
    expect(parseApiError(401, json)).toBe("Authentication error");
  });

  it("extracts .message field when .error is absent", () => {
    const json = JSON.stringify({ message: "Workspace not found" });
    expect(parseApiError(404, json)).toBe("Workspace not found");
  });

  it("prefers .error over .message when both present", () => {
    const json = JSON.stringify({ error: "Forbidden", message: "some detail" });
    expect(parseApiError(403, json)).toBe("Forbidden");
  });

  it("falls back to raw text when JSON is not an object", () => {
    expect(parseApiError(500, "Internal Server Error")).toBe("Internal Server Error");
  });

  it("falls back to status string when text is empty", () => {
    expect(parseApiError(503, "")).toBe("Request failed (503)");
  });

  it("falls back to raw text when JSON has no error/message field", () => {
    const json = JSON.stringify({ ok: false, code: 42 });
    expect(parseApiError(400, json)).toBe(json);
  });

  it("ignores empty string .error field", () => {
    const json = JSON.stringify({ error: "" });
    expect(parseApiError(400, json)).toBe(json);
  });

  it("handles non-JSON text gracefully", () => {
    expect(parseApiError(502, "Bad Gateway")).toBe("Bad Gateway");
  });

  it("handles HTML error page gracefully", () => {
    const html = "<!DOCTYPE html><html><body>503</body></html>";
    expect(parseApiError(503, html)).toBe(html);
  });

  it("handles null-ish values in envelope", () => {
    const json = JSON.stringify({ error: null, message: "Fallback message" });
    expect(parseApiError(500, json)).toBe("Fallback message");
  });
});
