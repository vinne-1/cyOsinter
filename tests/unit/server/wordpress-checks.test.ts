/**
 * Unit tests for server/scanner/wordpress-checks.ts — WordPress user
 * enumeration and XML-RPC detection, with http.js mocked.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const httpGet = vi.fn();
const httpGetNoRedirect = vi.fn();
vi.mock("../../../server/scanner/http.js", () => ({
  httpGet: (...a: unknown[]) => httpGet(...a),
  httpGetNoRedirect: (...a: unknown[]) => httpGetNoRedirect(...a),
}));

import { parseWpUsers, slugFromAuthorRedirect, runWordPressChecks } from "../../../server/scanner/wordpress-checks";

describe("parseWpUsers", () => {
  it("parses a valid users array", () => {
    const body = JSON.stringify([{ id: 1, name: "admin_ProcEll", slug: "admin_procell" }, { id: 2, slug: "editor" }]);
    const u = parseWpUsers(body);
    expect(u).toHaveLength(2);
    expect(u[0]).toMatchObject({ id: 1, slug: "admin_procell" });
  });
  it("returns [] for non-array / invalid JSON", () => {
    expect(parseWpUsers("not json")).toEqual([]);
    expect(parseWpUsers('{"code":"rest_forbidden"}')).toEqual([]);
    expect(parseWpUsers("[]")).toEqual([]);
  });
});

describe("slugFromAuthorRedirect", () => {
  it("extracts the slug from an author URL", () => {
    expect(slugFromAuthorRedirect("https://x.com/author/admin_procell/")).toBe("admin_procell");
  });
  it("returns null when no author segment", () => {
    expect(slugFromAuthorRedirect("https://x.com/login")).toBeNull();
  });
});

describe("runWordPressChecks", () => {
  beforeEach(() => { httpGet.mockReset(); httpGetNoRedirect.mockReset(); });

  it("reports HIGH user enumeration when REST API exposes users", async () => {
    httpGet.mockImplementation(async (url: string) => {
      if (url.includes("/wp-json/wp/v2/users")) {
        return { status: 200, headers: { "content-type": "application/json; charset=UTF-8" }, body: JSON.stringify([{ id: 1, name: "admin_ProcEll", slug: "admin_procell" }]), finalUrl: url };
      }
      if (url.includes("/xmlrpc.php")) return { status: 200, headers: {}, body: "<html>home</html>", finalUrl: url };
      return null;
    });
    const r = await runWordPressChecks("example.com");
    expect(r.isWordPress).toBe(true);
    expect(r.users.map((u) => u.slug)).toContain("admin_procell");
    const f = r.findings.find((x) => x.category === "information_disclosure");
    expect(f?.severity).toBe("high");
    expect(f?.description).toMatch(/admin_procell/);
    // 200 homepage for xmlrpc alone must NOT be flagged
    expect(r.xmlrpcEnabled).toBe(false);
  });

  it("falls back to author-scan when REST is blocked", async () => {
    httpGet.mockImplementation(async (url: string) => {
      if (url.includes("/wp-json/wp/v2/users")) return { status: 401, headers: {}, body: "", finalUrl: url };
      if (url.includes("/xmlrpc.php")) return { status: 405, headers: {}, body: "", finalUrl: url };
      return null;
    });
    httpGetNoRedirect.mockImplementation(async (url: string) => {
      if (url.includes("author=1")) return { status: 301, headers: {}, location: "https://example.com/author/bob/" };
      return null;
    });
    const r = await runWordPressChecks("example.com");
    expect(r.users[0].slug).toBe("bob");
    expect(r.xmlrpcEnabled).toBe(true); // 405 to GET = enabled
    expect(r.findings.some((x) => x.category === "web_application")).toBe(true);
  });

  it("reports nothing on a non-WordPress site", async () => {
    httpGet.mockResolvedValue({ status: 404, headers: {}, body: "Not found", finalUrl: "x" });
    httpGetNoRedirect.mockResolvedValue({ status: 404, headers: {}, location: undefined });
    const r = await runWordPressChecks("example.com");
    expect(r.isWordPress).toBe(false);
    expect(r.findings).toHaveLength(0);
  });
});
