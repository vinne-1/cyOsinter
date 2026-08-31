import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { watchForCodeLeaks, findSecretsInText, maskSecret } from "../../../server/scanner/code-leak-watch";

/**
 * Two failures matter here and both are silent ones:
 *  - reporting "no leaks found" when the check never ran, and
 *  - storing a live credential in a finding that then goes into a report.
 */

const ORIGINAL_TOKEN = process.env.GITHUB_TOKEN;

beforeEach(() => { delete process.env.GITHUB_TOKEN; delete process.env.GITHUB_PAT; });
afterEach(() => {
  if (ORIGINAL_TOKEN === undefined) delete process.env.GITHUB_TOKEN;
  else process.env.GITHUB_TOKEN = ORIGINAL_TOKEN;
  vi.restoreAllMocks();
});

/** Builds a fake GitHub API: one search result, one file body. */
function fakeGitHub(fileContent: string, items = 1) {
  return vi.fn(async (url: string) => {
    const u = String(url);
    if (u.includes("/search/code")) {
      return {
        ok: true, status: 200,
        headers: new Headers({ "x-ratelimit-remaining": "9" }),
        json: async () => ({
          items: Array.from({ length: items }, (_, i) => ({
            repository: { full_name: `acme/app-${i}` },
            path: `src/config-${i}.ts`,
            html_url: `https://github.com/acme/app-${i}/blob/main/src/config-${i}.ts`,
            url: `https://api.github.com/repos/acme/app-${i}/contents/src/config-${i}.ts`,
          })),
        }),
      } as unknown as Response;
    }
    return {
      ok: true, status: 200,
      headers: new Headers(),
      json: async () => ({ content: Buffer.from(fileContent).toString("base64"), encoding: "base64" }),
    } as unknown as Response;
  });
}

describe("configuration", () => {
  it("reports that it is not configured rather than returning an empty result", async () => {
    // "No leaks found" and "we never looked" must not be indistinguishable.
    const r = await watchForCodeLeaks("example.com");
    expect(r.error).toMatch(/requires a token/i);
    expect(r.hits).toEqual([]);
    expect(r.filesInspected).toBe(0);
  });

  it("names the environment variable the operator has to set", async () => {
    const r = await watchForCodeLeaks("example.com");
    expect(r.error).toContain("GITHUB_TOKEN");
  });

  it("accepts a token passed directly", async () => {
    const r = await watchForCodeLeaks("example.com", {
      token: "ghp_test", fetchImpl: fakeGitHub("nothing interesting here"),
    });
    expect(r.error).toBeUndefined();
  });

  it("picks the token up from the environment", async () => {
    process.env.GITHUB_TOKEN = "ghp_env";
    const r = await watchForCodeLeaks("example.com", { fetchImpl: fakeGitHub("plain text") });
    expect(r.error).toBeUndefined();
  });
});

describe("secret detection in repository content", () => {
  it("flags a file that carries a credential", async () => {
    const leak = 'const key = "AKIAIOSFODNN7EXAMPLE";';
    const r = await watchForCodeLeaks("example.com", { token: "t", fetchImpl: fakeGitHub(leak) });

    expect(r.counts.withSecrets).toBe(1);
    expect(r.hits[0]!.hasSecret).toBe(true);
    expect(r.hits[0]!.secrets[0]!.name).toBe("AWS Access Key");
  });

  it("separates a bare domain mention from an actual leak", async () => {
    // A domain appearing in an open-source project is usually harmless;
    // merging the two categories would bury the real leaks.
    const r = await watchForCodeLeaks("example.com", {
      token: "t", fetchImpl: fakeGitHub("// see docs at example.com for details"),
    });
    expect(r.counts.withSecrets).toBe(0);
    expect(r.counts.mentionsOnly).toBe(1);
    expect(r.hits[0]!.hasSecret).toBe(false);
  });

  it("orders files with credentials ahead of plain mentions", async () => {
    let call = 0;
    const impl = vi.fn(async (url: string) => {
      if (String(url).includes("/search/code")) {
        return {
          ok: true, status: 200, headers: new Headers(),
          json: async () => ({ items: [
            { repository: { full_name: "a/b" }, path: "x", html_url: "u1", url: "f1" },
            { repository: { full_name: "c/d" }, path: "y", html_url: "u2", url: "f2" },
          ] }),
        } as unknown as Response;
      }
      // First file is benign, second holds a key.
      const body = call++ === 0 ? "just example.com" : 'AKIAIOSFODNN7EXAMPLE';
      return {
        ok: true, status: 200, headers: new Headers(),
        json: async () => ({ content: Buffer.from(body).toString("base64"), encoding: "base64" }),
      } as unknown as Response;
    });

    const r = await watchForCodeLeaks("example.com", { token: "t", fetchImpl: impl as unknown as typeof fetch });
    expect(r.hits[0]!.hasSecret).toBe(true);
  });

  it("records the repository and path so the leak can be chased", async () => {
    const r = await watchForCodeLeaks("example.com", {
      token: "t", fetchImpl: fakeGitHub("AKIAIOSFODNN7EXAMPLE"),
    });
    expect(r.hits[0]!.repository).toBe("acme/app-0");
    expect(r.hits[0]!.path).toBe("src/config-0.ts");
    expect(r.hits[0]!.htmlUrl).toContain("github.com");
  });
});

describe("findSecretsInText", () => {
  it("never returns the raw credential", async () => {
    // This value is stored, exported into reports and rendered in a browser.
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const found = findSecretsInText(`aws_key = "${secret}"`);
    expect(found).toHaveLength(1);
    expect(found[0]!.redacted).not.toContain(secret);
  });

  it("keeps the key-type prefix, which is the useful part for triage", () => {
    const found = findSecretsInText('key = "AKIAIOSFODNN7EXAMPLE"');
    expect(found[0]!.redacted).toContain("AKIA");
    expect(found[0]!.redacted).toContain("REDACTED");
  });

  it("does not leak the secret's true length", () => {
    const short = maskSecret("AKIA" + "A".repeat(16));
    const long = maskSecret("AKIA" + "A".repeat(60));
    expect(short).toBe(long);
  });

  it("redacts private key material without preserving a prefix of it", () => {
    expect(maskSecret("-----BEGIN RSA PRIVATE KEY----- MIIEabcdef")).not.toContain("MIIEabcdef");
  });

  it("finds a private key block", () => {
    const found = findSecretsInText("-----BEGIN RSA PRIVATE KEY-----\nMIIE...");
    expect(found.some((f) => f.name === "Private Key")).toBe(true);
  });

  it("returns nothing for ordinary source", () => {
    expect(findSecretsInText("export const greeting = 'hello world';")).toEqual([]);
  });

  it("is repeatable across calls", () => {
    // The shared patterns carry /g, so a leaked lastIndex would make the second
    // call on identical input return a different answer.
    const text = 'key = "AKIAIOSFODNN7EXAMPLE"';
    expect(findSecretsInText(text)).toEqual(findSecretsInText(text));
  });

  it("reports each secret type only once per file", () => {
    const found = findSecretsInText("AKIAIOSFODNN7EXAMPLE and AKIAIOSFODNN7EXAMPLB");
    expect(found.filter((f) => f.name === "AWS Access Key")).toHaveLength(1);
  });
});

describe("failure handling", () => {
  it("explains an invalid token instead of reporting a clean result", async () => {
    const impl = vi.fn(async () => ({
      ok: false, status: 401, headers: new Headers({ "x-ratelimit-remaining": "9" }), json: async () => ({}),
    } as unknown as Response));

    const r = await watchForCodeLeaks("example.com", { token: "bad", fetchImpl: impl as unknown as typeof fetch });
    expect(r.error).toMatch(/token/i);
  });

  it("distinguishes a rate limit from a bad token", async () => {
    const impl = vi.fn(async () => ({
      ok: false, status: 403, headers: new Headers({ "x-ratelimit-remaining": "0" }), json: async () => ({}),
    } as unknown as Response));

    const r = await watchForCodeLeaks("example.com", { token: "t", fetchImpl: impl as unknown as typeof fetch });
    expect(r.error).toMatch(/rate limit/i);
  });

  it("returns an error rather than throwing when the network fails", async () => {
    const impl = vi.fn(async () => { throw new Error("ECONNRESET"); });
    const r = await watchForCodeLeaks("example.com", { token: "t", fetchImpl: impl as unknown as typeof fetch });
    expect(r.error).toBeTruthy();
    expect(r.hits).toEqual([]);
  });

  it("caps how many files one sweep will fetch", async () => {
    const r = await watchForCodeLeaks("example.com", {
      token: "t", maxFiles: 3, fetchImpl: fakeGitHub("plain", 20),
    });
    // Without a cap a single run would burn the whole hourly budget.
    expect(r.filesInspected).toBeLessThanOrEqual(3);
  });

  it("de-duplicates the search terms", async () => {
    const r = await watchForCodeLeaks("Example.com", {
      token: "t", aliases: ["example.com", "EXAMPLE.COM"], fetchImpl: fakeGitHub("x"),
    });
    expect(r.terms).toEqual(["example.com"]);
  });
});
