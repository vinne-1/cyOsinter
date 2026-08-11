/**
 * Unit tests for server/scanner/people-osint.ts — keyless, org-scoped
 * employee-exposure OSINT: email-format inference, permutation, GitHub commit
 * harvesting (domain-scoped), and Gravatar enrichment. stealthFetch is mocked so
 * both the GitHub API and Gravatar lookups are deterministic and offline.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const stealthFetch = vi.fn();
vi.mock("../../../server/scanner/stealth.js", () => ({
  stealthFetch: (...a: unknown[]) => stealthFetch(...a),
  resolveProfile: () => ({}),
}));

import {
  splitName, inferEmailFormat, permuteEmail, candidateGithubHandles, gravatarHash, runPeopleOsint,
} from "../../../server/scanner/people-osint";

const resp = (ok: boolean, body: unknown) => ({ ok, json: async () => body, text: async () => JSON.stringify(body) });

beforeEach(() => { stealthFetch.mockReset(); });

describe("splitName", () => {
  it("splits and normalizes (diacritics stripped)", () => {
    expect(splitName("José García")).toEqual({ first: "jose", last: "garcia" });
    expect(splitName("Jane")).toEqual({ first: "jane", last: "" });
    expect(splitName("Mary Jane Watson")).toEqual({ first: "mary", last: "watson" });
  });
});

describe("inferEmailFormat", () => {
  it("detects first.last", () => {
    const pairs = [
      { name: "Jane Doe", email: "jane.doe@acme.com" },
      { name: "Bob Smith", email: "bob.smith@acme.com" },
    ];
    expect(inferEmailFormat(pairs, "acme.com")).toBe("first.last");
  });
  it("detects flast", () => {
    expect(inferEmailFormat([{ name: "Jane Doe", email: "jdoe@acme.com" }], "acme.com")).toBe("flast");
  });
  it("ignores emails on other domains", () => {
    expect(inferEmailFormat([{ name: "Jane Doe", email: "jane.doe@other.com" }], "acme.com")).toBeUndefined();
  });
});

describe("permuteEmail", () => {
  it("builds the address for a format", () => {
    expect(permuteEmail("Jane Doe", "first.last", "acme.com")).toBe("jane.doe@acme.com");
    expect(permuteEmail("Jane Doe", "flast", "acme.com")).toBe("jdoe@acme.com");
    expect(permuteEmail("Jane", "first.last", "acme.com")).toBeUndefined(); // no last name
  });
});

describe("candidateGithubHandles", () => {
  it("derives handles from the domain label", () => {
    expect(candidateGithubHandles("alkem-labs.com")).toEqual(["alkem-labs", "alkemlabs"]);
  });
});

describe("gravatarHash", () => {
  it("is a lowercase-trimmed md5", () => {
    const h = gravatarHash("  Test@Example.com ");
    expect(h).toMatch(/^[a-f0-9]{32}$/);
    expect(h).toBe(gravatarHash("test@example.com"));
  });
});

describe("runPeopleOsint (end-to-end, mocked)", () => {
  it("harvests GitHub commit emails (domain-scoped), infers format, permutes, and emits a finding", async () => {
    stealthFetch.mockImplementation(async (url: string) => {
      if (url.includes("/orgs/acme/repos")) return resp(true, [{ name: "web", full_name: "acme/web", fork: false }]);
      if (url.includes("/repos/acme/web/commits")) return resp(true, [
        { commit: { author: { name: "Jane Doe", email: "jane.doe@acme.com" } } },
        { commit: { author: { name: "Bob Roe", email: "bob.roe@acme.com" } } },
        { commit: { author: { name: "Ext Contractor", email: "ext@gmail.com" } } }, // off-domain → excluded
      ]);
      if (url.includes("gravatar.com")) return resp(false, {}); // no gravatar profile
      return resp(false, {});
    });

    const { findings, people, emailFormat } = await runPeopleOsint("acme.com", [], "2026-01-01T00:00:00Z", { gravatar: true });
    const emails = people.map((p) => p.email);
    expect(emails).toContain("jane.doe@acme.com");
    expect(emails).toContain("bob.roe@acme.com");
    expect(emails).not.toContain("ext@gmail.com"); // domain-scoped
    expect(emailFormat).toBe("first.last");
    expect(findings).toHaveLength(1);
    expect(findings[0].category).toBe("osint_exposure");
    expect(findings[0].severity).toBe("low");
  });

  it("returns no finding when nothing is found (fail-soft)", async () => {
    stealthFetch.mockResolvedValue(resp(false, {}));
    const { findings, people } = await runPeopleOsint("nobody.example", [], "2026-01-01T00:00:00Z", { gravatar: false });
    expect(people).toEqual([]);
    expect(findings).toEqual([]);
  });

  it("enriches with Gravatar public profile when present", async () => {
    stealthFetch.mockImplementation(async (url: string) => {
      if (url.includes("/orgs/acme/repos")) return resp(true, [{ name: "web", full_name: "acme/web", fork: false }]);
      if (url.includes("/repos/acme/web/commits")) return resp(true, [{ commit: { author: { name: "Jane Doe", email: "jane.doe@acme.com" } } }]);
      if (url.includes("gravatar.com")) return resp(true, { entry: [{ displayName: "Jane D", currentLocation: "NYC", profileUrl: "https://gravatar.com/jane", accounts: [{ url: "https://twitter.com/jane" }] }] });
      return resp(false, {});
    });
    const { people } = await runPeopleOsint("acme.com", [], "2026-01-01T00:00:00Z", { gravatar: true });
    const jane = people.find((p) => p.email === "jane.doe@acme.com");
    expect(jane?.gravatar?.accounts).toContain("https://twitter.com/jane");
  });
});
