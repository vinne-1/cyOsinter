/**
 * Breach-corpus exposure.
 *
 * "Dark web monitoring" covers several very different things. This module does
 * the part reachable from clearnet with no credential handling and no Tor: it
 * asks the public breach corpus whether the scanned organisation appears in it
 * as the breached party.
 *
 * The tests that carry weight are the honesty ones. The corpus is not uniformly
 * trustworthy and says so per record, so reporting every hit at equal weight
 * would manufacture alarm — and repeating a record the maintainer believes is
 * INVENTED back to a customer as fact would be worse than saying nothing.
 */
import { describe, it, expect, vi, afterEach } from "vitest";

vi.mock("../../../server/logger", () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));

import {
  isUsableDomain,
  breachDomainFor,
  toBreachRecord,
  checkBreachExposure,
  buildBreachFindings,
} from "../../../server/scanner/breach-exposure";

/** A raw record in the corpus's own shape. */
const raw = (over: Record<string, unknown> = {}) => ({
  Name: "Acme",
  Title: "Acme",
  Domain: "acme.com",
  BreachDate: "2021-05-01",
  PwnCount: 1_500_000,
  DataClasses: ["Email addresses"],
  IsVerified: true,
  IsFabricated: false,
  IsSpamList: false,
  IsStealerLog: false,
  IsMalware: false,
  ...over,
});

const mockCorpus = (records: unknown[], opts: { status?: number; fail?: boolean } = {}) =>
  vi.fn(async () => {
    if (opts.fail) throw new Error("ENOTFOUND");
    const status = opts.status ?? 200;
    return { ok: status >= 200 && status < 300, status, json: async () => records };
  });

afterEach(() => vi.unstubAllGlobals());

describe("breachDomainFor", () => {
  it("reduces a URL or host to its registrable root", () => {
    expect(breachDomainFor("https://www.Acme.com/path")).toBe("acme.com");
    expect(breachDomainFor("mail.acme.com")).toBe("acme.com");
    expect(breachDomainFor("acme.com.")).toBe("acme.com");
  });
});

describe("toBreachRecord", () => {
  /** Credential exposure is the line between phishing input and account takeover. */
  it("marks credential exposure from the data classes", () => {
    expect(toBreachRecord(raw({ DataClasses: ["Email addresses"] })).exposedCredentials).toBe(false);
    expect(toBreachRecord(raw({ DataClasses: ["Email addresses", "Passwords"] })).exposedCredentials).toBe(true);
    expect(toBreachRecord(raw({ DataClasses: ["Credit cards"] })).exposedCredentials).toBe(true);
  });

  it("is case-insensitive about data class names", () => {
    expect(toBreachRecord(raw({ DataClasses: ["PASSWORDS"] })).exposedCredentials).toBe(true);
  });

  it("carries the corpus's own quality flags through", () => {
    const r = toBreachRecord(raw({ IsVerified: false, IsStealerLog: true, IsSpamList: true }));
    expect(r).toMatchObject({ verified: false, stealerLog: true, spamList: true });
  });

  it("survives a record with missing fields", () => {
    const r = toBreachRecord({});
    expect(r.pwnCount).toBe(0);
    expect(r.dataClasses).toEqual([]);
    expect(r.exposedCredentials).toBe(false);
  });
});

describe("checkBreachExposure", () => {
  it("separates verified records from unverified ones", async () => {
    vi.stubGlobal("fetch", mockCorpus([
      raw({ Name: "Real", IsVerified: true }),
      raw({ Name: "Unconfirmed", IsVerified: false }),
    ]));

    const r = await checkBreachExposure("acme.com");

    expect(r.confirmed.map((b) => b.name)).toEqual(["Real"]);
    expect(r.unverified.map((b) => b.name)).toEqual(["Unconfirmed"]);
    expect(r.unavailable).toBe(false);
  });

  /**
   * The corpus flags some records as invented. Repeating a hoax back to a
   * customer as an exposure is worse than reporting nothing.
   */
  it("quarantines fabricated records away from both real buckets", async () => {
    vi.stubGlobal("fetch", mockCorpus([raw({ Name: "Hoax", IsFabricated: true, IsVerified: true })]));

    const r = await checkBreachExposure("acme.com");

    expect(r.confirmed).toEqual([]);
    expect(r.unverified).toEqual([]);
    expect(r.fabricated.map((b) => b.name)).toEqual(["Hoax"]);
  });

  it("orders the most recent breach first", async () => {
    vi.stubGlobal("fetch", mockCorpus([
      raw({ Name: "Old", BreachDate: "2013-01-01" }),
      raw({ Name: "Recent", BreachDate: "2024-06-01" }),
    ]));
    const r = await checkBreachExposure("acme.com");
    expect(r.confirmed.map((b) => b.name)).toEqual(["Recent", "Old"]);
  });

  /** The corpus answers 404 for "no records", which is a result, not a failure. */
  it("treats 404 as a clean result rather than an outage", async () => {
    vi.stubGlobal("fetch", mockCorpus([], { status: 404 }));
    const r = await checkBreachExposure("acme.com");
    expect(r.unavailable).toBe(false);
    expect(r.confirmed).toEqual([]);
  });

  /** "We could not check" and "you appear in none" are opposite conclusions. */
  it("reports unavailable when the corpus cannot be reached", async () => {
    vi.stubGlobal("fetch", mockCorpus([], { fail: true }));
    expect((await checkBreachExposure("acme.com")).unavailable).toBe(true);
  });

  it("reports unavailable on a server error", async () => {
    vi.stubGlobal("fetch", mockCorpus([], { status: 503 }));
    expect((await checkBreachExposure("acme.com")).unavailable).toBe(true);
  });

  it("reports unavailable when the corpus returns something that is not a list", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: true, status: 200, json: async () => ({ error: "nope" }) })));
    expect((await checkBreachExposure("acme.com")).unavailable).toBe(true);
  });

  /** A clean result must never imply coverage this check does not have. */
  it("always states what it cannot see", async () => {
    vi.stubGlobal("fetch", mockCorpus([]));
    const r = await checkBreachExposure("acme.com");
    expect(r.notCovered.join(" ")).toMatch(/paid subscription and proof of domain ownership/i);
    expect(r.notCovered.join(" ")).toMatch(/forums, marketplaces and paste sites/i);
  });
});

describe("buildBreachFindings", () => {
  const result = (over: Record<string, unknown> = {}) => ({
    domain: "acme.com",
    confirmed: [],
    unverified: [],
    fabricated: [],
    notCovered: ["per-account exposure requires a paid subscription", "forums are not covered"],
    unavailable: false,
    ...over,
  }) as Parameters<typeof buildBreachFindings>[1];

  const rec = (over: Record<string, unknown> = {}) => toBreachRecord(raw(over));

  it("rates a credential breach higher than an email-only one", async () => {
    const creds = buildBreachFindings("acme.com", result({
      confirmed: [rec({ DataClasses: ["Email addresses", "Passwords"] })],
    }));
    const emails = buildBreachFindings("acme.com", result({
      confirmed: [rec({ DataClasses: ["Email addresses"] })],
    }));

    expect(creds[0].severity).toBe("high");
    expect(emails[0].severity).toBe("medium");
    // And the description explains the difference rather than just asserting it.
    expect(creds[0].description).toMatch(/credential-stuffing/i);
    expect(emails[0].description).toMatch(/phishing rather than account takeover/i);
  });

  /** One finding for the set: a row per historical incident buries the current one. */
  it("emits ONE finding for all confirmed breaches", () => {
    const f = buildBreachFindings("acme.com", result({
      confirmed: [rec({ Name: "A" }), rec({ Name: "B" }), rec({ Name: "C" })],
    }));
    expect(f.filter((x) => x.severity !== "info")).toHaveLength(1);
    expect(f[0].title).toMatch(/3 confirmed public breach records/);
  });

  it("reports unverified records separately and never above low", () => {
    const f = buildBreachFindings("acme.com", result({
      unverified: [rec({ Name: "Maybe", IsVerified: false, DataClasses: ["Passwords"] })],
    }));
    const unver = f.find((x) => /unverified/.test(x.title));
    expect(unver?.severity).toBe("low");
    expect(unver?.description).toMatch(/lead to check rather than as an established exposure/i);
  });

  it("names infostealer origin, because the remediation differs", () => {
    const f = buildBreachFindings("acme.com", result({
      confirmed: [rec({ IsStealerLog: true, DataClasses: ["Passwords"] })],
    }));
    expect(f[0].description).toMatch(/infostealer malware/i);
    expect(f[0].remediation).toMatch(/endpoint cleanup/i);
  });

  /** Historical incidents are not an ongoing compromise, and must not read as one. */
  it("does not imply a current compromise", () => {
    const f = buildBreachFindings("acme.com", result({ confirmed: [rec()] }));
    expect(f[0].description).toMatch(/does not indicate a current, ongoing compromise/i);
  });

  it("emits a coverage finding even when nothing was found", () => {
    const f = buildBreachFindings("acme.com", result());
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("info");
    expect(f[0].description).toMatch(/no records name it/i);
  });

  it("states an unreachable corpus rather than implying a clean result", () => {
    const f = buildBreachFindings("acme.com", result({ unavailable: true }));
    expect(f[0].description).toMatch(/not a statement that it does not/i);
  });

  it("records fabricated exclusions in the coverage finding", () => {
    const f = buildBreachFindings("acme.com", result({ fabricated: [rec({ Title: "Hoax" })] }));
    const info = f.find((x) => x.severity === "info")!;
    expect(info.description).toMatch(/flagged by the corpus as fabricated/i);
    expect(info.evidence.fabricatedExcluded).toEqual(["Hoax"]);
  });

  /** Grouping must not depend on the machine that generated the report. */
  it("formats account counts stably, not per server locale", () => {
    const f = buildBreachFindings("acme.com", result({ confirmed: [rec({ PwnCount: 152_445_165 })] }));
    expect(f[0].description).toContain("152,445,165");
  });
});

/**
 * Half the workspaces in a live database have no `domain` set, so the routes
 * fall back to the workspace NAME. Sometimes that is a domain
 * (`mydesk.theranym.com`) and sometimes a label (`Bigbaskt`). Querying a breach
 * catalogue for "bigbaskt" returns nothing, and reporting that as "no breaches
 * found" hands the reader reassurance that was never established.
 */
describe("isUsableDomain", () => {
  it("accepts real domains, including with a scheme or subdomain", () => {
    for (const d of ["adobe.com", "mydesk.theranym.com", "https://www.adobe.com/x"]) {
      expect(isUsableDomain(d), d).toBe(true);
    }
  });

  it("rejects a workspace label that is not a domain", () => {
    for (const d of ["Bigbaskt", "THeranym", "my workspace", ""]) {
      expect(isUsableDomain(d), d).toBe(false);
    }
  });
});

describe("a target that is not a domain", () => {
  it("is reported as unchecked, not as clean", async () => {
    vi.stubGlobal("fetch", mockCorpus([]));
    const r = await checkBreachExposure("Bigbaskt");

    expect(r.unavailable).toBe(true);
    expect(r.unavailableReason).toBe("no-domain");
    expect(r.confirmed).toEqual([]);
  });

  it("never queries the corpus for a label", async () => {
    const fetchMock = mockCorpus([]);
    vi.stubGlobal("fetch", fetchMock);
    await checkBreachExposure("Bigbaskt");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  /** The two unavailable reasons need different fixes, so they read differently. */
  it("names the configuration problem rather than blaming the corpus", async () => {
    vi.stubGlobal("fetch", mockCorpus([]));
    const r = await checkBreachExposure("Bigbaskt");
    const info = buildBreachFindings("Bigbaskt", r).find((f) => f.severity === "info")!;

    expect(info.title).toMatch(/No domain configured/i);
    expect(info.description).toMatch(/is a workspace name, not a domain name/i);
    expect(info.description).toMatch(/not a statement that the organisation appears in no breach/i);
    expect(info.remediation).toMatch(/Set the workspace's domain/i);
    // Must NOT blame the corpus, which is working fine.
    expect(info.description).not.toMatch(/could not be reached/i);
  });
});
