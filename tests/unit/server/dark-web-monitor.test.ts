import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * Dark web monitoring engine tests.
 *
 * The module reaches the network two ways, and BOTH have to be mocked or the
 * suite silently makes real requests: `torFetchJson`/`torFetchText` for .onion
 * sources, and `checkRansomwareExposure` — which owns its own fetch of a 21 MB
 * leak-site corpus. An earlier version of this file mocked only the first, so a
 * test asserting "no mentions" downloaded the real corpus and then failed
 * because the live data disagreed with the fixture.
 *
 * `vi.mock` factories are hoisted, so anything they reference MUST come from
 * `vi.hoisted()` — a plain top-level `const` is not initialised when the factory
 * runs.
 */

const {
  mockTorFetchJson,
  mockTorFetchText,
  mockIsTorAvailable,
  mockCheckRansomware,
} = vi.hoisted(() => ({
  mockTorFetchJson: vi.fn(),
  mockTorFetchText: vi.fn(),
  mockIsTorAvailable: vi.fn(async () => false),
  mockCheckRansomware: vi.fn(),
}));

vi.mock("../../../server/logger", () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));

vi.mock("../../../server/scanner/tor-fetch", () => ({
  torFetchJson: mockTorFetchJson,
  torFetchText: mockTorFetchText,
  isTorAvailable: mockIsTorAvailable,
  TOR_PROXY_URL: "socks5://127.0.0.1:9050",
}));

vi.mock("../../../server/scanner/ransomware-watch", () => ({
  checkRansomwareExposure: mockCheckRansomware,
}));

import {
  monitorDarkWeb,
  textMentionsDomain,
  __resetDarkWebCache,
} from "../../../server/scanner/dark-web-monitor";

/** The shape `checkRansomwareExposure` returns when nothing matched. */
const NO_LEAKS = {
  target: "example.com",
  recordsChecked: 31_512,
  matches: [],
  counts: { confirmed: 0, possible: 0 },
  feedFetchedAt: new Date().toISOString(),
};

beforeEach(() => {
  __resetDarkWebCache();
  mockTorFetchJson.mockReset();
  mockTorFetchText.mockReset();
  mockCheckRansomware.mockReset();
  mockIsTorAvailable.mockResolvedValue(false);
  mockCheckRansomware.mockResolvedValue({ ...NO_LEAKS });
});

afterEach(() => {
  __resetDarkWebCache();
  vi.restoreAllMocks();
});

describe("monitorDarkWeb — configuration", () => {
  /**
   * Tor down is reported, but the .onion source sets are currently EMPTY — both
   * shipped addresses were verified dead (one is a v2 onion, unresolvable since
   * Tor removed v2 in 2021). An absent source set must be neither "checked" nor
   * "failed": listing it either way misdescribes the run, and a permanent entry
   * in `sourcesFailed` is what trains a reader to stop reading that field.
   */
  it("reports Tor as unavailable without inventing failed .onion sources", async () => {
    mockIsTorAvailable.mockResolvedValue(false);
    const result = await monitorDarkWeb("example.com", { force: true });

    expect(result.torAvailable).toBe(false);
    expect(result.target).toBe("example.com");
    expect(result.sourcesFailed).not.toContain("dark_paste_sites");
    expect(result.sourcesFailed).not.toContain("credential_dumps");
  });

  /**
   * The leak-site corpus is clearnet, so it is the one source that still runs
   * with no Tor. Ahmia and Onion.live used to fill this role and were removed:
   * `ahmia.fi/api/v1` and `onion.live/api` both answer 404, and Ahmia's
   * `/search/` answers 302 to its homepage over clearnet AND over its .onion
   * service, so no transport makes them work.
   */
  it("checks the ransomware leak-site corpus without Tor", async () => {
    const result = await monitorDarkWeb("example.com", { force: true });

    expect(result.sourcesChecked).toContain("ransomware_leak_sites");
    expect(result.sourcesFailed).not.toContain("ransomware_leak_sites");
  });

  it("reports a clean run with no failures when the working source answers", async () => {
    mockIsTorAvailable.mockResolvedValue(true);
    mockTorFetchText.mockResolvedValue("");
    // `[]` is "answered with nothing"; `null` is "did not answer". Conflating
    // the two is the bug this whole module is built to avoid, so the fixture
    // has to respect the distinction as carefully as the code does.
    mockTorFetchJson.mockResolvedValue([]);

    const result = await monitorDarkWeb("example.com", { force: true });

    expect(result.torAvailable).toBe(true);
    expect(result.sourcesFailed).toEqual([]);
    expect(result.sourcesChecked).toContain("ransomware_leak_sites");
  });
});

describe("monitorDarkWeb — ransomware leak sites", () => {
  const match = (over: Record<string, unknown> = {}) => ({
    victim: "Example Corp",
    group: "LockBit",
    website: "example.com",
    country: "IN",
    sector: "Retail",
    publishedAt: "2026-10-01T00:00:00.000Z",
    discoveredAt: "2026-10-02T00:00:00.000Z",
    postUrl: "http://lockbitxxx.onion/post/1",
    confidence: "confirmed" as const,
    reason: "Listed domain matches the target",
    ...over,
  });

  it("surfaces a leak-site posting as a confirmed mention", async () => {
    mockCheckRansomware.mockResolvedValue({
      ...NO_LEAKS,
      matches: [match()],
      counts: { confirmed: 1, possible: 0 },
    });

    const result = await monitorDarkWeb("example.com", { force: true });
    const m = result.mentions.find((x) => x.source === "ransomware_leak_sites");

    expect(m).toBeDefined();
    expect(m!.confidence).toBe("confirmed");
    expect(m!.title).toContain("LockBit");
    expect(m!.title).toContain("Example Corp");
    expect(m!.url).toBe("http://lockbitxxx.onion/post/1");
  });

  /**
   * The corpus already grades its own matches — exact domain versus
   * organisation name — so the grade is carried across rather than re-derived.
   * Re-deriving it would be a second opinion that could disagree with the one
   * the Brand Threats page shows for the same record.
   */
  it("carries the corpus's own confidence rather than re-deriving it", async () => {
    mockCheckRansomware.mockResolvedValue({
      ...NO_LEAKS,
      matches: [match({ confidence: "possible", website: null, reason: "Name match" })],
      counts: { confirmed: 0, possible: 1 },
    });

    const result = await monitorDarkWeb("example.com", { force: true });
    expect(result.mentions[0]!.confidence).toBe("possible");
  });

  /** A feed outage must not render as "no leak-site exposure". */
  it("records the source as failed when the corpus is unreachable", async () => {
    mockCheckRansomware.mockResolvedValue({
      ...NO_LEAKS,
      error: "Leak-site feed unavailable — exposure could not be checked",
    });

    const result = await monitorDarkWeb("example.com", { force: true });

    expect(result.sourcesFailed).toContain("ransomware_leak_sites");
    expect(result.mentions).toHaveLength(0);
  });

  it("survives the corpus check throwing", async () => {
    mockCheckRansomware.mockRejectedValue(new Error("boom"));

    const result = await monitorDarkWeb("example.com", { force: true });
    expect(result.sourcesFailed).toContain("ransomware_leak_sites");
    expect(result.target).toBe("example.com");
  });
});

describe("monitorDarkWeb — error handling", () => {
  it("still returns a result when every source fails", async () => {
    mockCheckRansomware.mockRejectedValue(new Error("Network error"));
    mockTorFetchJson.mockRejectedValue(new Error("Network error"));

    const result = await monitorDarkWeb("example.com", { force: true });
    expect(result.sourcesFailed.length).toBeGreaterThan(0);
    expect(result.target).toBe("example.com");
  });

  it("serves stale cache on failure", async () => {
    const first = await monitorDarkWeb("example.com", { force: true });
    expect(first.target).toBe("example.com");

    mockCheckRansomware.mockRejectedValue(new Error("down"));
    const second = await monitorDarkWeb("example.com");
    expect(second.target).toBe("example.com");
  });
});

describe("monitorDarkWeb — caching", () => {
  it("returns a cached result on subsequent calls without force", async () => {
    const first = await monitorDarkWeb("example.com", { force: true });
    mockCheckRansomware.mockClear();

    const second = await monitorDarkWeb("example.com");
    expect(mockCheckRansomware).not.toHaveBeenCalled();
    expect(second.target).toBe(first.target);
  });

  it("bypasses the cache when force is true", async () => {
    await monitorDarkWeb("example.com", { force: true });
    mockCheckRansomware.mockClear();

    await monitorDarkWeb("example.com", { force: true });
    expect(mockCheckRansomware).toHaveBeenCalled();
  });
});

describe("monitorDarkWeb — aliases", () => {
  it("passes the primary domain to the leak-site check", async () => {
    await monitorDarkWeb("example.com", {
      force: true,
      aliases: ["subsidiary.example.org"],
      organisationName: "Example Corp",
    });

    expect(mockCheckRansomware).toHaveBeenCalledWith(
      "example.com",
      expect.objectContaining({ organisationName: expect.any(String) }),
    );
  });
});

/**
 * Domain matching used plain `includes()`, which is wrong in the most damaging
 * direction for this module: its stated purpose is to avoid telling a team they
 * are on the dark web when they are not.
 *
 * `"leaked data from notexample.com".includes("example.com")` is true, and so is
 * `"dump for example.com.evil.net"` — a listing about somebody else's domain.
 */
describe("textMentionsDomain", () => {
  it("rejects a domain that merely contains the target as a substring", () => {
    expect(textMentionsDomain("leaked data from notexample.com users", "example.com")).toBe(false);
    expect(textMentionsDomain("example.commerce listing", "example.com")).toBe(false);
  });

  /** The attribution error asn-expansion and inScopeSans both refuse. */
  it("rejects a different domain that starts with the target", () => {
    expect(textMentionsDomain("dump for example.com.evil.net", "example.com")).toBe(false);
  });

  it("accepts the domain itself and its subdomains", () => {
    expect(textMentionsDomain("breach at www.example.com", "example.com")).toBe(true);
    expect(textMentionsDomain("credentials for example.com", "example.com")).toBe(true);
    expect(textMentionsDomain("mail.example.com dumped", "example.com")).toBe(true);
  });

  it("accepts the domain inside an email address or URL", () => {
    expect(textMentionsDomain("contact @example.com now", "example.com")).toBe(true);
    expect(textMentionsDomain("visit http://example.com/leak", "example.com")).toBe(true);
  });

  it("is case-insensitive and safe on empty input", () => {
    expect(textMentionsDomain("Breach At EXAMPLE.COM", "example.com")).toBe(true);
    expect(textMentionsDomain("anything", "")).toBe(false);
  });
});

/**
 * `searchDarkPasteSites` and `searchCredentialDumps` both ended with a hardcoded
 * `return { failed: false }`, so a run in which every .onion source was
 * unreachable reported itself as a COMPLETED check that found nothing. That is
 * the failure this module's own header forbids, and it made the panel's green
 * "all sources answered" state partly untrue — measured on a live run that
 * reported 3 of 3 sources answered while both paste sites were in fact dead.
 */
describe("source accounting is never fabricated", () => {
  /**
   * `searchDarkPasteSites` and `searchCredentialDumps` both ended with a
   * hardcoded `return { failed: false }`, AND the caller discarded the flag
   * without reading it. Both halves had to be wrong for the bug to show, and
   * both were: a live run reported "3 of 3 sources answered" while two of the
   * three had reached nothing at all, which made the panel's green state untrue.
   *
   * With the dead addresses removed there is one working source, so the
   * property worth pinning now is that the module reports exactly what ran.
   */
  it("never lists a source as both checked and failed", async () => {
    mockIsTorAvailable.mockResolvedValue(true);
    const result = await monitorDarkWeb("example.com", { force: true });

    const both = result.sourcesChecked.filter((s) => result.sourcesFailed.includes(s));
    expect(both).toEqual([]);
  });

  it("reports the leak-site corpus as failed when it errors, and nothing else", async () => {
    mockCheckRansomware.mockResolvedValue({
      ...NO_LEAKS,
      error: "Leak-site feed unavailable — exposure could not be checked",
    });

    const result = await monitorDarkWeb("example.com", { force: true });
    expect(result.sourcesFailed).toEqual(["ransomware_leak_sites"]);
  });
});
