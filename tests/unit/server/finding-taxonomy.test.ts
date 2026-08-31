import { describe, it, expect } from "vitest";
import {
  classifyObservation,
  SECURITY_CATEGORIES,
  KNOWN_CONTROLS,
} from "../../../server/scanner/finding-taxonomy";

/**
 * These cases come from real stored findings. The engine had 25 of 76 findings
 * sitting in a single `informational` bucket that mixed genuine weaknesses,
 * controls that were working, and pure technology facts.
 */

const c = (id: string, name: string, sev = "info", isCve = false) =>
  classifyObservation(id, name, sev, isCve);

describe("the misclassifications that prompted this", () => {
  it("routes Weak HSTS to transport_security, not informational", () => {
    // Observed in the database as category "informational", severity "info".
    // It is a real weakness and no rule matched it.
    const r = c("weak-hsts", "Weak HTTP Strict-Transport-Security - Detect");
    expect(r.kind).toBe("security");
    expect(r.category).toBe("transport_security");
    expect(r.skip).toBe(false);
  });

  it("treats DNSSEC being present as a control, not a finding", () => {
    const r = c("dnssec-detection", "DNSSEC Detection");
    expect(r.kind).toBe("control");
    expect(r.category).toBe("DNSSEC");
    // Good news must never sit in the triage inbox or drag the score down.
    expect(r.skip).toBe(true);
  });

  it("treats security.txt being present as a control", () => {
    const r = c("security-txt", "security.txt File");
    expect(r.kind).toBe("control");
    expect(r.skip).toBe(true);
  });

  it("drops technology detection from the findings inbox", () => {
    for (const name of [
      "AWS Service - Detect",
      "DNS SaaS Service Detection",
      "Detect OpenID Connect provider",
      "Android Asset Links Configuration - Detect",
      "robots.txt endpoint prober",
      // Real stored titles that the narrower `-detect$` pattern missed, leaving
      // them in `unclassified` and making the taxonomy look full of holes.
      "Apache Detection on www.example.com",
      "AWS Service - Detect on host.example.com",
      "Microsoft Azure Domain Tenant ID - Detect on example.com",
      "Wildcard DNS Configuration - Detection on example.com",
      "Strapi API - Detect on admin.example.com",
    ]) {
      const r = c("tech", name);
      expect(r.kind, name).toBe("recon");
      expect(r.skip, name).toBe(true);
    }
  });
});

describe("negation flips a control into a weakness", () => {
  it.each([
    ["Weak HTTP Strict-Transport-Security", "transport_security"],
    ["Missing DMARC record", "email_security"],
    ["SPF record not configured", "email_security"],
    ["Invalid CAA record", "certificate_authority"],
  ])("%s is a security finding", (name, _category) => {
    const r = c("t", name);
    expect(r.kind).toBe("security");
  });

  it("distinguishes HSTS present from HSTS weak", () => {
    // Both mention HSTS; only one is good news.
    expect(c("t", "Strict-Transport-Security enabled").kind).toBe("control");
    expect(c("t", "Weak Strict-Transport-Security").kind).toBe("security");
  });

  it("keeps a negated observation even when no category rule matches it", () => {
    // Silently discarding "Insecure <something we have no rule for>" is the
    // exact failure mode this module exists to prevent.
    const r = c("t", "Insecure zzzz configuration");
    expect(r.kind).toBe("security");
    expect(r.skip).toBe(false);
    expect(r.category).toBe("unclassified");
  });

  it('treats "Misconfigured" as a negation', () => {
    // The pattern was /\bmisconfigur\b/, which demands a word boundary right
    // after "misconfigur" and therefore matched nothing. Every
    // "… - Misconfigured" finding fell through to recon and left the inbox.
    // Found by running the classifier over the findings already in the database.
    const r = c("expect-ct", "Expect-CT Header - Misconfigured");
    expect(r.kind).toBe("security");
    expect(r.category).toBe("security_headers");
  });

  it.each(["Misconfigured CORS policy", "Unsafe inline script policy", "Deprecated TLS version offered"])(
    "%s is a security finding",
    (name) => {
      expect(c("t", name).kind).toBe("security");
    },
  );

  it("distinguishes DMARC configured from DMARC missing", () => {
    expect(c("t", "DMARC record found").kind).toBe("control");
    expect(c("t", "Missing DMARC record").kind).toBe("security");
  });
});

describe("security routing", () => {
  it.each([
    ["missing-csp", "Missing Content-Security-Policy Header", "security_headers"],
    ["cookie-flags", "Insecure cookie attributes", "cookie_security"],
    ["cors-null", "CORS Allows Null Origin", "cors_misconfiguration"],
    ["xss-reflect", "Reflected XSS in search parameter", "xss"],
    ["open-redirect", "Open Redirect via next parameter", "open_redirect"],
    ["takeover", "Subdomain Takeover on cname", "subdomain_takeover"],
    ["git-exposed", "Exposed .git directory", "information_disclosure"],
    ["sqli", "SQL Injection in id parameter", "injection"],
    ["admin-panel", "Exposed admin panel", "exposed_service"],
    ["swagger", "API documentation exposed via swagger", "api_exposure"],
    ["aws-key", "AWS secret key leaked in response", "secret_exposure"],
    ["default-creds", "Default credentials accepted", "authentication"],
    // Without SRI a compromised CDN silently swaps the script a page loads.
    // This had no rule and was landing in "unclassified".
    ["sri", "Missing Subresource Integrity", "supply_chain"],
    // A reachable login panel is attack surface even when the template's
    // wording never says "exposed".
    ["strapi-panel", "Strapi Login Panel - Detect", "exposed_service"],
  ])("%s -> %s", (id, name, category) => {
    const r = c(id, name, "medium");
    expect(r.kind).toBe("security");
    expect(r.category).toBe(category);
  });

  it("never drops a CVE, however its text reads", () => {
    // A CVE whose name mentions "detect" must not be swept into recon.
    const r = c("CVE-2024-1234", "Version detect leading to RCE", "info", true);
    expect(r.kind).toBe("security");
    expect(r.category).toBe("vulnerability");
    expect(r.skip).toBe(false);
  });

  it("keeps an unnamed but actionable finding rather than dropping it", () => {
    // Better an unclassified real issue than a silently discarded one.
    const r = c("weird-template", "Some unusual condition", "high");
    expect(r.kind).toBe("security");
    expect(r.skip).toBe(false);
  });
});

describe("the informational bucket is gone", () => {
  it("never returns the old catch-all category", () => {
    const samples = [
      "AWS Service - Detect", "DNSSEC Detection", "robots.txt file",
      "Weak HTTP Strict-Transport-Security", "Wildcard DNS Configuration - Detection",
      "Keycloak OpenID Configuration - Detect", "security.txt File",
    ];
    for (const s of samples) {
      expect(c("t", s).category, s).not.toBe("informational");
    }
  });

  it("labels a genuinely unplaceable observation honestly", () => {
    const r = c("mystery", "zzzz qqqq", "info");
    // "unclassified" makes the taxonomy gap visible instead of hiding it.
    expect(r.category).toBe("unclassified");
    expect(r.reason).toMatch(/no rule matched/i);
  });

  it("always explains itself", () => {
    for (const s of ["DNSSEC Detection", "Missing DMARC record", "AWS Service - Detect"]) {
      expect(c("t", s).reason.length).toBeGreaterThan(5);
    }
  });
});

describe("exported vocabularies", () => {
  it("exposes the security categories for UI filters", () => {
    expect(SECURITY_CATEGORIES).toContain("transport_security");
    expect(SECURITY_CATEGORIES).toContain("email_security");
    expect(SECURITY_CATEGORIES).not.toContain("informational");
  });

  it("exposes the controls it can recognise", () => {
    expect(KNOWN_CONTROLS).toContain("DNSSEC");
    expect(KNOWN_CONTROLS).toContain("MTA-STS");
  });

  it("only ever marks control and recon observations as skippable", () => {
    // A security finding must never be silently dropped.
    for (const s of ["Missing DMARC record", "SQL Injection", "Weak HSTS"]) {
      expect(c("t", s, "medium").skip, s).toBe(false);
    }
  });
});
