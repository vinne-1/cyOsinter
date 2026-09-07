/**
 * Unit tests for server/scanner/credential-detection.ts.
 *
 * This heuristic decides whether a finding is reported at all and whether it is
 * escalated to critical, so the false-positive cases below are as load-bearing
 * as the true-positive ones. Each `false` expectation names content that used to
 * be reported as a leaked credential.
 */
import { describe, it, expect } from "vitest";
import {
  hasCredentialPattern,
  findCredentialIndicators,
  redactCredentialValues,
  isPlaceholderValue,
  isBenignHighEntropy,
  maskValue,
} from "../../../server/scanner/credential-detection";

describe("known key formats", () => {
  it("detects issuer-shaped keys without needing context", () => {
    expect(hasCredentialPattern("AKIAIOSFODNN7EXAMPLE")).toBe(true);
    expect(hasCredentialPattern("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi0")).toBe(true);
    expect(hasCredentialPattern("AIzaSyA1234567890abcdefghijklmnopqrstuv")).toBe(true);
    expect(hasCredentialPattern("-----BEGIN RSA PRIVATE KEY-----")).toBe(true);
  });

  it("detects a database URI only when it carries credentials", () => {
    expect(hasCredentialPattern("postgres://appuser:s3cr3tpw@db.internal:5432/app")).toBe(true);
    expect(hasCredentialPattern("Connect with postgres://db.example.com:5432/app")).toBe(false);
  });
});

describe("false positives that used to be reported as critical", () => {
  /**
   * A bare UUID was listed as a "Heroku/generic API key". Every request id,
   * trace id, asset hash and framework key on the modern web is a UUID, so any
   * page containing one counted as carrying credentials — which escalated
   * "Exposed Environment File" from high to critical / CVSS 9.8.
   */
  it("does not treat a bare UUID as a credential", () => {
    expect(hasCredentialPattern("Request ID: 550e8400-e29b-41d4-a716-446655440000")).toBe(false);
    expect(isBenignHighEntropy("550e8400-e29b-41d4-a716-446655440000")).toBe(true);
  });

  it("does not treat asset hashes or content digests as credentials", () => {
    expect(hasCredentialPattern('<script src="/assets/index.9f2c1a4b8e7d6c5f0a1b2c3d4e5f6071.js"></script>')).toBe(false);
    expect(isBenignHighEntropy("d41d8cd98f00b204e9800998ecf8427e")).toBe(true);
    expect(isBenignHighEntropy("sha384-abcdefghijklmnopqrstuvwxyz0123456789")).toBe(true);
  });

  it("does not treat a minified script full of high-entropy tokens as a leak", () => {
    const minified = "!function(e,t){var n=\"aK3mL9pN2xRtWz7bQ4jF8cY5d\",r=\"Xy9Zq2Wv8Nb4Mk6Lp0Rj3Tf7H\";e.exports=n+r}(module);";
    expect(hasCredentialPattern(minified)).toBe(false);
  });

  /**
   * `.env.example` and compose templates exist to be published. Reporting their
   * placeholder values as leaked credentials is the most common way a
   * config-file check turns into noise.
   */
  it("does not report documentation placeholders", () => {
    expect(hasCredentialPattern("API_KEY=your_api_key_here")).toBe(false);
    expect(hasCredentialPattern("DB_PASSWORD=")).toBe(false);
    expect(hasCredentialPattern("SECRET_TOKEN=changeme")).toBe(false);
    expect(hasCredentialPattern("password=${DB_PASSWORD}")).toBe(false);
    expect(hasCredentialPattern("api_key=<your-key>")).toBe(false);
    expect(isPlaceholderValue("xxxxx")).toBe(true);
    expect(isPlaceholderValue("hunter2")).toBe(false);
  });
});

describe("named assignments", () => {
  it("detects a real value behind a secret-shaped key name", () => {
    expect(hasCredentialPattern("password=mysecret123")).toBe(true);
    expect(hasCredentialPattern('DB_PASS="hunter2"')).toBe(true);
    expect(hasCredentialPattern("client_secret: 7f3a9b2c8d1e4f6a0b5c")).toBe(true);
  });

  it("ignores prose with no assignment", () => {
    expect(hasCredentialPattern("Hello world this is a normal page")).toBe(false);
    expect(hasCredentialPattern("Reset your password on the account settings page")).toBe(false);
    expect(hasCredentialPattern("<html><body>Login page</body></html>")).toBe(false);
  });
});

describe("lone candidate tokens", () => {
  /**
   * A caller that has already isolated a value is asking a different question
   * from a caller handing over a whole document, so entropy is allowed to decide
   * on its own here — and only here.
   */
  it("judges an isolated high-entropy token on entropy alone", () => {
    expect(hasCredentialPattern("aK3mL9pN2xRtWz7bQ4jF8cY5d")).toBe(true);
    expect(hasCredentialPattern("abc123")).toBe(false);
  });

  it("still refuses a benign shape even when handed over alone", () => {
    expect(hasCredentialPattern("550e8400-e29b-41d4-a716-446655440000")).toBe(false);
    expect(hasCredentialPattern("d41d8cd98f00b204e9800998ecf8427e")).toBe(false);
  });
});

describe("redaction", () => {
  /**
   * The finding record is stored in Postgres, rendered in a browser and written
   * into exported reports. A helper that only rewrote `name=value` shapes let a
   * bare AWS key through all three verbatim.
   */
  it("masks standalone issuer-shaped keys, not just name=value pairs", () => {
    const out = redactCredentialValues("key is AKIAIOSFODNN7EXAMPLE and password=hunter2swordfish");
    expect(out).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(out).not.toContain("hunter2swordfish");
  });

  it("keeps enough of a value to recognise the key type", () => {
    expect(maskValue("AKIAIOSFODNN7EXAMPLE")).toMatch(/^AKIA\*+MPLE$/);
    expect(maskValue("short")).toBe("*****");
  });

  it("reports every distinct indicator it finds", () => {
    const indicators = findCredentialIndicators("AKIAIOSFODNN7EXAMPLE\nDB_PASSWORD=realvalue123\n");
    expect(indicators.map((i) => i.kind)).toContain("known-key");
    expect(indicators.some((i) => i.kind === "named-assignment" || i.kind === "high-entropy-value")).toBe(true);
    expect(indicators.every((i) => !i.redacted.includes("realvalue123"))).toBe(true);
  });
});
