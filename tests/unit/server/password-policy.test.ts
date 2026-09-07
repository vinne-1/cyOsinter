/**
 * Password policy — OWASP ASVS 5.0 V6.2.
 *
 * The application previously enforced a 12-character minimum and nothing else,
 * so `q1w2e3r4t5y6` — a keyboard walk near the top of every breach corpus — was
 * an acceptable password, while the standard's actual intent (screen against
 * known-common passwords, and impose NO composition rules) was unimplemented.
 */
import { describe, it, expect } from "vitest";
import {
  checkPassword,
  PASSWORD_MIN_LENGTH,
  PASSWORD_MAX_LENGTH,
  COMMON_PASSWORD_COUNT,
} from "../../../server/password-policy";

describe("V6.2.4 — screening against common passwords", () => {
  /** ASVS asks for at least the top 3000 matching the application's policy. */
  it("screens against more than the 3000 the standard requires", () => {
    expect(COMMON_PASSWORD_COUNT).toBeGreaterThanOrEqual(3000);
  });

  it("rejects common passwords that satisfy the length rule", () => {
    for (const p of ["q1w2e3r4t5y6", "1qaz2wsx3edc", "qwerty123456", "1q2w3e4r5t6y"]) {
      const r = checkPassword(p);
      expect(r.ok, p).toBe(false);
      expect(r.reason, p).toMatch(/commonly used/i);
    }
  });

  /** Capitalising a common password does not make it uncommon. */
  it("is case-insensitive", () => {
    expect(checkPassword("QWERTY123456").ok).toBe(false);
    expect(checkPassword("Qwerty123456").ok).toBe(false);
  });

  it("accepts a long unremarkable passphrase", () => {
    expect(checkPassword("correct horse battery staple").ok).toBe(true);
    expect(checkPassword("plum-lantern-verdict-9931").ok).toBe(true);
  });
});

describe("V6.2.5 — no composition rules", () => {
  /**
   * The point of the requirement: forcing an uppercase/digit/symbol mix pushes
   * people to `Password1!` and measurably reduces real strength. A long
   * all-lowercase passphrase must be accepted.
   */
  it("accepts an all-lowercase passphrase with no digits or symbols", () => {
    expect(checkPassword("thistlebrooksandpiper").ok).toBe(true);
  });

  it("accepts an all-digit password of sufficient length that is not common", () => {
    expect(checkPassword("839201746650382914").ok).toBe(true);
  });
});

describe("V6.2.1 — length", () => {
  it("rejects anything under the minimum", () => {
    expect(checkPassword("a".repeat(PASSWORD_MIN_LENGTH - 1)).ok).toBe(false);
    expect(checkPassword("short").reason).toMatch(/at least/i);
  });

  /** Bounded only to stop a huge input burning CPU in the KDF. */
  it("rejects absurdly long input", () => {
    expect(checkPassword("a".repeat(PASSWORD_MAX_LENGTH + 1)).ok).toBe(false);
  });

  it("accepts exactly the minimum when it is not otherwise weak", () => {
    const p = "vqxmzlprtdkw";
    expect(p.length).toBe(PASSWORD_MIN_LENGTH);
    expect(checkPassword(p).ok).toBe(true);
  });
});

describe("identifier and degenerate cases", () => {
  it("refuses the account's own email or its local part", () => {
    expect(checkPassword("alice.brennan@example.com", ["alice.brennan@example.com"]).ok).toBe(false);
    expect(checkPassword("alice.brennan", ["alice.brennan@example.com"]).ok).toBe(false);
  });

  it("ignores empty or missing identifiers rather than throwing", () => {
    expect(checkPassword("plum-lantern-verdict-9931", [null, undefined, "", "  "]).ok).toBe(true);
  });

  /** Clears any length rule, has almost no entropy, and no corpus lists every length. */
  it("refuses a single repeated character", () => {
    expect(checkPassword("aaaaaaaaaaaaaaaa").ok).toBe(false);
    expect(checkPassword("################").ok).toBe(false);
  });

  it("does not treat a short identifier as a substring ban", () => {
    // "bo" is too short to anchor on; banning it would reject sound passwords.
    expect(checkPassword("thistlebrooksandpiper", ["bo@example.com"]).ok).toBe(true);
  });

  it("handles non-string input without throwing", () => {
    expect(checkPassword(undefined as unknown as string).ok).toBe(false);
    expect(checkPassword(null as unknown as string).ok).toBe(false);
  });
});

describe("V6.2.8 — the password is used exactly as received", () => {
  /**
   * No trimming or case folding anywhere in the check, so a password whose
   * leading space is meaningful stays distinct from one without it.
   */
  it("treats surrounding whitespace as part of the password", () => {
    expect(checkPassword(" plum-lantern-verdict-993").ok).toBe(true);
    expect(checkPassword("plum-lantern-verdict-9931").ok).toBe(true);
  });
});
