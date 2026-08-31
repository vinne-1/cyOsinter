import { describe, it, expect, vi } from "vitest";

// The functions under test are pure; the mock only lets auth.ts be imported
// without a live DATABASE_URL.
vi.mock("../../../server/db", () => ({ db: {} }));

import {
  hashToken,
  isLockedOut,
  lockoutDurationMs,
  lockoutSecondsRemaining,
  MAX_FAILED_LOGINS,
  LOCKOUT_BASE_MS,
  LOCKOUT_MAX_MS,
} from "../../../server/auth";

describe("hashToken", () => {
  it("produces a 64-character hex sha-256 digest", () => {
    expect(hashToken("abc")).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic, so a token can be looked up by its hash", () => {
    expect(hashToken("same-token")).toBe(hashToken("same-token"));
  });

  it("differs for different tokens", () => {
    expect(hashToken("token-a")).not.toBe(hashToken("token-b"));
  });

  it("never returns the token itself", () => {
    // The point of hashing is that a read-only leak of the sessions table does
    // not hand the attacker live bearer tokens.
    const token = "b7f1c2d3e4a5b6c7d8e9f0a1b2c3d4e5";
    expect(hashToken(token)).not.toContain(token);
  });

  it("matches the known SHA-256 digest of a fixed input", () => {
    // Guards against someone swapping the algorithm without noticing that every
    // existing session would be silently invalidated.
    expect(hashToken("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });
});

describe("lockoutDurationMs", () => {
  it("does not lock before the threshold", () => {
    for (let attempts = 0; attempts < MAX_FAILED_LOGINS; attempts++) {
      expect(lockoutDurationMs(attempts)).toBe(0);
    }
  });

  it("locks for the base duration at exactly the threshold", () => {
    expect(lockoutDurationMs(MAX_FAILED_LOGINS)).toBe(LOCKOUT_BASE_MS);
  });

  it("doubles for each additional failure", () => {
    expect(lockoutDurationMs(MAX_FAILED_LOGINS + 1)).toBe(LOCKOUT_BASE_MS * 2);
    expect(lockoutDurationMs(MAX_FAILED_LOGINS + 2)).toBe(LOCKOUT_BASE_MS * 4);
    expect(lockoutDurationMs(MAX_FAILED_LOGINS + 3)).toBe(LOCKOUT_BASE_MS * 8);
  });

  it("caps the lockout so an account is never bricked", () => {
    // Without a cap, a sustained attack would lock a real user out for years.
    expect(lockoutDurationMs(MAX_FAILED_LOGINS + 40)).toBe(LOCKOUT_MAX_MS);
    expect(lockoutDurationMs(10_000)).toBe(LOCKOUT_MAX_MS);
  });

  it("throttles a sustained guessing run to a handful of attempts per hour", () => {
    // The property that actually matters: at the cap an attacker gets at most
    // one guess per LOCKOUT_MAX_MS.
    const guessesPerHour = 3_600_000 / LOCKOUT_MAX_MS;
    expect(guessesPerHour).toBeLessThanOrEqual(1);
  });
});

describe("isLockedOut", () => {
  it("is false when no lockout is set", () => {
    expect(isLockedOut({ lockedUntil: null })).toBe(false);
    expect(isLockedOut({})).toBe(false);
  });

  it("is true while the lockout is in the future", () => {
    expect(isLockedOut({ lockedUntil: new Date(Date.now() + 60_000) })).toBe(true);
  });

  it("is false once the lockout has passed, without needing a reset job", () => {
    expect(isLockedOut({ lockedUntil: new Date(Date.now() - 1000) })).toBe(false);
  });
});

describe("lockoutSecondsRemaining", () => {
  it("is zero when not locked", () => {
    expect(lockoutSecondsRemaining({ lockedUntil: null })).toBe(0);
  });

  it("reports the remaining window, rounded up", () => {
    const remaining = lockoutSecondsRemaining({ lockedUntil: new Date(Date.now() + 90_000) });
    expect(remaining).toBeGreaterThan(88);
    expect(remaining).toBeLessThanOrEqual(90);
  });

  it("never reports a negative remainder for an expired lockout", () => {
    expect(lockoutSecondsRemaining({ lockedUntil: new Date(Date.now() - 60_000) })).toBe(0);
  });
});
