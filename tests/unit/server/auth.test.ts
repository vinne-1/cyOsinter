/**
 * Unit tests for server/auth.ts — pure, no database.
 *
 * Tests: hashPassword, verifyPassword, generateToken, generateRefreshToken.
 * DB-dependent functions (createSession, validateSession, etc.) are excluded
 * from this unit suite; integration tests would cover them with a real DB or
 * a drizzle mock.
 */

import { describe, it, expect, vi } from "vitest";

// Mock the database so auth.ts can be imported without DATABASE_URL
vi.mock("../../../server/db", () => ({
  db: {},
}));

import {
  hashPassword,
  verifyPassword,
  generateToken,
  generateRefreshToken,
} from "../../../server/auth";

// ---------------------------------------------------------------------------
// hashPassword
// ---------------------------------------------------------------------------
describe("hashPassword", () => {
  it("returns a non-empty string", async () => {
    const hash = await hashPassword("secret123");
    expect(typeof hash).toBe("string");
    expect(hash.length).toBeGreaterThan(0);
  });

  it("includes a salt:hash structure (contains exactly one colon separator)", async () => {
    const hash = await hashPassword("mypassword");
    const parts = hash.split(":");
    expect(parts).toHaveLength(2);
    expect(parts[0].length).toBeGreaterThan(0); // salt
    expect(parts[1].length).toBeGreaterThan(0); // hash
  });

  it("produces different hashes for the same password (salt is random)", async () => {
    const [h1, h2] = await Promise.all([
      hashPassword("samepassword"),
      hashPassword("samepassword"),
    ]);
    expect(h1).not.toBe(h2);
  });

  it("produces different hashes for different passwords", async () => {
    const [h1, h2] = await Promise.all([
      hashPassword("password1"),
      hashPassword("password2"),
    ]);
    expect(h1).not.toBe(h2);
  });

  it("handles empty string password", async () => {
    const hash = await hashPassword("");
    expect(hash).toBeTruthy();
    const parts = hash.split(":");
    expect(parts).toHaveLength(2);
  });

  it("handles very long passwords", async () => {
    const longPw = "a".repeat(1024);
    const hash = await hashPassword(longPw);
    expect(hash).toBeTruthy();
  });

  it("handles passwords with special characters", async () => {
    const specialPw = "p@$$w0rd!#%^&*()_+-={}|[]\\;':\",./<>?";
    const hash = await hashPassword(specialPw);
    expect(hash).toBeTruthy();
  });

  it("handles Unicode passwords", async () => {
    const unicodePw = "パスワード🔐€ñ";
    const hash = await hashPassword(unicodePw);
    expect(hash).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// verifyPassword
// ---------------------------------------------------------------------------
describe("verifyPassword", () => {
  it("returns true for correct password", async () => {
    const hash = await hashPassword("correcthorsebatterystaple");
    expect(await verifyPassword("correcthorsebatterystaple", hash)).toBe(true);
  });

  it("returns false for wrong password", async () => {
    const hash = await hashPassword("correctpassword");
    expect(await verifyPassword("wrongpassword", hash)).toBe(false);
  });

  it("is case-sensitive", async () => {
    const hash = await hashPassword("Secret");
    expect(await verifyPassword("secret", hash)).toBe(false);
    expect(await verifyPassword("SECRET", hash)).toBe(false);
    expect(await verifyPassword("Secret", hash)).toBe(true);
  });

  it("returns false for a hash with no colon separator", async () => {
    expect(await verifyPassword("any", "noseparatorhashvalue")).toBe(false);
  });

  it("returns false for empty stored hash", async () => {
    expect(await verifyPassword("password", "")).toBe(false);
  });

  it("returns false for empty password against a real hash", async () => {
    const hash = await hashPassword("notempty");
    expect(await verifyPassword("", hash)).toBe(false);
  });

  it("roundtrip: hash then verify works for multiple passwords", async () => {
    const passwords = ["alpha", "beta123", "!@#$%^", "", "🔑"];
    for (const pw of passwords) {
      const hash = await hashPassword(pw);
      expect(await verifyPassword(pw, hash)).toBe(true);
    }
  });

  it("returns false for a stored hash with an empty hash segment after colon", async () => {
    // Salt present but hash portion is empty — the !storedHash guard returns false early
    const noHash = "a".repeat(32) + ":";
    await expect(verifyPassword("test", noHash)).resolves.toBe(false);
  });
});

// ---------------------------------------------------------------------------
// generateToken
// ---------------------------------------------------------------------------
describe("generateToken", () => {
  it("returns a string", () => {
    expect(typeof generateToken()).toBe("string");
  });

  it("returns a 64-character hex string (32 bytes)", () => {
    const token = generateToken();
    expect(token).toHaveLength(64);
    expect(token).toMatch(/^[0-9a-f]{64}$/);
  });

  it("generates unique tokens on successive calls", () => {
    const tokens = new Set(Array.from({ length: 100 }, () => generateToken()));
    // All 100 should be unique
    expect(tokens.size).toBe(100);
  });

  it("is not empty", () => {
    expect(generateToken()).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// generateRefreshToken
// ---------------------------------------------------------------------------
describe("generateRefreshToken", () => {
  it("returns a string", () => {
    expect(typeof generateRefreshToken()).toBe("string");
  });

  it("returns a 64-character hex string (32 bytes)", () => {
    const token = generateRefreshToken();
    expect(token).toHaveLength(64);
    expect(token).toMatch(/^[0-9a-f]{64}$/);
  });

  it("generates unique tokens on successive calls", () => {
    const tokens = new Set(Array.from({ length: 100 }, () => generateRefreshToken()));
    expect(tokens.size).toBe(100);
  });

  it("is distinct from a generateToken result (probabilistically)", () => {
    // Extremely unlikely to collide — just ensure we're calling separate CSPRNG draws
    const access = generateToken();
    const refresh = generateRefreshToken();
    expect(access).not.toBe(refresh);
  });
});
