import { describe, it, expect } from "vitest";
import {
  base32Encode,
  base32Decode,
  generateTotp,
  generateTotpSecret,
  hotp,
  totpKeyUri,
  verifyTotp,
  TOTP_PERIOD_SECONDS,
} from "../../../server/totp";

describe("base32", () => {
  it("round-trips arbitrary bytes", () => {
    const buf = Buffer.from([0x00, 0xff, 0x10, 0x7a, 0x42, 0x99, 0x01]);
    expect(base32Decode(base32Encode(buf))).toEqual(buf);
  });

  it("matches RFC 4648 test vectors", () => {
    expect(base32Encode(Buffer.from("f"))).toBe("MY");
    expect(base32Encode(Buffer.from("fo"))).toBe("MZXQ");
    expect(base32Encode(Buffer.from("foo"))).toBe("MZXW6");
    expect(base32Encode(Buffer.from("foobar"))).toBe("MZXW6YTBOI");
  });

  it("tolerates lowercase, padding and whitespace on decode", () => {
    expect(base32Decode("mzxw6ytboi")).toEqual(Buffer.from("foobar"));
    expect(base32Decode("MZXW6YTBOI======")).toEqual(Buffer.from("foobar"));
    expect(base32Decode("MZXW 6YTB OI")).toEqual(Buffer.from("foobar"));
  });

  it("rejects characters outside the alphabet", () => {
    expect(() => base32Decode("MZXW6YTB01")).toThrow(/Invalid base32/);
  });
});

describe("hotp — RFC 4226 Appendix D vectors", () => {
  // The RFC's reference secret is the ASCII string "12345678901234567890".
  const secret = Buffer.from("12345678901234567890", "ascii");
  const expected = [
    "755224", "287082", "359152", "969429", "338314",
    "254676", "287922", "162583", "399871", "520489",
  ];

  it.each(expected.map((code, counter) => [counter, code]))(
    "counter %i produces %s",
    (counter, code) => {
      expect(hotp(secret, counter as number)).toBe(code);
    },
  );
});

describe("totp — RFC 6238 vectors", () => {
  // Same reference secret, base32-encoded as an authenticator would store it.
  const secretB32 = base32Encode(Buffer.from("12345678901234567890", "ascii"));

  // RFC 6238 Appendix B, SHA-1 rows, truncated to the 6 digits this app uses.
  it.each([
    [59, "287082"],
    [1111111109, "081804"],
    [1111111111, "050471"],
    [1234567890, "005924"],
    [2000000000, "279037"],
  ])("unix time %i produces %s", (seconds, code) => {
    expect(generateTotp(secretB32, (seconds as number) * 1000)).toBe(code);
  });
});

describe("verifyTotp", () => {
  const secret = generateTotpSecret();
  const now = 1_700_000_000_000;

  it("accepts the code for the current period", () => {
    expect(verifyTotp(secret, generateTotp(secret, now), { atMs: now })).toBe(true);
  });

  it("accepts one period of clock skew in each direction", () => {
    const step = TOTP_PERIOD_SECONDS * 1000;
    expect(verifyTotp(secret, generateTotp(secret, now - step), { atMs: now })).toBe(true);
    expect(verifyTotp(secret, generateTotp(secret, now + step), { atMs: now })).toBe(true);
  });

  it("rejects a code two periods away", () => {
    const step = TOTP_PERIOD_SECONDS * 1000;
    expect(verifyTotp(secret, generateTotp(secret, now - 2 * step), { atMs: now })).toBe(false);
  });

  it("rejects malformed input without throwing", () => {
    for (const bad of ["", "12345", "1234567", "abcdef", "12 34 56 78"]) {
      expect(verifyTotp(secret, bad, { atMs: now })).toBe(false);
    }
  });

  it("rejects a code from a different secret", () => {
    const other = generateTotpSecret();
    expect(verifyTotp(secret, generateTotp(other, now), { atMs: now })).toBe(false);
  });

  it("returns false rather than throwing on an unparseable secret", () => {
    expect(verifyTotp("not!valid!base32", "123456", { atMs: now })).toBe(false);
  });

  it("ignores whitespace in the submitted code", () => {
    const code = generateTotp(secret, now);
    const spaced = `${code.slice(0, 3)} ${code.slice(3)}`;
    expect(verifyTotp(secret, spaced, { atMs: now })).toBe(true);
  });
});

describe("generateTotpSecret", () => {
  it("produces a decodable 20-byte secret by default", () => {
    expect(base32Decode(generateTotpSecret())).toHaveLength(20);
  });

  it("produces a different secret each call", () => {
    expect(generateTotpSecret()).not.toBe(generateTotpSecret());
  });
});

describe("totpKeyUri", () => {
  it("builds a scannable otpauth URI with the standard parameters", () => {
    const uri = totpKeyUri("JBSWY3DPEHPK3PXP", "analyst@example.com");
    expect(uri).toMatch(/^otpauth:\/\/totp\//);
    expect(uri).toContain("secret=JBSWY3DPEHPK3PXP");
    expect(uri).toContain("issuer=Cyshield");
    expect(uri).toContain("digits=6");
    expect(uri).toContain("period=30");
    // The label must be percent-encoded, so the ":" separator is not ambiguous.
    expect(uri).toContain("Cyshield%3Aanalyst%40example.com");
  });
});
