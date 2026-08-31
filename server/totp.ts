/**
 * RFC 6238 TOTP (and the RFC 4226 HOTP it builds on).
 *
 * The previous implementation HMAC'd the *decimal string* of the time counter
 * with the secret taken as raw UTF-8. That is not RFC 6238, so codes never
 * matched Google Authenticator, Authy, 1Password or any other standard
 * authenticator — enrolment appeared to work and every login then failed.
 *
 * This implementation follows the spec: a base32 secret, an 8-byte big-endian
 * counter of `floor(unixSeconds / period)`, HMAC-SHA1, and dynamic truncation.
 */

import crypto from "crypto";

export const TOTP_PERIOD_SECONDS = 30;
export const TOTP_DIGITS = 6;
/**
 * How many periods either side of "now" are accepted, to tolerate clock skew
 * between the server and the user's phone. ±1 period = a 90-second window,
 * which is the usual balance between usability and replay exposure.
 */
export const TOTP_WINDOW = 1;

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** Encodes bytes as unpadded RFC 4648 base32 (the format authenticators expect). */
export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i]!;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

/** Decodes RFC 4648 base32. Tolerates lowercase, padding and spaces. */
export function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/=+$/, "").replace(/\s/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error("Invalid base32 character in TOTP secret");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** Generates a new random base32 secret. 20 bytes = 160 bits, per RFC 4226. */
export function generateTotpSecret(bytes = 20): string {
  return base32Encode(crypto.randomBytes(bytes));
}

/** RFC 4226 HOTP: HMAC-SHA1 over an 8-byte big-endian counter, then truncated. */
export function hotp(secret: Buffer, counter: number, digits = TOTP_DIGITS): string {
  const buf = Buffer.alloc(8);
  // Counter is a 64-bit value; Node's writeBigUInt64BE keeps it exact well past
  // the 2^53 boundary that a plain number multiplication would lose.
  buf.writeBigUInt64BE(BigInt(counter));

  const digest = crypto.createHmac("sha1", secret).update(buf).digest();

  // Dynamic truncation (RFC 4226 §5.3): the low nibble of the last byte picks
  // the 4-byte offset; the high bit is masked off to stay positive.
  const offset = digest[digest.length - 1]! & 0x0f;
  const binary =
    ((digest[offset]! & 0x7f) << 24) |
    ((digest[offset + 1]! & 0xff) << 16) |
    ((digest[offset + 2]! & 0xff) << 8) |
    (digest[offset + 3]! & 0xff);

  return String(binary % 10 ** digits).padStart(digits, "0");
}

/** The code valid at `atMs` (default: now). */
export function generateTotp(secretBase32: string, atMs: number = Date.now()): string {
  const counter = Math.floor(atMs / 1000 / TOTP_PERIOD_SECONDS);
  return hotp(base32Decode(secretBase32), counter);
}

/** Length-safe constant-time string comparison. */
function timingSafeEqualStr(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  // timingSafeEqual throws on a length mismatch, which would itself leak length.
  // Compare against a fixed-size digest so every path costs the same.
  const digestA = crypto.createHash("sha256").update(bufA).digest();
  const digestB = crypto.createHash("sha256").update(bufB).digest();
  return crypto.timingSafeEqual(digestA, digestB);
}

/**
 * Verifies a submitted code against the secret, accepting ±`window` periods.
 *
 * Every candidate is compared in constant time and the loop is not short-
 * circuited, so neither the result nor which period matched is observable from
 * timing.
 */
export function verifyTotp(
  secretBase32: string,
  code: string,
  opts?: { window?: number; atMs?: number },
): boolean {
  const window = opts?.window ?? TOTP_WINDOW;
  const atMs = opts?.atMs ?? Date.now();

  const submitted = code.replace(/\s/g, "");
  if (!/^\d{6}$/.test(submitted)) return false;

  let secret: Buffer;
  try {
    secret = base32Decode(secretBase32);
  } catch {
    return false;
  }

  const counter = Math.floor(atMs / 1000 / TOTP_PERIOD_SECONDS);
  let matched = false;
  for (let offset = -window; offset <= window; offset++) {
    const candidate = hotp(secret, counter + offset);
    // Bitwise-or rather than `||` so the loop always runs to completion.
    matched = timingSafeEqualStr(candidate, submitted) || matched;
  }
  return matched;
}

/**
 * Builds the `otpauth://` URI an authenticator app scans as a QR code.
 * Label and issuer are percent-encoded per the Key URI Format.
 */
export function totpKeyUri(secretBase32: string, account: string, issuer = "Cyshield"): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({
    secret: secretBase32,
    issuer,
    algorithm: "SHA1",
    digits: String(TOTP_DIGITS),
    period: String(TOTP_PERIOD_SECONDS),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}
