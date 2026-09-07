/**
 * Password policy, in one place so registration, password change and any future
 * reset flow cannot drift apart.
 *
 * Written against OWASP ASVS 5.0 chapter V6.2, which is deliberately the
 * *opposite* of the traditional composition rules:
 *
 *  - **V6.2.1** — a 12-character minimum (the standard's floor is 8; 15 is its
 *    recommendation).
 *  - **V6.2.5** — NO composition rules. No "must contain an uppercase letter, a
 *    digit and a symbol". Those rules measurably push people toward
 *    `Password1!` and are why the requirement forbids them: length and
 *    unpredictability are what matter, and a rule that forces a predictable
 *    shape reduces both.
 *  - **V6.2.4** — checked against the most common passwords that would pass the
 *    length rule. This is the control that composition rules were always a poor
 *    proxy for: it rejects `q1w2e3r4t5y6` (which satisfies every classic
 *    composition rule) while allowing a long passphrase of plain lowercase words.
 *  - **V6.2.8** — the password is used exactly as received. No trimming, no case
 *    folding, no truncation, so what the user typed is what is verified.
 *
 * `maxLength` exists only to bound work: bcrypt-family hashes and any KDF will
 * happily accept megabytes and burn CPU doing it, which is a cheap denial of
 * service. 256 is far above any real passphrase.
 */
import { COMMON_PASSWORDS_RAW } from "./data/common-passwords.js";

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 256;

/**
 * Built once at module load. A Set keeps the check O(1) — this runs on the
 * registration and password-change paths, which are rate limited but should not
 * be doing a 5000-entry scan per attempt.
 */
const COMMON_PASSWORDS: ReadonlySet<string> = new Set(COMMON_PASSWORDS_RAW.split("\n"));

/** Number of known-common passwords screened against. Exposed for the tests and docs. */
export const COMMON_PASSWORD_COUNT = COMMON_PASSWORDS.size;

export interface PasswordCheck {
  ok: boolean;
  /** Safe to show the user: says what to change without hinting at any stored value. */
  reason?: string;
}

/**
 * Whether a password is acceptable.
 *
 * `identifiers` are values that must not BE the password — the email and display
 * name. A password equal to the account's own email is trivially guessable by
 * anyone who knows the account exists, and that is everyone who can see a
 * message from that user.
 */
export function checkPassword(password: string, identifiers: Array<string | null | undefined> = []): PasswordCheck {
  if (typeof password !== "string" || password.length < PASSWORD_MIN_LENGTH) {
    return { ok: false, reason: `Password must be at least ${PASSWORD_MIN_LENGTH} characters` };
  }
  if (password.length > PASSWORD_MAX_LENGTH) {
    return { ok: false, reason: `Password must be at most ${PASSWORD_MAX_LENGTH} characters` };
  }

  // Case-insensitive: if the lowercase form is this common, the password is weak
  // however it was capitalised.
  if (COMMON_PASSWORDS.has(password.toLowerCase())) {
    return {
      ok: false,
      reason: "This password appears in lists of commonly used passwords. Choose something less predictable.",
    };
  }

  const lowered = password.toLowerCase();
  for (const id of identifiers) {
    if (!id) continue;
    const value = id.trim().toLowerCase();
    if (!value) continue;
    // The local part of an email counts: "alice@example.com" → "alice".
    const local = value.includes("@") ? value.split("@")[0]! : value;
    if (lowered === value || (local.length >= 4 && lowered === local)) {
      return { ok: false, reason: "Password must not be your email address or name" };
    }
  }

  // A single repeated character clears any length rule but has almost no
  // entropy, and no realistic corpus can list every length of "aaaaaaaaaaaa".
  if (/^(.)\1+$/.test(password)) {
    return { ok: false, reason: "Password must not be a single repeated character" };
  }

  return { ok: true };
}
