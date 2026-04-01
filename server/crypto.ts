/**
 * Symmetric encryption for credentials stored at rest.
 * Uses AES-256-GCM with a key derived from CREDENTIALS_KEY env var
 * or a randomly generated key persisted to .local/credentials.key.
 */

import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "crypto";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 32;
const SALT = "cyshield-credentials-salt";

const KEY_FILE_PATH = join(process.cwd(), ".local", "credentials.key");

function getEncryptionKey(): Buffer {
  // Prefer env var for production deployments
  const envKey = process.env.CREDENTIALS_KEY;
  if (envKey) {
    return scryptSync(envKey, SALT, KEY_LENGTH);
  }

  // Fall back to a file-based key (auto-generated on first use)
  const dir = join(process.cwd(), ".local");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

  if (existsSync(KEY_FILE_PATH)) {
    const rawKey = readFileSync(KEY_FILE_PATH, "utf-8").trim();
    return scryptSync(rawKey, SALT, KEY_LENGTH);
  }

  // Generate a new random key
  const newKey = randomBytes(32).toString("hex");
  writeFileSync(KEY_FILE_PATH, newKey, { mode: 0o600 });
  return scryptSync(newKey, SALT, KEY_LENGTH);
}

const encryptionKey = getEncryptionKey();

export function encrypt(plaintext: string): string {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, encryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  // Format: base64(iv + authTag + ciphertext)
  return Buffer.concat([iv, authTag, encrypted]).toString("base64");
}

export function decrypt(encoded: string): string {
  const buf = Buffer.from(encoded, "base64");
  const iv = buf.subarray(0, IV_LENGTH);
  const authTag = buf.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
  const ciphertext = buf.subarray(IV_LENGTH + AUTH_TAG_LENGTH);
  const decipher = createDecipheriv(ALGORITHM, encryptionKey, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}

export function encryptObject(obj: Record<string, unknown>): string {
  return encrypt(JSON.stringify(obj));
}

export function decryptObject<T = Record<string, unknown>>(encoded: string): T {
  return JSON.parse(decrypt(encoded)) as T;
}
