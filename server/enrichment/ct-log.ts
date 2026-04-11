/**
 * Certificate Transparency Log Enrichment
 *
 * Queries the public crt.sh API to discover all TLS certificates ever issued
 * for a domain, then upserts them into tls_certificates via cert-inventory.
 *
 * crt.sh is a free CT log aggregator maintained by Sectigo. No auth required.
 * Rate limit: ~100-200 requests/min (we make at most 1 per scan).
 */
import { createLogger } from "../logger";
import { storage } from "../storage";
import { computeCertFingerprint, isWildcardCert, computeDaysRemaining } from "./cert-inventory";

const log = createLogger("enrichment:ct-log");

const CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json";
const FETCH_TIMEOUT_MS = 15_000;

interface CrtShEntry {
  id: number;
  issuer_ca_id: number;
  issuer_name: string;
  common_name: string;
  name_value: string;
  not_before: string;
  not_after: string;
  serial_number: string;
  entry_timestamp: string;
}

/** Fetch all CT log entries for a domain from crt.sh. */
export async function fetchCtLogCerts(domain: string): Promise<CrtShEntry[]> {
  const url = CRTSH_URL.replace("{domain}", encodeURIComponent(domain));
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      headers: { "User-Agent": "CyberShieldPro/1.0", Accept: "application/json" },
    });
    if (!res.ok) {
      log.warn({ status: res.status, domain }, "crt.sh returned non-200");
      return [];
    }
    const data = await res.json() as CrtShEntry[];
    return Array.isArray(data) ? data : [];
  } catch (err) {
    log.warn({ err, domain }, "crt.sh fetch failed");
    return [];
  }
}

/** Deduplicate CT entries by (issuer, notAfter, commonName). */
function deduplicateCtEntries(entries: CrtShEntry[]): CrtShEntry[] {
  const seen = new Set<string>();
  return entries.filter((e) => {
    const key = `${e.issuer_name}|${e.not_after}|${e.common_name}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Refresh the certificate inventory for a workspace using CT log data. */
export async function refreshCtLogCerts(workspaceId: string, domain: string): Promise<void> {
  try {
    const entries = await fetchCtLogCerts(domain);
    if (entries.length === 0) {
      log.info({ workspaceId, domain }, "No CT log entries found");
      return;
    }

    const deduped = deduplicateCtEntries(entries);
    let upserted = 0;

    for (const entry of deduped) {
      const subject = entry.common_name ?? "";
      const issuer = entry.issuer_name ?? "";
      const serial = entry.serial_number ?? "";

      if (!subject && !issuer) continue;

      const fingerprint = computeCertFingerprint(subject, issuer, serial);
      const validTo = entry.not_after ? new Date(entry.not_after) : null;
      const validFrom = entry.not_before ? new Date(entry.not_before) : null;
      const daysRemaining = computeDaysRemaining(entry.not_after);

      // Extract SANs from name_value (newline-separated list of hostnames)
      const san = (entry.name_value ?? "")
        .split(/\n/)
        .map((n) => n.trim().replace(/^\*\./, ""))
        .filter(Boolean);

      // Determine host: use the most specific name from SANs or commonName
      const host = san.find((n) => n.endsWith(`.${domain}`) || n === domain) ?? subject.replace(/^\*\./, "") ?? domain;

      await storage.upsertCertificate({
        workspaceId,
        host,
        subject: subject || null,
        issuer: issuer || null,
        serial: serial || null,
        fingerprint,
        validFrom,
        validTo,
        daysRemaining,
        protocol: null, // CT logs don't expose TLS version
        san,
        signatureAlgorithm: null,
        isWildcard: isWildcardCert(subject),
      });
      upserted++;
    }

    log.info({ workspaceId, domain, total: entries.length, upserted }, "CT log certificate inventory updated");
  } catch (err) {
    log.error({ err, workspaceId, domain }, "CT log enrichment failed");
  }
}
