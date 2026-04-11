/**
 * Certificate Lifecycle Enrichment
 *
 * Extracts TLS certificate data from recon_modules, upserts into tls_certificates,
 * and creates expiry-warning findings for certs expiring within 30 days.
 */
import { createLogger } from "../logger";
import { storage } from "../storage";
import type { ReconModule } from "@shared/schema";

const log = createLogger("enrichment:cert-inventory");

interface RawCertData {
  daysRemaining?: number;
  validFrom?: string;
  validTo?: string;
  issuer?: string;
  subject?: string;
  serial?: string;
  protocol?: string;
  signatureAlgorithm?: string;
  altNames?: string[];
}

interface PerAssetTls {
  [host: string]: RawCertData;
}

/** Compute a stable fingerprint for deduplication (no real SHA-256 needed server-side). */
export function computeCertFingerprint(subject: string, issuer: string, serial: string): string {
  // Deterministic string concat for consistent upsert key — good enough without crypto
  return `${subject}|${issuer}|${serial}`.replace(/\s+/g, "").toLowerCase().slice(0, 120);
}

/** Whether the subject is a wildcard cert. */
export function isWildcardCert(subject: string | undefined): boolean {
  return (subject ?? "").includes("*.");
}

/** Compute days remaining until a given expiry date. */
export function computeDaysRemaining(validTo: string | undefined): number | null {
  if (!validTo) return null;
  const ms = new Date(validTo).getTime() - Date.now();
  return Math.ceil(ms / 86_400_000);
}

/** Extract all cert records from a single attack_surface recon module. */
export function extractCertsFromModule(
  workspaceId: string,
  module: ReconModule,
): Array<{
  workspaceId: string;
  host: string;
  subject: string | null;
  issuer: string | null;
  serial: string | null;
  fingerprint: string | null;
  validFrom: Date | null;
  validTo: Date | null;
  daysRemaining: number | null;
  protocol: string | null;
  san: string[];
  signatureAlgorithm: string | null;
  isWildcard: boolean;
}> {
  const data = module.data as Record<string, unknown>;
  const results: ReturnType<typeof extractCertsFromModule> = [];

  const domainTarget = module.target;

  // Primary ssl block (from the root domain)
  const ssl = data.ssl as RawCertData | undefined;
  if (ssl?.subject || ssl?.issuer || ssl?.validTo) {
    const subject = ssl.subject ?? "";
    const issuer = ssl.issuer ?? "";
    const serial = ssl.serial ?? "";
    results.push({
      workspaceId,
      host: domainTarget,
      subject: subject || null,
      issuer: issuer || null,
      serial: serial || null,
      fingerprint: computeCertFingerprint(subject, issuer, serial),
      validFrom: ssl.validFrom ? new Date(ssl.validFrom) : null,
      validTo: ssl.validTo ? new Date(ssl.validTo) : null,
      daysRemaining: ssl.daysRemaining ?? computeDaysRemaining(ssl.validTo),
      protocol: ssl.protocol ?? null,
      san: ssl.altNames ?? [],
      signatureAlgorithm: ssl.signatureAlgorithm ?? null,
      isWildcard: isWildcardCert(ssl.subject),
    });
  }

  // Per-asset TLS map (populated by easm-scan per discovered host)
  const perAssetTls = data.perAssetTls as PerAssetTls | undefined;
  if (perAssetTls && typeof perAssetTls === "object") {
    for (const [host, certData] of Object.entries(perAssetTls)) {
      if (!certData || typeof certData !== "object") continue;
      const subject = certData.subject ?? "";
      const issuer = certData.issuer ?? "";
      const serial = certData.serial ?? "";
      results.push({
        workspaceId,
        host,
        subject: subject || null,
        issuer: issuer || null,
        serial: serial || null,
        fingerprint: computeCertFingerprint(subject, issuer, serial),
        validFrom: certData.validFrom ? new Date(certData.validFrom) : null,
        validTo: certData.validTo ? new Date(certData.validTo) : null,
        daysRemaining: certData.daysRemaining ?? computeDaysRemaining(certData.validTo),
        protocol: certData.protocol ?? null,
        san: certData.altNames ?? [],
        signatureAlgorithm: certData.signatureAlgorithm ?? null,
        isWildcard: isWildcardCert(certData.subject),
      });
    }
  }

  return results;
}

/** Rebuild the certificate inventory for a workspace from recon_modules. */
export async function rebuildCertInventory(workspaceId: string): Promise<void> {
  try {
    const modules = await storage.getReconModulesByType(workspaceId, "attack_surface");
    let upserted = 0;

    for (const module of modules) {
      const certs = extractCertsFromModule(workspaceId, module);
      for (const cert of certs) {
        if (!cert.fingerprint) continue;
        await storage.upsertCertificate(cert);
        upserted++;
      }
    }

    // Create expiry alert findings for certs expiring within 30 days
    await createExpiryAlerts(workspaceId);

    log.info({ workspaceId, upserted }, "Certificate inventory rebuilt");
  } catch (err) {
    log.error({ err, workspaceId }, "Certificate inventory rebuild failed");
  }
}

const EXPIRY_THRESHOLDS = [7, 14, 30] as const;

async function createExpiryAlerts(workspaceId: string): Promise<void> {
  const certs = await storage.getCertificates(workspaceId);
  const now = Date.now();

  for (const cert of certs) {
    if (!cert.validTo) continue;
    const daysLeft = Math.ceil((new Date(cert.validTo).getTime() - now) / 86_400_000);
    if (daysLeft > 30 || daysLeft < 0) continue;

    const threshold = EXPIRY_THRESHOLDS.find((t) => daysLeft <= t) ?? 30;
    const severity = daysLeft <= 7 ? "critical" : daysLeft <= 14 ? "high" : "medium";

    // Avoid duplicate findings
    const exists = await storage.findingExists(
      workspaceId,
      `TLS Certificate Expiring in ${threshold} Days`,
      cert.host,
      "certificate_expiry",
    );
    if (exists) continue;

    await storage.createFinding({
      workspaceId,
      scanId: null,
      title: `TLS Certificate Expiring in ${threshold} Days`,
      description: `The TLS certificate for ${cert.host} (subject: ${cert.subject ?? "unknown"}) expires on ${new Date(cert.validTo).toLocaleDateString()} — ${daysLeft} day(s) remaining. Renew immediately to avoid service disruption and browser security warnings.`,
      severity,
      status: "open",
      category: "certificate_expiry",
      checkId: "cert-expiry",
      resourceType: "tls_certificate",
      resourceId: cert.host,
      provider: null,
      complianceTags: ["transport_security"],
      affectedAsset: cert.host,
      evidence: [{ daysRemaining: daysLeft, validTo: cert.validTo, subject: cert.subject, issuer: cert.issuer }] as Record<string, unknown>[],
      cvssScore: severity === "critical" ? "7.5" : severity === "high" ? "5.3" : "3.1",
      remediation: `Renew the TLS certificate for ${cert.host} before it expires. Contact your CA or use Let's Encrypt for automated renewal.`,
      assignee: null,
      assigneeId: null,
      priority: severity === "critical" ? 1 : severity === "high" ? 2 : 3,
      dueDate: cert.validTo ? new Date(cert.validTo) : null,
      slaBreached: daysLeft <= 0,
      workflowState: "open",
      groupId: null,
      verificationScanId: null,
      tags: ["certificate", "tls", "expiry"],
      aiEnrichment: null,
    });
  }
}
