import { createLogger } from "./logger.js";
import { storage } from "./storage.js";
import type { ScanProfileConfig } from "@shared/schema";

const log = createLogger("scan-profile-defaults");

interface PrebuiltProfile {
  name: string;
  description: string;
  scanType: string;
  mode: string;
  config: ScanProfileConfig;
  isDefault: boolean;
}

const PREBUILT_PROFILES: PrebuiltProfile[] = [
  {
    name: "Standard EASM",
    description: "Balanced external attack surface scan — subdomains, ports, TLS, headers, and DNS checks.",
    scanType: "easm",
    mode: "standard",
    isDefault: true,
    config: {
      portScanEnabled: true,
      enableTakeoverCheck: true,
      enableApiDiscovery: true,
      enableSecretScan: false,
      enableNuclei: false,
      subdomainWordlistCap: 5000,
      directoryWordlistCap: 2000,
      maxConcurrency: 5,
      timeoutMinutes: 30,
    },
  },
  {
    name: "Gold Deep Scan",
    description: "Comprehensive scan with Nuclei, secret detection, and extended wordlists. Slower but thorough.",
    scanType: "full",
    mode: "gold",
    isDefault: false,
    config: {
      portScanEnabled: true,
      enableTakeoverCheck: true,
      enableApiDiscovery: true,
      enableSecretScan: true,
      enableNuclei: true,
      subdomainWordlistCap: 50000,
      directoryWordlistCap: 10000,
      maxConcurrency: 3,
      timeoutMinutes: 120,
    },
  },
  {
    name: "OSINT Only",
    description: "Passive intelligence gathering — no active port scans or Nuclei probes.",
    scanType: "osint",
    mode: "standard",
    isDefault: false,
    config: {
      portScanEnabled: false,
      enableTakeoverCheck: false,
      enableApiDiscovery: false,
      enableSecretScan: false,
      enableNuclei: false,
      subdomainWordlistCap: 0,
      directoryWordlistCap: 0,
      maxConcurrency: 5,
      timeoutMinutes: 20,
    },
  },
];

/**
 * Creates the three prebuilt scan profiles for a workspace if they haven't
 * been seeded yet. Idempotent — skips profiles whose names already exist.
 */
export async function ensurePrebuiltScanProfiles(workspaceId: string): Promise<void> {
  const workspace = await storage.getWorkspace(workspaceId);
  if (!workspace) return;
  if (workspace.scanProfilesBootstrapped) return;

  const existing = await storage.getScanProfiles(workspaceId);
  const toCreate = PREBUILT_PROFILES.slice(existing.length);

  for (const profile of toCreate) {
    await storage.createScanProfile({ workspaceId, ...profile });
    log.info({ workspaceId, profile: profile.name }, "Created prebuilt scan profile");
  }

  await storage.updateWorkspace(workspaceId, { scanProfilesBootstrapped: true });
}
