/**
 * Browser-side breach check hooks — call CORS-open free APIs directly.
 * No server proxy, no API keys, no backend changes required.
 */

import { useQuery } from "@tanstack/react-query";

// ── EmailRep.io ────────────────────────────────────────────────────────────────

export interface EmailRepResult {
  email: string;
  reputation: "high" | "medium" | "low" | "none";
  suspicious: boolean;
  references: number;
  details: {
    blacklisted: boolean;
    malicious_activity: boolean;
    malicious_activity_recent: boolean;
    credentials_leaked: boolean;
    credentials_leaked_recent: boolean;
    data_breach: boolean;
    first_seen: string | null;
    last_seen: string | null;
    domain_exists: boolean;
    domain_reputation: string | null;
    new_domain: boolean;
    days_since_domain_creation: number | null;
    spam: boolean;
    free_provider: boolean;
    disposable: boolean;
    deliverable: boolean | null;
    accept_all: boolean | null;
    valid_mx: boolean;
    primary_mx: string | null;
    spoofable: boolean;
    spf_strict: boolean;
    dmarc_enforced: boolean;
    profiles: string[];
  };
}

export function useEmailRepCheck(email: string | null | undefined) {
  return useQuery<EmailRepResult>({
    queryKey: ["emailrep", email],
    enabled: !!email && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email),
    staleTime: 10 * 60 * 1000, // 10 min
    gcTime: 30 * 60 * 1000,
    retry: false,
    queryFn: async () => {
      const res = await fetch(`https://emailrep.io/${encodeURIComponent(email!)}`, {
        headers: { "User-Agent": "cyoshield-breach-check/1.0" },
        signal: AbortSignal.timeout(8000),
      });
      if (!res.ok) throw new Error(`EmailRep returned ${res.status}`);
      return res.json() as Promise<EmailRepResult>;
    },
  });
}

// ── Shodan InternetDB (keyless, CORS-open) ─────────────────────────────────────

export interface ShodanInternetDBResult {
  ip: string;
  ports: number[];
  vulns: string[];
  hostnames: string[];
  tags: string[];
  cpes: string[];
}

export function useShodanInternetDB(ip: string | null | undefined) {
  return useQuery<ShodanInternetDBResult>({
    queryKey: ["shodan-internetdb", ip],
    enabled: !!ip && /^(\d{1,3}\.){3}\d{1,3}$/.test(ip),
    staleTime: 30 * 60 * 1000, // 30 min
    gcTime: 60 * 60 * 1000,
    retry: false,
    queryFn: async () => {
      const res = await fetch(`https://internetdb.shodan.io/${encodeURIComponent(ip!)}`, {
        signal: AbortSignal.timeout(8000),
      });
      if (!res.ok) throw new Error(`Shodan InternetDB returned ${res.status}`);
      return res.json() as Promise<ShodanInternetDBResult>;
    },
  });
}
