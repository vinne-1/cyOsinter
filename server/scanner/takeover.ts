/**
 * Subdomain Takeover Detection Module
 *
 * Checks discovered subdomains for takeover vulnerabilities by:
 * 1. Identifying dangling CNAME records pointing to deprovisioned services
 * 2. Fingerprint matching against known vulnerable service providers
 * 3. Checking for NXDOMAIN responses on CNAME targets
 */

import dns from "dns/promises";
import { createLogger } from "../logger.js";
import { httpGet } from "./http.js";
import { resolveDNS } from "./dns.js";
import { runWithConcurrency } from "./utils.js";
import type { VerifiedFinding, EvidenceItem } from "./types.js";

const log = createLogger("scanner:takeover");

/** Known service fingerprints that indicate a subdomain may be claimable */
const SERVICE_FINGERPRINTS: Array<{
  service: string;
  cnames: string[];
  bodyFingerprints: string[];
  statusCodes: number[];
}> = [
  {
    service: "GitHub Pages",
    cnames: [".github.io"],
    bodyFingerprints: ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/)"],
    statusCodes: [404],
  },
  {
    service: "Heroku",
    cnames: [".herokuapp.com", ".herokussl.com", ".herokudns.com"],
    bodyFingerprints: ["No such app", "no-such-app", "herokucdn.com/error-pages"],
    statusCodes: [404],
  },
  {
    service: "AWS S3",
    cnames: [".s3.amazonaws.com", ".s3-website"],
    bodyFingerprints: ["NoSuchBucket", "The specified bucket does not exist"],
    statusCodes: [404],
  },
  {
    service: "AWS Elastic Beanstalk",
    cnames: [".elasticbeanstalk.com"],
    bodyFingerprints: [],
    statusCodes: [404],
  },
  {
    service: "Azure",
    cnames: [".azurewebsites.net", ".cloudapp.net", ".cloudapp.azure.com", ".trafficmanager.net", ".blob.core.windows.net", ".azure-api.net", ".azurefd.net"],
    bodyFingerprints: ["404 Web Site not found", "Web App - Pair with a custom domain"],
    statusCodes: [404],
  },
  {
    service: "Shopify",
    cnames: [".myshopify.com"],
    bodyFingerprints: ["Sorry, this shop is currently unavailable", "Only one step left"],
    statusCodes: [404],
  },
  {
    service: "Fastly",
    cnames: [".fastly.net", ".fastlylb.net"],
    bodyFingerprints: ["Fastly error: unknown domain"],
    statusCodes: [500],
  },
  {
    service: "Pantheon",
    cnames: [".pantheonsite.io"],
    bodyFingerprints: ["404 error unknown site", "The gods are wise"],
    statusCodes: [404],
  },
  {
    service: "Tumblr",
    cnames: [".tumblr.com"],
    bodyFingerprints: ["There's nothing here", "Whatever you were looking for doesn't currently exist"],
    statusCodes: [404],
  },
  {
    service: "WordPress.com",
    cnames: [".wordpress.com"],
    bodyFingerprints: ["Do you want to register"],
    statusCodes: [404],
  },
  {
    service: "Surge.sh",
    cnames: [".surge.sh"],
    bodyFingerprints: ["project not found"],
    statusCodes: [404],
  },
  {
    service: "Fly.io",
    cnames: [".fly.dev"],
    bodyFingerprints: ["404 Not Found"],
    statusCodes: [404],
  },
  {
    service: "Netlify",
    cnames: [".netlify.app", ".netlify.com"],
    bodyFingerprints: ["Not Found - Request ID"],
    statusCodes: [404],
  },
  {
    service: "Vercel",
    cnames: [".vercel.app", ".now.sh"],
    bodyFingerprints: ["The deployment could not be found"],
    statusCodes: [404],
  },
  {
    service: "Unbounce",
    cnames: [".unbouncepages.com"],
    bodyFingerprints: ["The requested URL was not found on this server"],
    statusCodes: [404],
  },
  {
    service: "Cargo Collective",
    cnames: [".cargocollective.com"],
    bodyFingerprints: ["404 Not Found"],
    statusCodes: [404],
  },
  {
    service: "Ghost",
    cnames: [".ghost.io"],
    bodyFingerprints: ["The thing you were looking for is no longer here"],
    statusCodes: [404],
  },
  {
    service: "Zendesk",
    cnames: [".zendesk.com"],
    bodyFingerprints: ["Help Center Closed"],
    statusCodes: [404],
  },
];

export interface TakeoverResult {
  subdomain: string;
  cname: string;
  service: string | null;
  vulnerable: boolean;
  confidence: "high" | "medium" | "low";
  evidence: string;
}

export interface TakeoverScanResults {
  findings: VerifiedFinding[];
  results: TakeoverResult[];
}

/**
 * Check a single subdomain for takeover vulnerability.
 */
async function checkSubdomainTakeover(
  subdomain: string,
): Promise<TakeoverResult | null> {
  try {
    const dnsResult = await resolveDNS(subdomain);
    if (dnsResult.cnames.length === 0) return null;

    const cname = dnsResult.cnames[0];
    const cnameLower = cname.toLowerCase();

    // Match against known service fingerprints
    const matchedService = SERVICE_FINGERPRINTS.find((fp) =>
      fp.cnames.some((c) => cnameLower.endsWith(c)),
    );

    // Check if CNAME target resolves
    let cnameResolves = true;
    try {
      await dns.resolve4(cname);
    } catch {
      cnameResolves = false;
    }

    // If CNAME doesn't resolve (NXDOMAIN), it's a strong takeover signal
    if (!cnameResolves) {
      return {
        subdomain,
        cname,
        service: matchedService?.service ?? null,
        vulnerable: true,
        confidence: matchedService ? "high" : "medium",
        evidence: `CNAME target ${cname} does not resolve (NXDOMAIN)${matchedService ? ` — known ${matchedService.service} pattern` : ""}`,
      };
    }

    // If CNAME resolves but matches a known service, probe the HTTP response
    if (matchedService && matchedService.bodyFingerprints.length > 0) {
      try {
        const httpResult = await httpGet(`https://${subdomain}`);
        if (httpResult) {
          const body = httpResult.body.toLowerCase();
          const matched = matchedService.bodyFingerprints.some((fp) =>
            body.includes(fp.toLowerCase()),
          );
          if (matched && matchedService.statusCodes.includes(httpResult.status)) {
            return {
              subdomain,
              cname,
              service: matchedService.service,
              vulnerable: true,
              confidence: "high",
              evidence: `HTTP response matches ${matchedService.service} unclaimed fingerprint (status ${httpResult.status})`,
            };
          }
        }
      } catch {
        // HTTP probe failed, not conclusive
      }
    }

    return null;
  } catch (err) {
    log.debug({ err, subdomain }, "Takeover check failed");
    return null;
  }
}

/**
 * Scan all provided subdomains for subdomain takeover vulnerabilities.
 */
export async function scanSubdomainTakeover(
  subdomains: string[],
  signal?: AbortSignal,
): Promise<TakeoverScanResults> {
  const findings: VerifiedFinding[] = [];
  const results: TakeoverResult[] = [];
  const now = new Date().toISOString();

  if (subdomains.length === 0) return { findings, results };

  const checked = await runWithConcurrency(
    subdomains,
    10,
    checkSubdomainTakeover,
    signal,
  );

  for (const result of checked) {
    if (!result || !result.vulnerable) continue;
    results.push(result);

    const severity = result.confidence === "high" ? "critical" : "high";
    const evidence: EvidenceItem[] = [
      {
        type: "dns_record",
        description: `Dangling CNAME detected: ${result.subdomain} → ${result.cname}`,
        snippet: result.evidence,
        source: "Subdomain Takeover Scanner",
        verifiedAt: now,
      },
    ];

    findings.push({
      title: `Subdomain Takeover: ${result.subdomain}`,
      description: `The subdomain ${result.subdomain} has a CNAME record pointing to ${result.cname}${result.service ? ` (${result.service})` : ""} which appears to be unclaimed. An attacker could register the target service and serve malicious content on this subdomain.`,
      severity,
      category: "subdomain_takeover",
      affectedAsset: result.subdomain,
      cvssScore: severity === "critical" ? "9.8" : "8.1",
      remediation: `Remove the dangling CNAME record for ${result.subdomain} or re-provision the ${result.service ?? "target"} service. If the service is no longer needed, delete the DNS record entirely.`,
      evidence,
    });
  }

  log.info({ checked: subdomains.length, vulnerable: results.length }, "Subdomain takeover scan complete");
  return { findings, results };
}
