/**
 * Subdomain Takeover Detection Module
 *
 * Checks discovered subdomains for takeover vulnerabilities by:
 * 1. Identifying dangling CNAME records pointing to deprovisioned services
 * 2. Fingerprint matching against known vulnerable service providers
 * 3. Checking for NXDOMAIN responses on CNAME targets
 */

import { createLogger } from "../logger.js";
import { httpGet } from "./http.js";
import { resolveDNS, getNSRecords } from "./dns.js";
import { registrableDomain } from "./ransomware-watch.js";
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
  /**
   * Whether an attacker could actually CLAIM the target — a known multi-tenant
   * service, or an unregistered domain. False for a dangling CNAME inside a zone
   * that somebody else still controls, which is a hygiene issue, not a takeover.
   */
  takeoverable: boolean;
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
  httpProbe = true,
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

    // Check if the CNAME target resolves, via the reliable public resolver
    // (resolveDNS). Using the flaky system resolver here risked a transient
    // timeout being mis-read as NXDOMAIN → a false-positive CRITICAL takeover.
    const cnameTargetDns = await resolveDNS(cname);
    const cnameResolves = cnameTargetDns.resolved;

    // A CNAME that does not resolve is a dangling record — but that is not the
    // same thing as a takeover, and reporting it as one at critical severity was
    // wrong for the common case.
    //
    // A takeover needs the target to be CLAIMABLE by an attacker. Two ways:
    //
    //   1. It points at a known multi-tenant service (GitHub Pages, Heroku, S3)
    //      where anyone can register the unclaimed hostname.
    //   2. Its registrable domain is itself unregistered, so an attacker can buy
    //      the domain and serve whatever they like.
    //
    // If neither holds — the target's apex is registered and delegated, it is
    // simply a broken record inside somebody's own zone — the finding is DNS
    // hygiene, not a critical takeover. Calling that critical is how a scanner
    // loses a reader's trust for every other finding it reports.
    if (!cnameResolves) {
      if (matchedService) {
        return {
          subdomain,
          cname,
          service: matchedService.service,
          vulnerable: true,
          confidence: "high",
          takeoverable: true,
          evidence: `CNAME target ${cname} does not resolve (NXDOMAIN) and matches the ${matchedService.service} pattern, where an unclaimed hostname can be registered by anyone`,
        };
      }

      const apex = registrableDomain(cname);
      const apexNs = await getNSRecords(apex);
      if (apexNs.length === 0) {
        return {
          subdomain,
          cname,
          service: null,
          vulnerable: true,
          confidence: "medium",
          takeoverable: true,
          evidence: `CNAME target ${cname} does not resolve and its registrable domain ${apex} has no NS records — the domain appears unregistered and could be bought by an attacker`,
        };
      }

      return {
        subdomain,
        cname,
        service: null,
        vulnerable: true,
        confidence: "low",
        takeoverable: false,
        evidence: `CNAME target ${cname} does not resolve, but ${apex} is registered and delegated (NS: ${apexNs.slice(0, 2).join(", ")}) — a broken record inside a zone somebody else controls, not a claimable name`,
      };
    }

    // If CNAME resolves but matches a known service, probe the HTTP response.
    // Skipped in passive mode — the DNS/NXDOMAIN signal above is fully passive.
    if (httpProbe && matchedService && matchedService.bodyFingerprints.length > 0) {
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
              takeoverable: true,
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
  opts?: { httpProbe?: boolean },
): Promise<TakeoverScanResults> {
  const findings: VerifiedFinding[] = [];
  const results: TakeoverResult[] = [];
  const now = new Date().toISOString();
  const httpProbe = opts?.httpProbe ?? true;

  if (subdomains.length === 0) return { findings, results };

  const checked = await runWithConcurrency(
    subdomains,
    10,
    (subdomain) => checkSubdomainTakeover(subdomain, httpProbe),
    signal,
  );

  for (const result of checked) {
    if (!result || !result.vulnerable) continue;
    results.push(result);

    // Severity follows what an attacker can actually do, not merely that a
    // record is broken.
    const severity = !result.takeoverable ? "low" : result.confidence === "high" ? "critical" : "high";
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
      title: result.takeoverable
        ? `Subdomain Takeover: ${result.subdomain}`
        : `Dangling DNS Record: ${result.subdomain}`,
      description: result.takeoverable
        ? `The subdomain ${result.subdomain} has a CNAME record pointing to ${result.cname}${result.service ? ` (${result.service})` : ""}, which an attacker can claim. Registering it would let them serve content on your subdomain — inheriting its reputation, and any cookies scoped to the parent domain.`
        : `The subdomain ${result.subdomain} points to ${result.cname}, which no longer resolves. The target's domain is still registered and delegated to somebody else's nameservers, so this is not currently claimable — but it is a broken record that will silently break links and may become takeoverable if that domain lapses.`,
      severity,
      category: result.takeoverable ? "subdomain_takeover" : "dns_misconfiguration",
      affectedAsset: result.subdomain,
      cvssScore: severity === "critical" ? "9.8" : severity === "high" ? "8.1" : "3.1",
      remediation: result.takeoverable
        ? `Remove the dangling CNAME record for ${result.subdomain} or re-provision the ${result.service ?? "target"} service. If the service is no longer needed, delete the DNS record entirely.`
        : `Delete the CNAME record for ${result.subdomain}, or repoint it at a host you control. Re-check it if ${registrableDomain(result.cname)} ever expires.`,
      evidence,
    });
  }

  log.info({ checked: subdomains.length, vulnerable: results.length }, "Subdomain takeover scan complete");
  return { findings, results };
}
