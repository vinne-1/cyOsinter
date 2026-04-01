import dns from "dns/promises";
import { createLogger } from "../logger.js";
import { runWithConcurrency } from "./utils.js";

const log = createLogger("cloud-discovery");

const BUCKET_CONCURRENCY = 10;
const HTTP_TIMEOUT_MS = 6000;

const CLOUD_CNAME_PATTERNS: Array<{ pattern: string; provider: string; service: string }> = [
  { pattern: ".cloudfront.net", provider: "AWS", service: "CloudFront CDN" },
  { pattern: ".amazonaws.com", provider: "AWS", service: "AWS Service" },
  { pattern: ".s3.amazonaws.com", provider: "AWS", service: "S3 Bucket" },
  { pattern: ".elasticbeanstalk.com", provider: "AWS", service: "Elastic Beanstalk" },
  { pattern: ".elb.amazonaws.com", provider: "AWS", service: "Elastic Load Balancer" },
  { pattern: ".azurewebsites.net", provider: "Azure", service: "Azure App Service" },
  { pattern: ".azureedge.net", provider: "Azure", service: "Azure CDN" },
  { pattern: ".blob.core.windows.net", provider: "Azure", service: "Azure Blob Storage" },
  { pattern: ".azure-api.net", provider: "Azure", service: "Azure API Management" },
  { pattern: ".trafficmanager.net", provider: "Azure", service: "Azure Traffic Manager" },
  { pattern: ".googleapis.com", provider: "GCP", service: "Google Cloud Service" },
  { pattern: ".storage.googleapis.com", provider: "GCP", service: "Google Cloud Storage" },
  { pattern: ".appspot.com", provider: "GCP", service: "Google App Engine" },
  { pattern: ".firebaseapp.com", provider: "Firebase", service: "Firebase Hosting" },
  { pattern: ".firebaseio.com", provider: "Firebase", service: "Firebase Realtime Database" },
  { pattern: ".netlify.app", provider: "Netlify", service: "Netlify Hosting" },
  { pattern: ".vercel.app", provider: "Vercel", service: "Vercel Hosting" },
  { pattern: ".herokuapp.com", provider: "Heroku", service: "Heroku App" },
  { pattern: ".pages.dev", provider: "Cloudflare", service: "Cloudflare Pages" },
  { pattern: ".workers.dev", provider: "Cloudflare", service: "Cloudflare Workers" },
];

const CLOUD_HEADER_PATTERNS: Array<{ header: string; prefix: string; provider: string; service: string }> = [
  { header: "x-amz-request-id", prefix: "", provider: "AWS", service: "AWS S3/Service" },
  { header: "x-amz-cf-id", prefix: "", provider: "AWS", service: "CloudFront" },
  { header: "x-amz-cf-pop", prefix: "", provider: "AWS", service: "CloudFront" },
  { header: "x-amz-bucket-region", prefix: "", provider: "AWS", service: "S3 Bucket" },
  { header: "x-goog-generation", prefix: "", provider: "GCP", service: "Google Cloud Storage" },
  { header: "x-goog-metageneration", prefix: "", provider: "GCP", service: "Google Cloud Storage" },
  { header: "x-goog-hash", prefix: "", provider: "GCP", service: "Google Cloud Storage" },
  { header: "x-ms-request-id", prefix: "", provider: "Azure", service: "Azure Storage" },
  { header: "x-ms-version", prefix: "", provider: "Azure", service: "Azure Storage" },
  { header: "x-ms-blob-type", prefix: "", provider: "Azure", service: "Azure Blob Storage" },
];

export interface CloudDiscoveryResults {
  buckets: Array<{
    provider: string;
    name: string;
    url: string;
    accessible: boolean;
    status: number;
  }>;
  cloudServices: Array<{
    provider: string;
    service: string;
    evidence: string;
  }>;
  findings: Array<{
    title: string;
    description: string;
    severity: string;
    category: string;
    affectedAsset: string;
    remediation: string;
  }>;
  duration: number;
}

interface BucketCheckTarget {
  provider: string;
  name: string;
  url: string;
}

function buildBucketTargets(domain: string): BucketCheckTarget[] {
  const baseName = domain.replace(/\./g, "-");
  const dotName = domain;
  const suffixes = ["", "-backup", "-assets", "-static", "-media", "-logs", "-dev", "-staging", "-prod"];

  const targets: BucketCheckTarget[] = [];

  for (const suffix of suffixes) {
    const name = baseName + suffix;
    const dotVariant = dotName + suffix;

    // AWS S3
    targets.push({ provider: "AWS", name, url: `https://${name}.s3.amazonaws.com` });
    if (name !== dotVariant) {
      targets.push({ provider: "AWS", name: dotVariant, url: `https://${dotVariant}.s3.amazonaws.com` });
    }

    // Azure Blob
    targets.push({ provider: "Azure", name, url: `https://${name}.blob.core.windows.net` });

    // GCP Storage
    targets.push({ provider: "GCP", name, url: `https://storage.googleapis.com/${name}` });
    if (name !== dotVariant) {
      targets.push({ provider: "GCP", name: dotVariant, url: `https://storage.googleapis.com/${dotVariant}` });
    }
  }

  return targets;
}

async function safeFetch(
  url: string,
  timeout: number,
  signal?: AbortSignal,
): Promise<{ status: number; headers: Record<string, string> } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  const onAbort = () => controller.abort();
  signal?.addEventListener("abort", onAbort, { once: true });

  try {
    const res = await fetch(url, {
      method: "HEAD",
      signal: controller.signal,
      headers: { "User-Agent": "Cyshield-Scanner/1.0" },
      redirect: "follow",
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k] = v; });
    return { status: res.status, headers };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", onAbort);
  }
}

function extractCloudServicesFromHeaders(
  headers: Record<string, string>,
  sourceUrl: string,
): Array<{ provider: string; service: string; evidence: string }> {
  const services: Array<{ provider: string; service: string; evidence: string }> = [];
  const seen = new Set<string>();

  for (const pattern of CLOUD_HEADER_PATTERNS) {
    const headerValue = headers[pattern.header];
    if (headerValue !== undefined) {
      const key = `${pattern.provider}:${pattern.service}`;
      if (!seen.has(key)) {
        seen.add(key);
        services.push({
          provider: pattern.provider,
          service: pattern.service,
          evidence: `Header "${pattern.header}" found on ${sourceUrl}`,
        });
      }
    }
  }

  return services;
}

async function checkCNAMEsForCloudServices(
  domain: string,
): Promise<Array<{ provider: string; service: string; evidence: string }>> {
  const services: Array<{ provider: string; service: string; evidence: string }> = [];

  try {
    const cnames = await dns.resolveCname(domain);
    for (const cname of cnames) {
      const cnameLower = cname.toLowerCase();
      for (const pattern of CLOUD_CNAME_PATTERNS) {
        if (cnameLower.endsWith(pattern.pattern)) {
          services.push({
            provider: pattern.provider,
            service: pattern.service,
            evidence: `CNAME ${domain} -> ${cname}`,
          });
          break;
        }
      }
    }
  } catch {
    log.warn({ domain }, "CNAME lookup failed for cloud discovery");
  }

  return services;
}

export async function runCloudDiscovery(
  domain: string,
  signal?: AbortSignal,
): Promise<CloudDiscoveryResults> {
  const startTime = Date.now();

  log.info({ domain }, "Starting cloud asset discovery");

  const bucketTargets = buildBucketTargets(domain);
  const buckets: CloudDiscoveryResults["buckets"] = [];
  const allCloudServices: CloudDiscoveryResults["cloudServices"] = [];
  const findings: CloudDiscoveryResults["findings"] = [];

  // Check bucket targets concurrently
  const bucketResults = await runWithConcurrency(
    bucketTargets,
    BUCKET_CONCURRENCY,
    async (target) => {
      const res = await safeFetch(target.url, HTTP_TIMEOUT_MS, signal);
      if (!res) return null;

      // Extract cloud service indicators from headers
      const headerServices = extractCloudServicesFromHeaders(res.headers, target.url);

      return {
        target,
        status: res.status,
        accessible: res.status === 200 || res.status === 403,
        headerServices,
      };
    },
    signal,
  );

  const seenServices = new Set<string>();

  for (const result of bucketResults) {
    if (!result) continue;

    if (result.accessible) {
      buckets.push({
        provider: result.target.provider,
        name: result.target.name,
        url: result.target.url,
        accessible: result.status === 200,
        status: result.status,
      });

      if (result.status === 200) {
        findings.push({
          title: `Publicly Accessible ${result.target.provider} Storage Bucket`,
          description: `The ${result.target.provider} storage bucket "${result.target.name}" at ${result.target.url} returned HTTP 200, indicating it is publicly accessible. This may expose sensitive data.`,
          severity: "high",
          category: "cloud_exposure",
          affectedAsset: result.target.url,
          remediation: `Review and restrict the bucket access policy for "${result.target.name}". Remove public access and implement proper IAM policies.`,
        });
      } else if (result.status === 403) {
        findings.push({
          title: `${result.target.provider} Storage Bucket Exists (Access Denied)`,
          description: `The ${result.target.provider} storage bucket "${result.target.name}" at ${result.target.url} exists but returned HTTP 403. While not publicly readable, the bucket's existence is confirmed and may be targeted for misconfiguration.`,
          severity: "low",
          category: "cloud_exposure",
          affectedAsset: result.target.url,
          remediation: `Ensure bucket "${result.target.name}" has proper access controls. Consider using a less predictable bucket name.`,
        });
      }
    }

    for (const svc of result.headerServices) {
      const key = `${svc.provider}:${svc.service}`;
      if (!seenServices.has(key)) {
        seenServices.add(key);
        allCloudServices.push(svc);
      }
    }
  }

  // Check CNAME records for cloud services
  const cnameServices = await checkCNAMEsForCloudServices(domain);
  for (const svc of cnameServices) {
    const key = `${svc.provider}:${svc.service}`;
    if (!seenServices.has(key)) {
      seenServices.add(key);
      allCloudServices.push(svc);
    }
  }

  // Also check main domain response headers
  const mainRes = await safeFetch(`https://${domain}`, HTTP_TIMEOUT_MS, signal);
  if (mainRes) {
    const headerServices = extractCloudServicesFromHeaders(mainRes.headers, `https://${domain}`);
    for (const svc of headerServices) {
      const key = `${svc.provider}:${svc.service}`;
      if (!seenServices.has(key)) {
        seenServices.add(key);
        allCloudServices.push(svc);
      }
    }
  }

  const duration = Date.now() - startTime;

  log.info(
    { domain, buckets: buckets.length, cloudServices: allCloudServices.length, findings: findings.length, duration },
    "Cloud discovery complete",
  );

  return { buckets, cloudServices: allCloudServices, findings, duration };
}
