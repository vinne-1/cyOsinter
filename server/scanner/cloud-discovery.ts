import dns from "dns/promises";
import { createLogger } from "../logger.js";
import { runWithConcurrency } from "./utils.js";
import { stealthFetch } from "./stealth.js";
import { httpGet } from "./http.js";
import { looksLikeBucketListing } from "./body-signatures.js";

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
    /** The bucket name is the domain itself, not a guessed variant. */
    exactName: boolean;
    /** Anonymous requests get a full object listing back. */
    listable: boolean;
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
    evidence?: Array<Record<string, unknown>>;
  }>;
  /** Buckets that answered 200 without proving they are listable. */
  unconfirmed: Array<{ url: string; reason: string }>;
  duration: number;
}

interface BucketCheckTarget {
  provider: string;
  name: string;
  url: string;
  /**
   * True when the bucket name IS the domain (or its dashed form), rather than a
   * guessed variant like `<domain>-media`.
   *
   * The distinction decides what we are allowed to claim. S3 answers 403 for any
   * bucket that exists ANYWHERE in the world, so `acme-com-dev` almost certainly
   * "exists" — in a stranger's account. Reporting that as the customer's asset is
   * an attribution error, and it is the kind that erodes trust in every other
   * finding in the report.
   */
  exactName: boolean;
}

/**
 * Suffixes used for the smaller S3-compatible providers.
 *
 * The full nine-suffix list against five more providers and their regions would
 * roughly triple this module's request count. These three are where buckets
 * actually turn up.
 */
const SECONDARY_SUFFIXES = ["", "-backup", "-assets"];

export function buildBucketTargets(domain: string): BucketCheckTarget[] {
  const baseName = domain.replace(/\./g, "-");
  const dotName = domain;
  const suffixes = ["", "-backup", "-assets", "-static", "-media", "-logs", "-dev", "-staging", "-prod"];

  const targets: BucketCheckTarget[] = [];

  for (const suffix of suffixes) {
    const name = baseName + suffix;
    const dotVariant = dotName + suffix;
    const exactName = suffix === "";

    // AWS S3
    targets.push({ provider: "AWS", name, url: `https://${name}.s3.amazonaws.com`, exactName });
    if (name !== dotVariant) {
      targets.push({ provider: "AWS", name: dotVariant, url: `https://${dotVariant}.s3.amazonaws.com`, exactName });
    }

    // Azure Blob
    targets.push({ provider: "Azure", name, url: `https://${name}.blob.core.windows.net`, exactName });

    // GCP Storage
    targets.push({ provider: "GCP", name, url: `https://storage.googleapis.com/${name}`, exactName });
    if (name !== dotVariant) {
      targets.push({ provider: "GCP", name: dotVariant, url: `https://storage.googleapis.com/${dotVariant}`, exactName });
    }

    // DigitalOcean Spaces (S3-compatible, region-scoped). A few common regions.
    for (const region of ["nyc3", "sfo3", "ams3"]) {
      targets.push({ provider: "DigitalOcean", name, url: `https://${name}.${region}.digitaloceanspaces.com`, exactName });
    }

    // Firebase Realtime Database — publicly-readable DB check (/.json returns data).
    targets.push({ provider: "Firebase", name, url: `https://${name}.firebaseio.com/.json`, exactName });
  }

  // ── S3-compatible providers beyond the big three ──────────────────────────
  //
  // Deliberately probed with a SHORT suffix list. The nine suffixes above
  // against five more providers and their regions would roughly triple the
  // request count for this module, and these providers are a small fraction of
  // real-world usage — the bare name and the two suffixes that actually turn
  // things up carry nearly all the value for a fraction of the traffic.
  for (const suffix of SECONDARY_SUFFIXES) {
    const name = baseName + suffix;
    const exactName = suffix === "";

    // Wasabi — S3-compatible, region in the hostname.
    for (const region of ["s3", "s3.eu-central-1", "s3.us-west-1"]) {
      targets.push({ provider: "Wasabi", name, url: `https://${name}.${region}.wasabisys.com`, exactName });
    }

    // Alibaba Cloud OSS.
    for (const region of ["oss-cn-hangzhou", "oss-us-west-1", "oss-ap-southeast-1"]) {
      targets.push({ provider: "Alibaba", name, url: `https://${name}.${region}.aliyuncs.com`, exactName });
    }

    // Linode / Akamai Object Storage.
    for (const region of ["us-east-1", "eu-central-1"]) {
      targets.push({ provider: "Linode", name, url: `https://${name}.${region}.linodeobjects.com`, exactName });
    }

    // Scaleway Object Storage.
    targets.push({ provider: "Scaleway", name, url: `https://${name}.s3.fr-par.scw.cloud`, exactName });

    // Backblaze B2 — the /file/<bucket>/ form is the one reachable without an
    // account-scoped hostname.
    targets.push({ provider: "Backblaze", name, url: `https://f000.backblazeb2.com/file/${name}/`, exactName });
  }

  // Cloudflare R2 is deliberately absent. A public R2 bucket is served from
  // pub-<32 hex chars>.r2.dev, which is derived from the account, not the
  // bucket or domain name — so it cannot be guessed from a domain the way the
  // providers above can. Probing r2.dev with domain-derived names would
  // generate traffic that can never hit anything. R2 buckets attached to a
  // custom domain are found by the CNAME patterns instead.

  return targets;
}

async function safeFetch(
  url: string,
  timeout: number,
  signal?: AbortSignal,
): Promise<{ status: number; headers: Record<string, string> } | null> {
  try {
    const res = await stealthFetch(url, { method: "HEAD", redirect: "follow", signal }, timeout);
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k] = v; });
    return { status: res.status, headers };
  } catch {
    return null;
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
  const unconfirmed: CloudDiscoveryResults["unconfirmed"] = [];

  // Check bucket targets concurrently
  const bucketResults = await runWithConcurrency(
    bucketTargets,
    BUCKET_CONCURRENCY,
    async (target) => {
      const res = await safeFetch(target.url, HTTP_TIMEOUT_MS, signal);
      if (!res) return null;

      // A bucket only truly EXISTS on 200 (public) or 403 (private). A 404 is
      // "NoSuchBucket" — its response still carries generic provider headers
      // (e.g. x-amz-request-id on every S3 reply), so extracting cloud-service
      // indicators from a 404 produced false positives. Only mine headers when
      // the bucket actually exists.
      const accessible = res.status === 200 || res.status === 403;
      const headerServices = accessible ? extractCloudServicesFromHeaders(res.headers, target.url) : [];

      return {
        target,
        status: res.status,
        accessible,
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
        exactName: result.target.exactName,
        listable: false,
      });

      if (result.status === 200) {
        // A 200 from a bucket hostname is not a public bucket. Providers answer
        // 200 with their own landing page, an error document, or a single
        // public object. Fetch the body and require the provider's own listing
        // root before claiming the contents are enumerable.
        const listing = await httpGet(result.target.url);
        const listable = !!listing && looksLikeBucketListing(listing.body);
        buckets[buckets.length - 1].listable = listable;

        if (!listable) {
          unconfirmed.push({ url: result.target.url, reason: "HTTP 200 but the response is not an object listing" });
          continue;
        }

        // Ownership: an exact-name bucket is the customer's by any reasonable
        // reading. A guessed variant that happens to exist may belong to anyone
        // — say so rather than asserting it is theirs.
        findings.push({
          title: `Publicly Listable ${result.target.provider} Storage Bucket${result.target.exactName ? "" : " (ownership unconfirmed)"}`,
          description: result.target.exactName
            ? `The ${result.target.provider} storage bucket "${result.target.name}" at ${result.target.url} returns a full object listing to anonymous requests. Anyone can enumerate and download its contents.`
            : `A ${result.target.provider} storage bucket named "${result.target.name}" — a guessed variant of your domain — returns a full object listing to anonymous requests. Bucket namespaces are global, so this bucket may belong to an unrelated party; confirm ownership before acting, and treat the listing itself as the evidence.`,
          severity: result.target.exactName ? "high" : "medium",
          category: "cloud_exposure",
          affectedAsset: result.target.url,
          remediation: `Confirm whether "${result.target.name}" is yours. If it is, remove public read/list permissions and enable the provider's public-access block.`,
          evidence: [{
            type: "http_response",
            description: "Anonymous object listing returned by the bucket",
            url: result.target.url,
            snippet: (listing?.body ?? "").slice(0, 500),
            source: "cloud-discovery",
            verifiedAt: new Date().toISOString(),
          }],
        });
      } else if (result.status === 403 && result.target.exactName) {
        // Only for an exact-name match. Every provider answers 403 for a bucket
        // that exists anywhere in the world, so a 403 on a guessed variant like
        // `<domain>-dev` says nothing about this customer at all — reporting one
        // finding per guessed suffix was manufacturing noise from the wordlist.
        findings.push({
          title: `${result.target.provider} Storage Bucket Exists (Access Denied)`,
          description: `A ${result.target.provider} bucket named "${result.target.name}" — exactly your domain name — exists but denies anonymous access. Its contents are not exposed; the name is recorded because it is the obvious first guess for anyone probing your storage.`,
          severity: "info",
          category: "cloud_exposure",
          affectedAsset: result.target.url,
          remediation: `Confirm the bucket is yours and that its access policy is intentional. Bucket names are guessable by design, so access control is the only control that matters here.`,
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
    { domain, buckets: buckets.length, cloudServices: allCloudServices.length, findings: findings.length, unconfirmed: unconfirmed.length, duration },
    "Cloud discovery complete",
  );

  return { buckets, cloudServices: allCloudServices, findings, unconfirmed, duration };
}
