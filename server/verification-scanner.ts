import { eq } from "drizzle-orm";
import { db } from "./db";
import { findings } from "@shared/schema";
import { createLogger } from "./logger";
import * as dns from "dns/promises";
import * as net from "net";
import * as https from "https";
import * as http from "http";

const log = createLogger("verification-scanner");

const FETCH_TIMEOUT_MS = 10_000;
const TCP_TIMEOUT_MS = 5_000;

interface VerificationResult {
  stillPresent: boolean;
  evidence: Record<string, unknown>;
  checkedAt: string;
}

async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function checkSecurityHeader(
  url: string,
  headerName: string,
): Promise<{ stillPresent: boolean; evidence: Record<string, unknown> }> {
  try {
    const response = await fetchWithTimeout(url);
    const headerValue = response.headers.get(headerName);
    const allHeaders: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      allHeaders[key] = value;
    });

    return {
      stillPresent: !headerValue,
      evidence: {
        url,
        headerChecked: headerName,
        headerPresent: !!headerValue,
        headerValue: headerValue ?? null,
        statusCode: response.status,
      },
    };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Unknown error";
    return {
      stillPresent: true,
      evidence: { url, error: message, reason: "fetch_failed" },
    };
  }
}

async function checkCors(
  url: string,
): Promise<{ stillPresent: boolean; evidence: Record<string, unknown> }> {
  try {
    const response = await fetchWithTimeout(url, {
      headers: { Origin: "https://evil.example.com" },
    });
    const acao = response.headers.get("access-control-allow-origin");
    const isMisconfigured = acao === "*" || acao === "https://evil.example.com";

    return {
      stillPresent: isMisconfigured,
      evidence: {
        url,
        accessControlAllowOrigin: acao ?? null,
        misconfigured: isMisconfigured,
        statusCode: response.status,
      },
    };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Unknown error";
    return {
      stillPresent: true,
      evidence: { url, error: message, reason: "cors_check_failed" },
    };
  }
}

async function checkTransportSecurity(
  url: string,
): Promise<{ stillPresent: boolean; evidence: Record<string, unknown> }> {
  try {
    const httpUrl = url.replace(/^https:/, "http:");
    const response = await fetchWithTimeout(httpUrl, { redirect: "manual" });
    const location = response.headers.get("location") ?? "";
    const redirectsToHttps = location.startsWith("https://");

    return {
      stillPresent: !redirectsToHttps,
      evidence: {
        httpUrl,
        redirectsToHttps,
        redirectLocation: location || null,
        statusCode: response.status,
      },
    };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Unknown error";
    return {
      stillPresent: true,
      evidence: { url, error: message, reason: "transport_check_failed" },
    };
  }
}

async function checkExposedService(
  host: string,
  port: number,
): Promise<{ stillPresent: boolean; evidence: Record<string, unknown> }> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(TCP_TIMEOUT_MS);

    socket.on("connect", () => {
      socket.destroy();
      resolve({
        stillPresent: true,
        evidence: { host, port, reachable: true },
      });
    });

    socket.on("timeout", () => {
      socket.destroy();
      resolve({
        stillPresent: false,
        evidence: { host, port, reachable: false, reason: "timeout" },
      });
    });

    socket.on("error", () => {
      socket.destroy();
      resolve({
        stillPresent: false,
        evidence: { host, port, reachable: false, reason: "connection_refused" },
      });
    });

    socket.connect(port, host);
  });
}

async function checkCookieSecurity(
  url: string,
): Promise<{ stillPresent: boolean; evidence: Record<string, unknown> }> {
  try {
    const response = await fetchWithTimeout(url);
    const setCookieHeaders = response.headers.getSetCookie?.() ?? [];
    const insecureCookies = setCookieHeaders.filter((cookie) => {
      const lower = cookie.toLowerCase();
      return !lower.includes("secure") || !lower.includes("httponly");
    });

    return {
      stillPresent: insecureCookies.length > 0,
      evidence: {
        url,
        totalCookies: setCookieHeaders.length,
        insecureCookies: insecureCookies.length,
        cookies: setCookieHeaders,
      },
    };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Unknown error";
    return {
      stillPresent: true,
      evidence: { url, error: message, reason: "cookie_check_failed" },
    };
  }
}

async function checkSubdomainTakeover(
  domain: string,
): Promise<{ stillPresent: boolean; evidence: Record<string, unknown> }> {
  try {
    const records = await dns.resolveCname(domain);
    const danglingIndicators = [
      "s3.amazonaws.com",
      "herokuapp.com",
      "github.io",
      "azurewebsites.net",
      "cloudfront.net",
      "pantheon.io",
      "unbouncepages.com",
      "zendesk.com",
      "surge.sh",
    ];

    const dangling = records.some((cname) =>
      danglingIndicators.some((indicator) => cname.includes(indicator)),
    );

    // If CNAME points to known service, try to fetch it
    if (dangling) {
      try {
        const response = await fetchWithTimeout(`https://${domain}`);
        const body = await response.text();
        const notFoundIndicators = [
          "NoSuchBucket",
          "There isn't a GitHub Pages site here",
          "herokucdn.com/error-pages",
          "Domain not found",
          "The specified bucket does not exist",
        ];
        const isTakeover = notFoundIndicators.some((indicator) =>
          body.includes(indicator),
        );

        return {
          stillPresent: isTakeover,
          evidence: {
            domain,
            cnameRecords: records,
            dangling,
            takeoverIndicatorFound: isTakeover,
          },
        };
      } catch {
        return {
          stillPresent: true,
          evidence: { domain, cnameRecords: records, dangling, fetchFailed: true },
        };
      }
    }

    return {
      stillPresent: false,
      evidence: { domain, cnameRecords: records, dangling: false },
    };
  } catch (error: unknown) {
    // NXDOMAIN or no CNAME means the issue may be resolved
    const message = error instanceof Error ? error.message : "Unknown error";
    if (message.includes("ENOTFOUND") || message.includes("ENODATA")) {
      return {
        stillPresent: false,
        evidence: { domain, noCname: true, reason: "no_dns_record" },
      };
    }
    return {
      stillPresent: true,
      evidence: { domain, error: message, reason: "dns_lookup_failed" },
    };
  }
}

async function checkDefault(
  url: string,
): Promise<{ stillPresent: boolean; evidence: Record<string, unknown> }> {
  try {
    const response = await fetchWithTimeout(url);
    return {
      stillPresent: response.status === 200,
      evidence: {
        url,
        statusCode: response.status,
        reachable: true,
      },
    };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Unknown error";
    return {
      stillPresent: false,
      evidence: { url, error: message, reachable: false },
    };
  }
}

function parseHostPort(asset: string): { host: string; port: number } {
  const parts = asset.replace(/^https?:\/\//, "").split(":");
  const host = parts[0];
  const port = parseInt(parts[1] ?? "80", 10);
  return { host, port: isNaN(port) ? 80 : port };
}

function ensureUrl(asset: string): string {
  if (asset.startsWith("http://") || asset.startsWith("https://")) {
    return asset;
  }
  return `https://${asset}`;
}

export async function verifyFinding(findingId: string): Promise<VerificationResult> {
  const finding = await db
    .select()
    .from(findings)
    .where(eq(findings.id, findingId))
    .then((rows) => rows[0]);

  if (!finding) {
    throw new Error(`Finding not found: ${findingId}`);
  }

  const category = finding.category.toLowerCase();
  const asset = finding.affectedAsset ?? "";
  const checkedAt = new Date().toISOString();

  let result: { stillPresent: boolean; evidence: Record<string, unknown> };

  try {
    if (category === "security_headers" || category === "missing_security_header") {
      const headerName = extractHeaderName(finding.title);
      result = await checkSecurityHeader(ensureUrl(asset), headerName);
    } else if (category === "cors_misconfiguration") {
      result = await checkCors(ensureUrl(asset));
    } else if (category === "transport_security") {
      result = await checkTransportSecurity(ensureUrl(asset));
    } else if (category === "exposed_service") {
      const { host, port } = parseHostPort(asset);
      result = await checkExposedService(host, port);
    } else if (category === "cookie_security") {
      result = await checkCookieSecurity(ensureUrl(asset));
    } else if (category === "subdomain_takeover") {
      result = await checkSubdomainTakeover(asset.replace(/^https?:\/\//, ""));
    } else {
      result = await checkDefault(ensureUrl(asset));
    }
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Unknown error";
    log.error({ findingId, error: message }, "Verification check failed");
    result = {
      stillPresent: true,
      evidence: { error: message, reason: "check_exception" },
    };
  }

  const newWorkflowState = result.stillPresent ? "remediated" : "verified";

  const existingEnrichment =
    (finding.aiEnrichment as Record<string, unknown>) ?? {};
  const updatedEnrichment = {
    ...existingEnrichment,
    verification: {
      stillPresent: result.stillPresent,
      evidence: result.evidence,
      checkedAt,
    },
  };

  await db
    .update(findings)
    .set({
      workflowState: newWorkflowState,
      aiEnrichment: updatedEnrichment,
    })
    .where(eq(findings.id, findingId));

  log.info(
    { findingId, stillPresent: result.stillPresent, newWorkflowState },
    "Finding verification completed",
  );

  return {
    stillPresent: result.stillPresent,
    evidence: result.evidence,
    checkedAt,
  };
}

function extractHeaderName(title: string): string {
  const headerPatterns = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "x-permitted-cross-domain-policies",
  ];

  const lower = title.toLowerCase();
  for (const header of headerPatterns) {
    if (lower.includes(header)) {
      return header;
    }
  }

  // Fallback: try to extract from pattern "Missing X-Header-Name"
  const match = lower.match(/missing\s+([\w-]+)/);
  if (match) {
    return match[1];
  }

  return "x-content-type-options";
}
