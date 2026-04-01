/**
 * API Security Discovery Module
 *
 * Discovers and assesses API endpoints by:
 * 1. Probing common API paths and documentation endpoints
 * 2. Detecting OpenAPI/Swagger specifications
 * 3. Checking for unauthenticated API access
 * 4. Identifying GraphQL endpoints
 * 5. Detecting API versioning and exposed debug endpoints
 */

import { createLogger } from "../logger.js";
import { httpGet, fetchJSON } from "./http.js";
import { runWithConcurrency } from "./utils.js";
import type { VerifiedFinding, EvidenceItem } from "./types.js";

const log = createLogger("scanner:api-discovery");

/** Common API documentation and endpoint paths */
const API_DOC_PATHS = [
  "/swagger.json",
  "/swagger.yaml",
  "/swagger-ui/",
  "/swagger-ui/index.html",
  "/api-docs",
  "/api-docs/",
  "/openapi.json",
  "/openapi.yaml",
  "/openapi/",
  "/v1/api-docs",
  "/v2/api-docs",
  "/v3/api-docs",
  "/redoc",
  "/docs",
  "/docs/api",
  "/api/docs",
  "/api/swagger",
  "/api/openapi",
  "/_api",
  "/graphql",
  "/graphiql",
  "/playground",
  "/api/graphql",
  "/api/playground",
  "/altair",
];

/** Common API version prefixes */
const API_VERSION_PATHS = [
  "/api",
  "/api/v1",
  "/api/v2",
  "/api/v3",
  "/rest",
  "/rest/v1",
  "/rest/v2",
];

/** Debug/admin API paths */
const API_DEBUG_PATHS = [
  "/actuator",
  "/actuator/env",
  "/actuator/configprops",
  "/actuator/mappings",
  "/actuator/beans",
  "/actuator/info",
  "/actuator/health",
  "/actuator/metrics",
  "/actuator/heapdump",
  "/actuator/threaddump",
  "/_debug",
  "/debug/vars",
  "/debug/pprof",
  "/__debug__",
  "/trace",
  "/metrics",
  "/health",
  "/healthz",
  "/ready",
  "/readyz",
  "/status",
  "/info",
  "/env",
  "/internal",
  "/admin/api",
  "/manage",
  "/management",
  "/.well-known/openid-configuration",
  "/oauth/token",
  "/auth/token",
  "/api/tokens",
];

export interface ApiEndpoint {
  path: string;
  type: "documentation" | "graphql" | "rest" | "debug" | "auth";
  status: number;
  authenticated: boolean;
  details: string;
}

export interface ApiDiscoveryResults {
  findings: VerifiedFinding[];
  endpoints: ApiEndpoint[];
  openApiSpec: Record<string, unknown> | null;
}

/** Check if response body looks like a real API response (not a generic 404/HTML page) */
function isApiResponse(body: string, status: number): boolean {
  const trimmed = body.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) return true;
  if (trimmed.startsWith("<?xml") || trimmed.startsWith("<wsdl")) return true;
  if (status === 200 && trimmed.includes('"openapi"')) return true;
  if (status === 200 && trimmed.includes('"swagger"')) return true;
  if (status === 200 && trimmed.includes('"info"') && trimmed.includes('"paths"')) return true;
  return false;
}

/** Check if body contains GraphQL indicators */
function isGraphQLResponse(body: string): boolean {
  return body.includes('"data"') || body.includes("GraphiQL") || body.includes("graphql-playground") || body.includes("__schema");
}

/** Probe a single API path */
async function probeApiPath(
  baseUrl: string,
  path: string,
  type: ApiEndpoint["type"],
): Promise<ApiEndpoint | null> {
  try {
    const result = await httpGet(`${baseUrl}${path}`);
    if (!result) return null;

    const { status, body } = result;

    // Filter out generic error pages
    if (status >= 400 && status !== 401 && status !== 403 && status !== 405) return null;
    if (status === 200 && body.trim().startsWith("<!DOCTYPE") && !body.includes("swagger") && !body.includes("Swagger") && !body.includes("graphql") && !body.includes("GraphiQL")) return null;

    const authenticated = status !== 401 && status !== 403;
    let details = `HTTP ${status}`;

    if (type === "graphql" && isGraphQLResponse(body)) {
      details = "GraphQL endpoint detected";
    } else if (type === "documentation") {
      if (body.includes('"openapi"') || body.includes('"swagger"')) {
        details = "OpenAPI/Swagger specification exposed";
      } else if (body.includes("Swagger UI") || body.includes("swagger-ui")) {
        details = "Swagger UI documentation exposed";
      } else if (body.includes("ReDoc") || body.includes("redoc")) {
        details = "ReDoc API documentation exposed";
      } else if (isApiResponse(body, status)) {
        details = "API documentation endpoint accessible";
      } else {
        return null; // Not actually API docs
      }
    } else if (type === "debug") {
      if (!isApiResponse(body, status) && status === 200) return null;
      details = `Debug/management endpoint accessible (${path})`;
    } else if (type === "rest") {
      if (!isApiResponse(body, status) && status !== 405) return null;
      details = status === 405 ? "API endpoint exists (Method Not Allowed)" : "API endpoint accessible";
    } else if (type === "auth") {
      if (status === 200 || status === 405) {
        details = `Auth endpoint accessible (${path})`;
      } else {
        return null;
      }
    }

    return { path, type, status, authenticated, details };
  } catch {
    return null;
  }
}

/**
 * Discover API endpoints and assess their security posture.
 */
export async function discoverAPIs(
  domain: string,
  signal?: AbortSignal,
): Promise<ApiDiscoveryResults> {
  const findings: VerifiedFinding[] = [];
  const endpoints: ApiEndpoint[] = [];
  let openApiSpec: Record<string, unknown> | null = null;
  const now = new Date().toISOString();
  const baseUrl = `https://${domain}`;

  // Build probe list with type tags
  const probes: Array<{ path: string; type: ApiEndpoint["type"] }> = [
    ...API_DOC_PATHS.map((p) => ({ path: p, type: "documentation" as const })),
    ...API_VERSION_PATHS.map((p) => ({ path: p, type: "rest" as const })),
    ...API_DEBUG_PATHS.map((p) => {
      const isAuth = p.includes("oauth") || p.includes("auth") || p.includes("token") || p.includes("openid");
      return { path: p, type: (isAuth ? "auth" : "debug") as ApiEndpoint["type"] };
    }),
    { path: "/graphql", type: "graphql" },
    { path: "/api/graphql", type: "graphql" },
    { path: "/graphiql", type: "graphql" },
  ];

  // Deduplicate
  const seen = new Set<string>();
  const uniqueProbes = probes.filter((p) => {
    if (seen.has(p.path)) return false;
    seen.add(p.path);
    return true;
  });

  const results = await runWithConcurrency(
    uniqueProbes,
    8,
    (probe) => probeApiPath(baseUrl, probe.path, probe.type),
    signal,
  );

  for (const ep of results) {
    if (!ep) continue;
    endpoints.push(ep);
  }

  // Try to fetch OpenAPI spec
  for (const specPath of ["/swagger.json", "/openapi.json", "/api-docs", "/v2/api-docs", "/v3/api-docs"]) {
    if (openApiSpec) break;
    try {
      const spec = await fetchJSON(`${baseUrl}${specPath}`, 10000);
      if (spec && typeof spec === "object" && ("openapi" in spec || "swagger" in spec || "paths" in spec)) {
        openApiSpec = spec as Record<string, unknown>;
      }
    } catch {
      // not available
    }
  }

  // Generate findings
  const docEndpoints = endpoints.filter((e) => e.type === "documentation" && e.authenticated);
  if (docEndpoints.length > 0) {
    const paths = docEndpoints.map((e) => e.path).join(", ");
    findings.push({
      title: `API Documentation Publicly Exposed on ${domain}`,
      description: `API documentation is accessible without authentication at: ${paths}. This exposes internal API structure, endpoints, and potentially sensitive data schemas to attackers.`,
      severity: "high",
      category: "api_exposure",
      affectedAsset: domain,
      cvssScore: "7.5",
      remediation: "Restrict API documentation endpoints behind authentication. If public documentation is intentional, ensure no sensitive internal endpoints or schemas are exposed.",
      evidence: docEndpoints.map((e) => ({
        type: "http_response",
        description: e.details,
        url: `${baseUrl}${e.path}`,
        source: "API Discovery Scanner",
        verifiedAt: now,
      })),
    });
  }

  const graphqlEndpoints = endpoints.filter((e) => e.type === "graphql");
  if (graphqlEndpoints.length > 0) {
    const unauth = graphqlEndpoints.filter((e) => e.authenticated);
    if (unauth.length > 0) {
      findings.push({
        title: `GraphQL Endpoint Exposed on ${domain}`,
        description: `A GraphQL endpoint is accessible${unauth.length > 0 ? " without authentication" : ""} at ${unauth.map((e) => e.path).join(", ")}. GraphQL introspection may reveal the entire API schema.`,
        severity: "high",
        category: "api_exposure",
        affectedAsset: domain,
        cvssScore: "7.5",
        remediation: "Disable GraphQL introspection in production. Implement authentication and authorization on GraphQL endpoints. Consider using query depth limiting and cost analysis.",
        evidence: unauth.map((e) => ({
          type: "http_response",
          description: e.details,
          url: `${baseUrl}${e.path}`,
          source: "API Discovery Scanner",
          verifiedAt: now,
        })),
      });
    }
  }

  const debugEndpoints = endpoints.filter((e) => e.type === "debug" && e.authenticated);
  if (debugEndpoints.length > 0) {
    const sensitiveDebug = debugEndpoints.filter((e) =>
      e.path.includes("env") || e.path.includes("configprops") || e.path.includes("heapdump") ||
      e.path.includes("threaddump") || e.path.includes("mappings") || e.path.includes("pprof"),
    );
    const isCritical = sensitiveDebug.length > 0;

    findings.push({
      title: `Debug/Management Endpoints Exposed on ${domain}`,
      description: `${debugEndpoints.length} debug or management endpoint(s) are accessible without authentication: ${debugEndpoints.map((e) => e.path).join(", ")}. ${isCritical ? "Sensitive endpoints like /env or /heapdump can leak secrets and memory contents." : "These can reveal internal application structure."}`,
      severity: isCritical ? "critical" : "high",
      category: "api_exposure",
      affectedAsset: domain,
      cvssScore: isCritical ? "9.8" : "7.5",
      remediation: "Disable debug/management endpoints in production or restrict access via authentication and network controls. Spring Boot Actuator endpoints should be secured with Spring Security.",
      evidence: debugEndpoints.map((e) => ({
        type: "http_response",
        description: e.details,
        url: `${baseUrl}${e.path}`,
        source: "API Discovery Scanner",
        verifiedAt: now,
      })),
    });
  }

  if (openApiSpec) {
    const paths = openApiSpec.paths as Record<string, unknown> | undefined;
    const pathCount = paths ? Object.keys(paths).length : 0;
    const info = openApiSpec.info as Record<string, unknown> | undefined;

    findings.push({
      title: `OpenAPI Specification Publicly Accessible on ${domain}`,
      description: `An OpenAPI/Swagger specification was found exposing ${pathCount} API path(s). API title: "${info?.title ?? "unknown"}". Version: ${info?.version ?? "unknown"}.`,
      severity: "medium",
      category: "api_exposure",
      affectedAsset: domain,
      cvssScore: "5.3",
      remediation: "Review the OpenAPI spec for sensitive endpoints. Restrict access if the spec contains internal APIs.",
      evidence: [{
        type: "http_response",
        description: `OpenAPI spec with ${pathCount} paths`,
        snippet: JSON.stringify({ info: openApiSpec.info, pathCount, servers: openApiSpec.servers }, null, 2).slice(0, 500),
        source: "API Discovery Scanner",
        verifiedAt: now,
      }],
    });
  }

  const authEndpoints = endpoints.filter((e) => e.type === "auth" && e.authenticated);
  if (authEndpoints.length > 0) {
    findings.push({
      title: `Authentication Endpoints Discovered on ${domain}`,
      description: `Authentication/OAuth endpoints were found accessible: ${authEndpoints.map((e) => e.path).join(", ")}. These may be vulnerable to brute-force or credential stuffing if not properly rate-limited.`,
      severity: "info",
      category: "api_exposure",
      affectedAsset: domain,
      cvssScore: "0.0",
      remediation: "Ensure authentication endpoints have rate limiting, account lockout, and CAPTCHA mechanisms in place.",
      evidence: authEndpoints.map((e) => ({
        type: "http_response",
        description: e.details,
        url: `${baseUrl}${e.path}`,
        source: "API Discovery Scanner",
        verifiedAt: now,
      })),
    });
  }

  log.info({ domain, endpoints: endpoints.length, findings: findings.length }, "API discovery scan complete");
  return { findings, endpoints, openApiSpec };
}
