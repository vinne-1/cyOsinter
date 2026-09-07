/**
 * API Security Discovery Module
 *
 * Discovers and assesses API endpoints: documentation, GraphQL, REST roots,
 * operational endpoints, and genuinely sensitive debug/management surfaces.
 *
 * ## Three precision rules
 *
 * **A health endpoint is not a vulnerability.** `/health`, `/healthz`, `/ready`,
 * `/status`, `/info` and `/metrics` are *supposed* to answer a load balancer
 * without credentials. They were pooled with `/actuator/heapdump` into a single
 * "Debug/Management Endpoints Exposed" finding at high severity, so a correctly
 * operated service was reported as insecure for doing the normal thing. They are
 * now recon, and only the endpoints that actually disclose configuration,
 * memory, or internal wiring produce a security finding.
 *
 * **Publishing API documentation is a choice, not a defect.** A public OpenAPI
 * spec is deliberate for most SaaS. It is worth telling the reader the surface
 * exists — at low severity — not accusing them of a high-severity exposure.
 *
 * **Introspection is tested, never assumed.** The GraphQL finding used to assert
 * "introspection may reveal the entire API schema" on the strength of a 405 at
 * `/graphql`. It now sends an introspection query and reports what came back.
 */

import { createLogger } from "../logger.js";
import { httpGet, httpRequest } from "./http.js";
import { runWithConcurrency } from "./utils.js";
import { calibrate, isSoftNotFound, type ResponseBaseline } from "./response-oracle.js";
import {
  looksLikeHtml,
  looksLikeOpenApiSpec,
  looksLikeSpringActuator,
  looksLikeGraphQL,
  looksLikeGoPprof,
  looksLikePrometheusMetrics,
  parseJsonBody,
} from "./body-signatures.js";
import type { VerifiedFinding } from "./types.js";

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
  "/docs/api",
  "/api/docs",
  "/api/swagger",
  "/api/openapi",
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

/**
 * Endpoints that disclose configuration, memory, or internal wiring. A public
 * one of these is a real finding.
 */
const SENSITIVE_DEBUG_PATHS = [
  "/actuator/env",
  "/actuator/configprops",
  "/actuator/mappings",
  "/actuator/beans",
  "/actuator/heapdump",
  "/actuator/threaddump",
  "/actuator",
  "/_debug",
  "/debug/vars",
  "/debug/pprof",
  "/__debug__",
  "/trace",
  "/env",
  "/internal",
  "/admin/api",
  "/manage",
  "/management",
];

/**
 * Endpoints whose whole purpose is to answer an unauthenticated prober —
 * container orchestrators and load balancers require exactly that. Recorded as
 * intelligence about the service, never as a weakness.
 */
const OPERATIONAL_PATHS = [
  "/actuator/info",
  "/actuator/health",
  "/actuator/metrics",
  "/metrics",
  "/health",
  "/healthz",
  "/ready",
  "/readyz",
  "/status",
  "/info",
];

/** Authentication surfaces — useful context, not a defect on their own. */
const AUTH_PATHS = [
  "/.well-known/openid-configuration",
  "/oauth/token",
  "/auth/token",
  "/api/tokens",
];

const GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/graphiql", "/playground", "/api/playground", "/altair"];

export interface ApiEndpoint {
  path: string;
  type: "documentation" | "graphql" | "rest" | "debug" | "operational" | "auth";
  status: number;
  /** True when the endpoint answered us without demanding credentials. */
  unauthenticated: boolean;
  details: string;
}

export interface ApiDiscoveryResults {
  findings: VerifiedFinding[];
  endpoints: ApiEndpoint[];
  openApiSpec: Record<string, unknown> | null;
  /** GraphQL endpoints confirmed to answer an introspection query. */
  introspectableGraphql: string[];
  /** 200 responses that were not reported, with the reason. */
  suppressed: Array<{ path: string; reason: string }>;
}

/** A response body that is machine-readable rather than a rendered page. */
function isStructuredResponse(body: string): boolean {
  if (looksLikeHtml(body)) return false;
  if (parseJsonBody(body) !== null) return true;
  const trimmed = body.trim();
  return trimmed.startsWith("<?xml") || trimmed.startsWith("<wsdl");
}

/** Swagger UI / ReDoc / GraphiQL ship recognisable shells. */
function isApiDocsUi(body: string): boolean {
  return /swagger-ui|<title>\s*Swagger UI|redoc\b|<redoc|graphql-playground|GraphiQL/i.test(body);
}

/**
 * Does this debug endpoint actually disclose something?
 *
 * A 200 at `/actuator/env` that returns the site's home page discloses nothing.
 * The response has to be the management document it claims to be.
 */
function confirmsSensitiveDebug(path: string, body: string): boolean {
  if (path.startsWith("/actuator")) return looksLikeSpringActuator(body);
  if (path.startsWith("/debug/pprof")) return looksLikeGoPprof(body);
  if (path === "/debug/vars") {
    const j = parseJsonBody(body);
    return !!j && typeof j === "object" && ("cmdline" in (j as Record<string, unknown>) || "memstats" in (j as Record<string, unknown>));
  }
  return isStructuredResponse(body);
}

interface ProbeContext {
  baseUrl: string;
  baseline: ResponseBaseline | null;
  suppressed: Array<{ path: string; reason: string }>;
}

/** Probe a single API path. */
async function probeApiPath(
  ctx: ProbeContext,
  path: string,
  type: ApiEndpoint["type"],
): Promise<ApiEndpoint | null> {
  const result = await httpGet(`${ctx.baseUrl}${path}`);
  if (!result) return null;

  const { status, body } = result;

  // 401/403/405 are informative: the endpoint exists and told us so.
  if (status >= 400 && status !== 401 && status !== 403 && status !== 405) return null;

  if (status === 200 && isSoftNotFound(ctx.baseline, path, result)) {
    ctx.suppressed.push({ path, reason: "matches this host's response for a random non-existent path" });
    return null;
  }

  const unauthenticated = status !== 401 && status !== 403;
  let details = `HTTP ${status}`;

  if (type === "graphql") {
    if (status === 200 && !looksLikeGraphQL(body)) {
      ctx.suppressed.push({ path, reason: "200 response is not a GraphQL endpoint" });
      return null;
    }
    details = "GraphQL endpoint detected";
  } else if (type === "documentation") {
    if (status !== 200) return null;
    if (looksLikeOpenApiSpec(body)) details = "OpenAPI/Swagger specification exposed";
    else if (isApiDocsUi(body)) details = "API documentation UI exposed";
    else {
      ctx.suppressed.push({ path, reason: "200 response is not an API specification or documentation UI" });
      return null;
    }
  } else if (type === "debug") {
    if (status === 200 && !confirmsSensitiveDebug(path, body)) {
      ctx.suppressed.push({ path, reason: `200 response does not disclose management data for ${path}` });
      return null;
    }
    details = `Management endpoint discloses data (${path})`;
  } else if (type === "operational") {
    if (status !== 200) return null;
    const confirmed = path === "/metrics" ? looksLikePrometheusMetrics(body) : isStructuredResponse(body) || body.trim().length < 40;
    if (!confirmed) {
      ctx.suppressed.push({ path, reason: `200 response is not an operational endpoint document` });
      return null;
    }
    details = `Operational endpoint (${path})`;
  } else if (type === "rest") {
    if (status !== 405 && !isStructuredResponse(body)) {
      ctx.suppressed.push({ path, reason: "200 response is a web page, not an API root" });
      return null;
    }
    details = status === 405 ? "API endpoint exists (Method Not Allowed)" : "API endpoint accessible";
  } else if (type === "auth") {
    if (status !== 200 && status !== 405) return null;
    if (status === 200 && !isStructuredResponse(body)) {
      ctx.suppressed.push({ path, reason: "200 response is not an auth endpoint document" });
      return null;
    }
    details = `Auth endpoint accessible (${path})`;
  }

  return { path, type, status, unauthenticated, details };
}

/**
 * Ask a GraphQL endpoint for its schema.
 *
 * Introspection being ENABLED is the actual defect — the previous code asserted
 * it from the endpoint merely existing. A single minimal query settles it, and
 * the response is the evidence.
 */
async function probeGraphqlIntrospection(url: string): Promise<{ enabled: boolean; detail: string }> {
  const res = await httpRequest(
    url,
    "POST",
    { "content-type": "application/json" },
    8000,
    JSON.stringify({ query: "{__schema{queryType{name}}}" }),
  );
  if (!res) return { enabled: false, detail: "endpoint did not answer an introspection query" };
  const json = parseJsonBody(res.body) as { data?: { __schema?: { queryType?: { name?: string } } } } | null;
  const name = json?.data?.__schema?.queryType?.name;
  if (typeof name === "string" && name.length > 0) {
    return { enabled: true, detail: `introspection returned the schema root type "${name}"` };
  }
  return { enabled: false, detail: "introspection query was refused or returned no schema" };
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
  const suppressed: ApiDiscoveryResults["suppressed"] = [];
  const introspectableGraphql: string[] = [];
  let openApiSpec: Record<string, unknown> | null = null;
  const now = new Date().toISOString();
  const baseUrl = `https://${domain}`;

  const baseline = await calibrate(baseUrl);
  const ctx: ProbeContext = { baseUrl, baseline, suppressed };

  const probes: Array<{ path: string; type: ApiEndpoint["type"] }> = [
    ...API_DOC_PATHS.map((p) => ({ path: p, type: "documentation" as const })),
    ...API_VERSION_PATHS.map((p) => ({ path: p, type: "rest" as const })),
    ...SENSITIVE_DEBUG_PATHS.map((p) => ({ path: p, type: "debug" as const })),
    ...OPERATIONAL_PATHS.map((p) => ({ path: p, type: "operational" as const })),
    ...AUTH_PATHS.map((p) => ({ path: p, type: "auth" as const })),
    ...GRAPHQL_PATHS.map((p) => ({ path: p, type: "graphql" as const })),
  ];

  const seen = new Set<string>();
  const uniqueProbes = probes.filter((p) => {
    if (seen.has(p.path)) return false;
    seen.add(p.path);
    return true;
  });

  const results = await runWithConcurrency(
    uniqueProbes,
    8,
    (probe) => probeApiPath(ctx, probe.path, probe.type),
    signal,
  );

  for (const ep of results) {
    if (ep) endpoints.push(ep);
  }

  // ── API documentation ────────────────────────────────────────────────────
  const docEndpoints = endpoints.filter((e) => e.type === "documentation" && e.unauthenticated);
  for (const e of docEndpoints) {
    if (openApiSpec) break;
    const res = await httpGet(`${baseUrl}${e.path}`);
    if (!res || !looksLikeOpenApiSpec(res.body)) continue;
    const parsed = parseJsonBody(res.body);
    if (parsed && typeof parsed === "object") openApiSpec = parsed as Record<string, unknown>;
  }

  if (docEndpoints.length > 0) {
    const paths = docEndpoints.map((e) => e.path).join(", ");
    const spec = openApiSpec?.paths as Record<string, unknown> | undefined;
    const pathCount = spec ? Object.keys(spec).length : 0;
    findings.push({
      title: `API Documentation Publicly Accessible on ${domain}`,
      description: `API documentation is reachable without authentication at: ${paths}${pathCount > 0 ? `, describing ${pathCount} API path(s)` : ""}. Publishing documentation is often deliberate; the risk is that it also describes internal or undocumented endpoints an attacker would not otherwise find.`,
      severity: "low",
      category: "api_exposure",
      affectedAsset: domain,
      cvssScore: "3.1",
      remediation: "Confirm the published specification is the intended public surface. Remove internal, admin, and deprecated endpoints from it, or move the specification behind authentication.",
      evidence: docEndpoints.map((e) => ({
        type: "http_response",
        description: e.details,
        url: `${baseUrl}${e.path}`,
        source: "API Discovery Scanner",
        verifiedAt: now,
      })),
    });
  }

  // ── GraphQL ──────────────────────────────────────────────────────────────
  const graphqlEndpoints = endpoints.filter((e) => e.type === "graphql" && e.unauthenticated);
  for (const e of graphqlEndpoints) {
    const url = `${baseUrl}${e.path}`;
    const probe = await probeGraphqlIntrospection(url);
    if (!probe.enabled) continue;
    introspectableGraphql.push(url);
    findings.push({
      title: `GraphQL Introspection Enabled on ${domain}${e.path}`,
      description: `The GraphQL endpoint at ${url} answers introspection queries without authentication, so the complete schema — every type, field, and mutation, including any not used by the public client — can be enumerated by anyone.`,
      severity: "medium",
      category: "api_exposure",
      affectedAsset: domain,
      cvssScore: "5.3",
      remediation: "Disable introspection in production, or restrict it to authenticated internal callers. Add query depth limiting and cost analysis while you are there.",
      evidence: [{
        type: "http_response",
        description: probe.detail,
        url,
        snippet: probe.detail,
        source: "API Discovery Scanner (introspection query)",
        verifiedAt: now,
      }],
    });
  }

  // ── Sensitive management endpoints ───────────────────────────────────────
  const debugEndpoints = endpoints.filter((e) => e.type === "debug" && e.unauthenticated);
  if (debugEndpoints.length > 0) {
    const sensitiveDebug = debugEndpoints.filter((e) =>
      /\/(env|configprops|heapdump|threaddump|mappings|beans|pprof|vars)$/.test(e.path),
    );
    const isCritical = sensitiveDebug.length > 0;

    findings.push({
      title: `Debug/Management Endpoints Exposed on ${domain}`,
      description: `${debugEndpoints.length} management endpoint(s) return internal data without authentication: ${debugEndpoints.map((e) => e.path).join(", ")}. ${isCritical ? "Endpoints such as /env, /configprops and /heapdump disclose configuration values and process memory, which routinely include credentials." : "These reveal internal application structure and wiring."}`,
      severity: isCritical ? "critical" : "high",
      category: "api_exposure",
      affectedAsset: domain,
      cvssScore: isCritical ? "9.8" : "7.5",
      remediation: "Disable management endpoints in production, or restrict them to an internal network and require authentication. For Spring Boot, expose only /health and /info over the web and secure the rest with Spring Security.",
      evidence: debugEndpoints.map((e) => ({
        type: "http_response",
        description: e.details,
        url: `${baseUrl}${e.path}`,
        source: "API Discovery Scanner",
        verifiedAt: now,
      })),
    });
  }

  // ── Operational and auth endpoints: intelligence, not findings ────────────
  const operational = endpoints.filter((e) => e.type === "operational");
  if (operational.length > 0) {
    findings.push({
      title: `Operational Endpoints Discovered on ${domain}`,
      description: `${operational.length} health, readiness, or metrics endpoint(s) answer unauthenticated requests: ${operational.map((e) => e.path).join(", ")}. This is normal — load balancers and orchestrators require it. Recorded so the surface is known, and worth reviewing only if one of them echoes configuration or version detail you would rather not publish.`,
      severity: "info",
      category: "api_exposure",
      kind: "recon",
      affectedAsset: domain,
      cvssScore: "0.0",
      remediation: "No action required unless a response discloses internal hostnames, versions, or configuration. Restrict those to internal monitoring if so.",
      evidence: operational.map((e) => ({
        type: "http_response",
        description: e.details,
        url: `${baseUrl}${e.path}`,
        source: "API Discovery Scanner",
        verifiedAt: now,
      })),
    });
  }

  const authEndpoints = endpoints.filter((e) => e.type === "auth" && e.unauthenticated);
  if (authEndpoints.length > 0) {
    findings.push({
      title: `Authentication Endpoints Discovered on ${domain}`,
      description: `Authentication/OAuth endpoints were found at: ${authEndpoints.map((e) => e.path).join(", ")}. These are the surface a credential-stuffing or brute-force campaign would target.`,
      severity: "info",
      category: "api_exposure",
      kind: "recon",
      affectedAsset: domain,
      cvssScore: "0.0",
      remediation: "Ensure authentication endpoints have rate limiting, account lockout, and bot mitigation in place.",
      evidence: authEndpoints.map((e) => ({
        type: "http_response",
        description: e.details,
        url: `${baseUrl}${e.path}`,
        source: "API Discovery Scanner",
        verifiedAt: now,
      })),
    });
  }

  log.info(
    { domain, endpoints: endpoints.length, findings: findings.length, suppressed: suppressed.length, introspectable: introspectableGraphql.length },
    "API discovery scan complete",
  );
  return { findings, endpoints, openApiSpec, introspectableGraphql, suppressed };
}
