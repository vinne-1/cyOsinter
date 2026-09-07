/**
 * Container / orchestration exposure detection.
 *
 * ## Why every probe carries a `confirm` predicate
 *
 * This module used to treat `status === 200` as proof that the endpoint it
 * asked for exists. It does not. A single-page app, a framework catch-all
 * route, or any server with a custom 200 error page answers `/api/v1/pods` with
 * `index.html` — and the module then reported
 * "Kubernetes Pods API Exposed Without Authentication" at **critical** for a
 * static marketing site. That single bug could put a fabricated critical at the
 * top of a customer's dashboard.
 *
 * Two independent gates now stand between a 200 and a finding:
 *
 * 1. {@link isSoftNotFound} — the response must differ from what this host
 *    returns for random paths that cannot exist (see response-oracle.ts).
 * 2. `confirm` — the body must positively BE the artefact claimed. A
 *    Prometheus finding requires a Prometheus exposition; a Kubernetes finding
 *    requires a Kubernetes API document. A page that merely mentions the word
 *    is not evidence.
 *
 * Gate 2 is the load-bearing one and is never skipped: gate 1 can be
 * inconclusive (an unreachable host during calibration), but a detector is
 * never allowed to name a technology it has not seen.
 */

import { createLogger } from "../logger.js";
import { runWithConcurrency } from "./utils.js";
import { stealthFetch } from "./stealth.js";
import { calibrate, isSoftNotFound, type ResponseBaseline } from "./response-oracle.js";
import {
  looksLikeKubernetesApi,
  looksLikeDockerRegistry,
  looksLikePrometheusMetrics,
  looksLikeGoPprof,
  looksLikeHtml,
  parseJsonBody,
} from "./body-signatures.js";

const log = createLogger("container-detection");

const PROBE_TIMEOUT_MS = 5000;
const PROBE_CONCURRENCY = 8;

interface ContainerProbe {
  path: string;
  type: string;
  severityIfExposed: string;
  description: string;
  /**
   * Positive proof that the response IS this artefact. Receives the body and
   * the response headers. A probe without convincing proof produces no finding,
   * however inviting its status code was.
   */
  confirm: (body: string, headers: Record<string, string>) => boolean;
}

/** The Kubernetes health endpoint answers a bare `ok`, not a web page. */
function isKubeHealthz(body: string): boolean {
  const t = body.trim();
  if (t.toLowerCase() === "ok") return true;
  // The verbose form lists individual checks, each ending in `ok`.
  return /^\[\+\]\w[\w-]* ok$/m.test(t) && /healthz check passed|livez check passed|readyz check passed/i.test(t);
}

/** The Kubernetes Dashboard SPA identifies itself in its own shell. */
function isKubeDashboard(body: string): boolean {
  return /<kd-root|kubernetes-dashboard|<title>\s*Kubernetes Dashboard\s*<\/title>/i.test(body);
}

/** A container/app health document, as JSON — not an HTML page. */
function isHealthDocument(body: string): boolean {
  if (looksLikeHtml(body)) return false;
  const json = parseJsonBody(body);
  if (json && typeof json === "object" && !Array.isArray(json)) {
    const rec = json as Record<string, unknown>;
    return typeof rec.status === "string" || typeof rec.state === "string" || typeof rec.healthy === "boolean";
  }
  return /^(ok|healthy|pass|up)$/i.test(body.trim());
}

const CONTAINER_PROBES: ContainerProbe[] = [
  { path: "/api/v1/pods", type: "kubernetes-api", severityIfExposed: "critical", description: "Kubernetes Pods API", confirm: looksLikeKubernetesApi },
  { path: "/api/v1/namespaces", type: "kubernetes-api", severityIfExposed: "critical", description: "Kubernetes Namespaces API", confirm: looksLikeKubernetesApi },
  { path: "/api/v1/nodes", type: "kubernetes-api", severityIfExposed: "critical", description: "Kubernetes Nodes API", confirm: looksLikeKubernetesApi },
  { path: "/dashboard/", type: "kubernetes-dashboard", severityIfExposed: "high", description: "Kubernetes Dashboard", confirm: isKubeDashboard },
  { path: "/healthz", type: "kubernetes-health", severityIfExposed: "low", description: "Kubernetes Health Endpoint", confirm: isKubeHealthz },
  { path: "/v2/_catalog", type: "docker-registry", severityIfExposed: "high", description: "Docker Registry Catalog", confirm: looksLikeDockerRegistry },
  { path: "/v2/", type: "docker-registry", severityIfExposed: "high", description: "Docker Registry v2 API", confirm: looksLikeDockerRegistry },
  { path: "/metrics", type: "prometheus", severityIfExposed: "medium", description: "Prometheus Metrics Endpoint", confirm: looksLikePrometheusMetrics },
  { path: "/debug/pprof/", type: "go-debug", severityIfExposed: "high", description: "Go Debug Profiling Endpoint", confirm: looksLikeGoPprof },
  { path: "/_status", type: "container-health", severityIfExposed: "low", description: "Container Health Status", confirm: isHealthDocument },
];

const SUBDOMAIN_PREFIXES = ["", "k8s.", "dashboard.", "registry.", "docker."];

export interface ContainerDetectionResults {
  exposedEndpoints: Array<{
    url: string;
    path: string;
    type: string;
    status: number;
    authenticated: boolean;
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
  /** Probes that returned 200 but could not be confirmed, for diagnostics. */
  unconfirmed: Array<{ url: string; reason: string }>;
  duration: number;
}

interface ProbeTarget {
  url: string;
  origin: string;
  host: string;
  probe: ContainerProbe;
}

async function safeFetchGet(
  url: string,
  timeout: number,
  signal?: AbortSignal,
): Promise<{ status: number; headers: Record<string, string>; body: string; finalUrl: string } | null> {
  try {
    const res = await stealthFetch(url, { redirect: "follow", signal }, timeout);
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k] = v; });
    const body = (await res.text()).substring(0, 20000);
    return { status: res.status, headers, body, finalUrl: res.url };
  } catch {
    return null;
  }
}

/**
 * Whether the endpoint refused us.
 *
 * Only the transport's own answer counts. The previous implementation returned
 * true when the body contained the word "login" anywhere, so any HTML page with
 * a login link was recorded as an authenticated Kubernetes API.
 */
function isAuthenticated(status: number, body: string): boolean {
  if (status === 401 || status === 403) return true;
  const json = parseJsonBody(body);
  if (json && typeof json === "object" && !Array.isArray(json)) {
    const rec = json as Record<string, unknown>;
    if (rec.kind === "Status" && /Forbidden|Unauthorized/i.test(String(rec.reason ?? ""))) return true;
  }
  return false;
}

function buildFindingForEndpoint(
  probe: ContainerProbe,
  url: string,
  authenticated: boolean,
  evidenceSnippet: string,
): ContainerDetectionResults["findings"][number] {
  const severity = authenticated ? "low" : probe.severityIfExposed;

  const remediationMap: Record<string, string> = {
    "kubernetes-api": "Restrict Kubernetes API access using network policies and RBAC. Never expose the API server to the public internet without authentication.",
    "kubernetes-dashboard": "Protect the Kubernetes Dashboard with authentication (OIDC or token-based) and restrict access via network policies or VPN.",
    "kubernetes-health": "While health endpoints are low risk, restrict access to internal monitoring systems only.",
    "docker-registry": "Enable authentication on the Docker Registry. Use TLS and restrict network access to authorized clients only.",
    "prometheus": "Restrict Prometheus metrics endpoints to internal monitoring infrastructure. Use authentication and network policies.",
    "go-debug": "Disable Go debug/pprof endpoints in production. These expose profiling data and can leak sensitive information about the application.",
    "container-health": "Restrict health check endpoints to internal load balancers and monitoring systems.",
  };

  const evidence = [{
    type: "http_response",
    description: `Response body confirmed to be ${probe.description}`,
    url,
    snippet: evidenceSnippet.slice(0, 500),
    source: "container-detection",
    verifiedAt: new Date().toISOString(),
  }];

  if (authenticated) {
    return {
      title: `${probe.description} Detected (Authenticated)`,
      description: `${probe.description} was found at ${url} but requires authentication. The endpoint's existence reveals infrastructure details.`,
      severity,
      category: "container_exposure",
      affectedAsset: url,
      remediation: remediationMap[probe.type] ?? "Restrict access to internal networks and ensure proper authentication is configured.",
      evidence,
    };
  }

  return {
    title: `${probe.description} Exposed Without Authentication`,
    description: `${probe.description} is publicly accessible at ${url} without authentication, and the response was confirmed to be a genuine ${probe.description} rather than a generic page. This exposes container infrastructure details and may allow unauthorized access or control.`,
    severity,
    category: "container_exposure",
    affectedAsset: url,
    remediation: remediationMap[probe.type] ?? "Restrict access to internal networks and configure proper authentication.",
    evidence,
  };
}

export async function runContainerDetection(
  domain: string,
  signal?: AbortSignal,
): Promise<ContainerDetectionResults> {
  const startTime = Date.now();

  log.info({ domain }, "Starting container exposure detection");

  const targets: ProbeTarget[] = [];
  for (const prefix of SUBDOMAIN_PREFIXES) {
    const host = prefix ? `${prefix}${domain}` : domain;
    for (const probe of CONTAINER_PROBES) {
      for (const scheme of ["https", "http"]) {
        targets.push({ url: `${scheme}://${host}${probe.path}`, origin: `${scheme}://${host}`, host, probe });
      }
    }
  }

  const exposedEndpoints: ContainerDetectionResults["exposedEndpoints"] = [];
  const findings: ContainerDetectionResults["findings"] = [];
  const unconfirmed: ContainerDetectionResults["unconfirmed"] = [];
  const seenEndpoints = new Set<string>();

  const results = await runWithConcurrency(
    targets,
    PROBE_CONCURRENCY,
    async (target) => {
      const res = await safeFetchGet(target.url, PROBE_TIMEOUT_MS, signal);
      if (!res) return null;
      return { target, res };
    },
    signal,
  );

  // Calibrate only the origins that actually answered something, and only once
  // each — calibration costs eight requests per origin, so it must not be paid
  // for hosts that never resolved.
  const liveOrigins = Array.from(new Set(results.filter((r): r is NonNullable<typeof r> => !!r).map((r) => r.target.origin)));
  const baselines = new Map<string, ResponseBaseline>();
  for (const origin of liveOrigins) {
    if (signal?.aborted) break;
    baselines.set(origin, await calibrate(origin, ["bare", "dir"]));
  }

  for (const result of results) {
    if (!result) continue;

    const { target, res } = result;
    const { status, body, headers } = res;

    if (status < 200 || status >= 300) continue;

    const endpointKey = `${target.host}${target.probe.path}`;
    if (seenEndpoints.has(endpointKey)) continue;

    // Gate 1: the host's own answer for a path that cannot exist.
    if (isSoftNotFound(baselines.get(target.origin) ?? null, target.probe.path, { status, body, finalUrl: res.finalUrl, headers })) {
      unconfirmed.push({ url: target.url, reason: "response matches this host's catch-all page for non-existent paths" });
      continue;
    }

    // Gate 2: the body must be the artefact we are about to name.
    if (!target.probe.confirm(body, headers)) {
      unconfirmed.push({ url: target.url, reason: `200 response is not a ${target.probe.description}` });
      continue;
    }

    seenEndpoints.add(endpointKey);
    const authenticated = isAuthenticated(status, body);

    exposedEndpoints.push({ url: target.url, path: target.probe.path, type: target.probe.type, status, authenticated });

    if (!authenticated || target.probe.severityIfExposed === "critical" || target.probe.severityIfExposed === "high") {
      findings.push(buildFindingForEndpoint(target.probe, target.url, authenticated, body));
    }
  }

  const duration = Date.now() - startTime;

  log.info(
    { domain, exposed: exposedEndpoints.length, findings: findings.length, unconfirmed: unconfirmed.length, duration },
    "Container detection complete",
  );

  return { exposedEndpoints, findings, unconfirmed, duration };
}
