import { createLogger } from "../logger.js";
import { runWithConcurrency } from "./utils.js";

const log = createLogger("container-detection");

const PROBE_TIMEOUT_MS = 5000;
const PROBE_CONCURRENCY = 8;

interface ContainerProbe {
  path: string;
  type: string;
  severityIfExposed: string;
  description: string;
}

const CONTAINER_PROBES: ContainerProbe[] = [
  { path: "/api/v1/pods", type: "kubernetes-api", severityIfExposed: "critical", description: "Kubernetes Pods API" },
  { path: "/api/v1/namespaces", type: "kubernetes-api", severityIfExposed: "critical", description: "Kubernetes Namespaces API" },
  { path: "/api/v1/nodes", type: "kubernetes-api", severityIfExposed: "critical", description: "Kubernetes Nodes API" },
  { path: "/dashboard/", type: "kubernetes-dashboard", severityIfExposed: "high", description: "Kubernetes Dashboard" },
  { path: "/healthz", type: "kubernetes-health", severityIfExposed: "low", description: "Kubernetes Health Endpoint" },
  { path: "/v2/_catalog", type: "docker-registry", severityIfExposed: "high", description: "Docker Registry Catalog" },
  { path: "/v2/", type: "docker-registry", severityIfExposed: "high", description: "Docker Registry v2 API" },
  { path: "/metrics", type: "prometheus", severityIfExposed: "medium", description: "Prometheus Metrics Endpoint" },
  { path: "/debug/pprof/", type: "go-debug", severityIfExposed: "high", description: "Go Debug Profiling Endpoint" },
  { path: "/_status", type: "container-health", severityIfExposed: "low", description: "Container Health Status" },
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
  }>;
  duration: number;
}

interface ProbeTarget {
  url: string;
  host: string;
  probe: ContainerProbe;
}

async function safeFetchGet(
  url: string,
  timeout: number,
  signal?: AbortSignal,
): Promise<{ status: number; headers: Record<string, string>; body: string } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  const onAbort = () => controller.abort();
  signal?.addEventListener("abort", onAbort, { once: true });

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "Cyshield-Scanner/1.0" },
      redirect: "follow",
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k] = v; });
    const body = (await res.text()).substring(0, 5000);
    return { status: res.status, headers, body };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", onAbort);
  }
}

function isAuthenticated(status: number, body: string): boolean {
  if (status === 401 || status === 403) return true;
  const bodyLower = body.toLowerCase();
  if (bodyLower.includes("unauthorized") || bodyLower.includes("login") || bodyLower.includes("forbidden")) {
    return true;
  }
  return false;
}

function buildFindingForEndpoint(
  probe: ContainerProbe,
  url: string,
  authenticated: boolean,
): { title: string; description: string; severity: string; category: string; affectedAsset: string; remediation: string } {
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

  if (authenticated) {
    return {
      title: `${probe.description} Detected (Authenticated)`,
      description: `${probe.description} was found at ${url} but requires authentication. The endpoint's existence reveals infrastructure details.`,
      severity,
      category: "container_exposure",
      affectedAsset: url,
      remediation: remediationMap[probe.type] ?? "Restrict access to internal networks and ensure proper authentication is configured.",
    };
  }

  return {
    title: `${probe.description} Exposed Without Authentication`,
    description: `${probe.description} is publicly accessible at ${url} without authentication. This exposes sensitive container infrastructure details and may allow unauthorized access or control.`,
    severity,
    category: "container_exposure",
    affectedAsset: url,
    remediation: remediationMap[probe.type] ?? "Restrict access to internal networks and configure proper authentication.",
  };
}

export async function runContainerDetection(
  domain: string,
  signal?: AbortSignal,
): Promise<ContainerDetectionResults> {
  const startTime = Date.now();

  log.info({ domain }, "Starting container exposure detection");

  // Build all probe targets
  const targets: ProbeTarget[] = [];
  for (const prefix of SUBDOMAIN_PREFIXES) {
    const host = prefix ? `${prefix}${domain}` : domain;
    for (const probe of CONTAINER_PROBES) {
      for (const scheme of ["https", "http"]) {
        targets.push({
          url: `${scheme}://${host}${probe.path}`,
          host,
          probe,
        });
      }
    }
  }

  const exposedEndpoints: ContainerDetectionResults["exposedEndpoints"] = [];
  const findings: ContainerDetectionResults["findings"] = [];
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

  for (const result of results) {
    if (!result) continue;

    const { target, res } = result;
    const { status, body } = res;

    // Only consider 200-level responses as exposed endpoints
    if (status < 200 || status >= 300) continue;

    // Deduplicate by host+path (we try both http/https)
    const endpointKey = `${target.host}${target.probe.path}`;
    if (seenEndpoints.has(endpointKey)) continue;
    seenEndpoints.add(endpointKey);

    const authenticated = isAuthenticated(status, body);

    exposedEndpoints.push({
      url: target.url,
      path: target.probe.path,
      type: target.probe.type,
      status,
      authenticated,
    });

    // Only generate findings for non-trivial exposure (skip low-severity authenticated endpoints)
    if (!authenticated || target.probe.severityIfExposed === "critical" || target.probe.severityIfExposed === "high") {
      findings.push(buildFindingForEndpoint(target.probe, target.url, authenticated));
    }
  }

  const duration = Date.now() - startTime;

  log.info(
    { domain, exposed: exposedEndpoints.length, findings: findings.length, duration },
    "Container detection complete",
  );

  return { exposedEndpoints, findings, duration };
}
