import net from "net";
import { createLogger } from "../logger.js";
import { runWithConcurrency } from "./utils.js";

const log = createLogger("port-scan");

const CONNECT_TIMEOUT_MS = 3000;
const BATCH_CONCURRENCY = 20;

const SERVICE_MAP: Record<number, string> = {
  21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
  80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
  143: "imap", 443: "https", 445: "smb", 465: "smtps", 587: "submission",
  993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 1723: "pptp",
  2375: "docker", 2376: "docker-tls", 3306: "mysql", 3389: "rdp",
  4243: "docker", 5432: "postgresql", 5900: "vnc", 5984: "couchdb",
  6379: "redis", 6443: "kubernetes-api", 8080: "http-proxy", 8443: "https-alt",
  8888: "http-alt", 9042: "cassandra", 9090: "prometheus", 9200: "elasticsearch",
  9300: "elasticsearch-transport", 10250: "kubelet", 11211: "memcached",
  15672: "rabbitmq-mgmt", 27017: "mongodb", 28017: "mongodb-web",
  50070: "hadoop-namenode",
};

const DEFAULT_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
  1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 27017,
  // Additional common ports
  465, 587, 1433, 1521, 2375, 2376, 3000, 4243, 5000, 5601, 5984,
  6443, 7000, 8000, 8009, 8088, 9042, 9090, 9200, 9300, 9418,
  10250, 11211, 15672, 28017, 50070,
  // Web alternates
  80, 443, 8080, 8443, 8888, 9000, 9090, 3000, 4000, 5000,
  // Infrastructure
  389, 636, 873, 2049, 2181, 4848, 5353, 7077, 8161, 8172, 8983,
];

const DANGEROUS_SERVICES: Record<number, { title: string; severity: string; remediation: string }> = {
  27017: {
    title: "MongoDB Exposed Without Authentication",
    severity: "critical",
    remediation: "Enable MongoDB authentication and restrict network access using firewall rules. Bind to localhost or internal interfaces only.",
  },
  28017: {
    title: "MongoDB Web Interface Exposed",
    severity: "high",
    remediation: "Disable the MongoDB HTTP interface and restrict access to internal networks only.",
  },
  6379: {
    title: "Redis Exposed Without Authentication",
    severity: "critical",
    remediation: "Enable Redis AUTH, bind to localhost or internal interfaces, and use firewall rules to restrict access.",
  },
  9200: {
    title: "Elasticsearch Exposed Without Authentication",
    severity: "critical",
    remediation: "Enable Elasticsearch security features (X-Pack), restrict network access, and require authentication.",
  },
  9300: {
    title: "Elasticsearch Transport Port Exposed",
    severity: "high",
    remediation: "Restrict Elasticsearch transport port to internal cluster communication only using firewall rules.",
  },
  8080: {
    title: "HTTP Proxy / Admin Panel Exposed",
    severity: "medium",
    remediation: "Restrict access to administrative interfaces using authentication and firewall rules.",
  },
  8443: {
    title: "HTTPS Alternate / Admin Panel Exposed",
    severity: "medium",
    remediation: "Restrict access to administrative interfaces using authentication and IP whitelisting.",
  },
  2375: {
    title: "Docker API Exposed (Unauthenticated)",
    severity: "critical",
    remediation: "Never expose the Docker daemon socket to the network. Use TLS authentication (port 2376) and restrict access.",
  },
  4243: {
    title: "Docker API Exposed (Legacy Port)",
    severity: "critical",
    remediation: "Disable legacy Docker API port and migrate to TLS-authenticated access on port 2376.",
  },
  6443: {
    title: "Kubernetes API Server Exposed",
    severity: "high",
    remediation: "Restrict Kubernetes API access using network policies, RBAC, and firewall rules.",
  },
  10250: {
    title: "Kubelet API Exposed",
    severity: "high",
    remediation: "Restrict kubelet API access to the control plane only and enable authentication.",
  },
  11211: {
    title: "Memcached Exposed",
    severity: "high",
    remediation: "Bind Memcached to localhost and restrict access using firewall rules. Disable UDP if not needed.",
  },
  5984: {
    title: "CouchDB Exposed",
    severity: "high",
    remediation: "Enable CouchDB authentication, restrict network access, and bind to internal interfaces.",
  },
  5900: {
    title: "VNC Exposed",
    severity: "high",
    remediation: "Use VNC over an encrypted tunnel (SSH/VPN) and restrict direct access with firewall rules.",
  },
  3389: {
    title: "RDP Exposed to Internet",
    severity: "high",
    remediation: "Restrict RDP access via VPN or bastion host. Enable Network Level Authentication and use strong credentials.",
  },
  23: {
    title: "Telnet Service Exposed",
    severity: "high",
    remediation: "Disable Telnet and migrate to SSH for remote administration. Telnet transmits credentials in cleartext.",
  },
};

export interface PortScanResults {
  openPorts: Array<{ port: number; service: string; banner?: string }>;
  closedCount: number;
  filteredCount: number;
  scannedCount: number;
  duration: number;
  findings: Array<{
    title: string;
    description: string;
    severity: string;
    category: string;
    affectedAsset: string;
    remediation: string;
  }>;
}

interface PortProbeResult {
  port: number;
  state: "open" | "closed" | "filtered";
  banner?: string;
}

function probePort(host: string, port: number, timeout: number): Promise<PortProbeResult> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let banner: string | undefined;

    const cleanup = () => {
      socket.removeAllListeners();
      socket.destroy();
    };

    socket.setTimeout(timeout);

    socket.on("connect", () => {
      socket.setTimeout(1000);
      socket.once("data", (data) => {
        banner = data.toString("utf-8").trim().substring(0, 256);
        cleanup();
        resolve({ port, state: "open", banner });
      });
      // If no banner arrives within the extra timeout, still report open
      socket.once("timeout", () => {
        cleanup();
        resolve({ port, state: "open", banner });
      });
    });

    socket.on("timeout", () => {
      cleanup();
      resolve({ port, state: "filtered" });
    });

    socket.on("error", (err: NodeJS.ErrnoException) => {
      cleanup();
      if (err.code === "ECONNREFUSED") {
        resolve({ port, state: "closed" });
      } else {
        resolve({ port, state: "filtered" });
      }
    });

    socket.connect(port, host);
  });
}

export async function runPortScan(
  host: string,
  ports?: number[],
  signal?: AbortSignal,
): Promise<PortScanResults> {
  const startTime = Date.now();
  const targetPorts = ports ?? Array.from(new Set(DEFAULT_PORTS));
  const uniquePorts = Array.from(new Set(targetPorts)).sort((a, b) => a - b);

  log.info({ host, portCount: uniquePorts.length }, "Starting port scan");

  const probeResults = await runWithConcurrency(
    uniquePorts,
    BATCH_CONCURRENCY,
    (port) => probePort(host, port, CONNECT_TIMEOUT_MS),
    signal,
  );

  const openPorts: PortScanResults["openPorts"] = [];
  let closedCount = 0;
  let filteredCount = 0;

  for (const result of probeResults) {
    if (!result) continue;
    switch (result.state) {
      case "open":
        openPorts.push({
          port: result.port,
          service: SERVICE_MAP[result.port] ?? "unknown",
          banner: result.banner,
        });
        break;
      case "closed":
        closedCount++;
        break;
      case "filtered":
        filteredCount++;
        break;
    }
  }

  const findings: PortScanResults["findings"] = [];

  for (const openPort of openPorts) {
    const dangerInfo = DANGEROUS_SERVICES[openPort.port];
    if (dangerInfo) {
      findings.push({
        title: dangerInfo.title,
        description: `Port ${openPort.port} (${openPort.service}) is open and accessible on ${host}. This service is commonly targeted by attackers when exposed to the internet without proper authentication.`,
        severity: dangerInfo.severity,
        category: "exposed_service",
        affectedAsset: `${host}:${openPort.port}`,
        remediation: dangerInfo.remediation,
      });
    }
  }

  const duration = Date.now() - startTime;

  log.info(
    { host, open: openPorts.length, closed: closedCount, filtered: filteredCount, duration },
    "Port scan complete",
  );

  return {
    openPorts,
    closedCount,
    filteredCount,
    scannedCount: uniquePorts.length,
    duration,
    findings,
  };
}
