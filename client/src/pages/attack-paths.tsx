import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, AlertTriangle, ArrowRight, Globe, Key, Server, Lock, Bug, Zap } from "lucide-react";

interface Finding {
  id: string;
  title: string;
  severity: string;
  category: string;
  affectedAsset: string | null;
  status: string;
  description: string;
}

interface AttackNode {
  id: string;
  label: string;
  type: "entry" | "pivot" | "target" | "impact";
  severity: "critical" | "high" | "medium" | "low" | "info";
  findings: Finding[];
  icon: typeof Globe;
}

interface AttackEdge {
  from: string;
  to: string;
  label: string;
}

interface AttackPath {
  id: string;
  name: string;
  riskScore: number;
  nodes: AttackNode[];
  edges: AttackEdge[];
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/15 border-red-500/40 text-red-700 dark:text-red-400",
  high: "bg-orange-500/15 border-orange-500/40 text-orange-700 dark:text-orange-400",
  medium: "bg-yellow-500/15 border-yellow-500/40 text-yellow-700 dark:text-yellow-400",
  low: "bg-blue-500/15 border-blue-500/40 text-blue-700 dark:text-blue-400",
  info: "bg-gray-500/15 border-gray-500/40 text-gray-700 dark:text-gray-400",
};

const CATEGORY_ICON: Record<string, typeof Globe> = {
  xss: Bug,
  cors_misconfiguration: Globe,
  transport_security: Lock,
  security_headers: Shield,
  cookie_security: Key,
  open_redirect: ArrowRight,
  information_disclosure: Server,
  dns_security: Globe,
  ssl_tls: Lock,
  exposed_credentials: Key,
  secret_exposure: Key,
  subdomain_takeover: Zap,
  api_exposure: Server,
};

function categorizeFindings(findings: Finding[]): Map<string, Finding[]> {
  const map = new Map<string, Finding[]>();
  for (const f of findings) {
    const cat = f.category;
    const existing = map.get(cat) ?? [];
    existing.push(f);
    map.set(cat, existing);
  }
  return map;
}

function buildAttackPaths(findings: Finding[]): AttackPath[] {
  const openFindings = findings.filter((f) => f.status === "open" || f.status === "in_review");
  if (openFindings.length === 0) return [];

  const categorized = categorizeFindings(openFindings);
  const paths: AttackPath[] = [];

  // Path 1: External Reconnaissance → Initial Access chain
  const reconCategories = ["information_disclosure", "dns_security", "security_headers", "exposed_service"];
  const accessCategories = ["xss", "open_redirect", "cors_misconfiguration", "api_exposure"];
  const impactCategories = ["exposed_credentials", "secret_exposure", "cookie_security"];

  const reconFindings = reconCategories.flatMap((c) => categorized.get(c) ?? []);
  const accessFindings = accessCategories.flatMap((c) => categorized.get(c) ?? []);
  const impactFindings = impactCategories.flatMap((c) => categorized.get(c) ?? []);

  if (reconFindings.length + accessFindings.length + impactFindings.length > 0) {
    const nodes: AttackNode[] = [];
    const edges: AttackEdge[] = [];

    if (reconFindings.length > 0) {
      nodes.push({
        id: "recon",
        label: "Reconnaissance",
        type: "entry",
        severity: highestSeverity(reconFindings),
        findings: reconFindings,
        icon: Globe,
      });
    }
    if (accessFindings.length > 0) {
      nodes.push({
        id: "access",
        label: "Initial Access",
        type: "pivot",
        severity: highestSeverity(accessFindings),
        findings: accessFindings,
        icon: Bug,
      });
      if (nodes.find((n) => n.id === "recon")) {
        edges.push({ from: "recon", to: "access", label: "Exploit web vulnerabilities" });
      }
    }
    if (impactFindings.length > 0) {
      nodes.push({
        id: "impact",
        label: "Data Exfiltration",
        type: "impact",
        severity: highestSeverity(impactFindings),
        findings: impactFindings,
        icon: Key,
      });
      const prev = nodes[nodes.length - 2];
      if (prev) {
        edges.push({ from: prev.id, to: "impact", label: "Extract secrets/credentials" });
      }
    }

    if (nodes.length > 0) {
      paths.push({
        id: "chain-web",
        name: "Web Application Attack Chain",
        riskScore: computePathRisk(nodes),
        nodes,
        edges,
      });
    }
  }

  // Path 2: Subdomain Takeover chain
  const takeoverFindings = categorized.get("subdomain_takeover") ?? [];
  if (takeoverFindings.length > 0) {
    paths.push({
      id: "chain-takeover",
      name: "Subdomain Takeover Chain",
      riskScore: computePathRisk([{
        id: "takeover",
        label: "Subdomain Takeover",
        type: "entry",
        severity: highestSeverity(takeoverFindings),
        findings: takeoverFindings,
        icon: Zap,
      }]),
      nodes: [
        {
          id: "dangling-dns",
          label: "Dangling DNS",
          type: "entry",
          severity: "high",
          findings: [],
          icon: Globe,
        },
        {
          id: "takeover",
          label: "Subdomain Takeover",
          type: "pivot",
          severity: highestSeverity(takeoverFindings),
          findings: takeoverFindings,
          icon: Zap,
        },
        {
          id: "phishing",
          label: "Phishing / Cookie Theft",
          type: "impact",
          severity: "critical",
          findings: [],
          icon: AlertTriangle,
        },
      ],
      edges: [
        { from: "dangling-dns", to: "takeover", label: "Claim orphaned subdomain" },
        { from: "takeover", to: "phishing", label: "Host malicious content" },
      ],
    });
  }

  // Path 3: TLS/Transport attack chain
  const tlsFindings = [...(categorized.get("ssl_tls") ?? []), ...(categorized.get("transport_security") ?? [])];
  if (tlsFindings.length > 0) {
    paths.push({
      id: "chain-tls",
      name: "Transport Security Attack Chain",
      riskScore: computePathRisk([{
        id: "tls",
        label: "TLS Weakness",
        type: "entry",
        severity: highestSeverity(tlsFindings),
        findings: tlsFindings,
        icon: Lock,
      }]),
      nodes: [
        {
          id: "network",
          label: "Network Position",
          type: "entry",
          severity: "info",
          findings: [],
          icon: Server,
        },
        {
          id: "tls-weakness",
          label: "TLS/HSTS Weakness",
          type: "pivot",
          severity: highestSeverity(tlsFindings),
          findings: tlsFindings,
          icon: Lock,
        },
        {
          id: "mitm",
          label: "Man-in-the-Middle",
          type: "impact",
          severity: "high",
          findings: [],
          icon: AlertTriangle,
        },
      ],
      edges: [
        { from: "network", to: "tls-weakness", label: "Intercept traffic" },
        { from: "tls-weakness", to: "mitm", label: "Downgrade / strip encryption" },
      ],
    });
  }

  // Path 4: API exposure chain
  const apiFindings = categorized.get("api_exposure") ?? [];
  if (apiFindings.length > 1) {
    paths.push({
      id: "chain-api",
      name: "API Exploitation Chain",
      riskScore: computePathRisk([{
        id: "api",
        label: "API Exposure",
        type: "entry",
        severity: highestSeverity(apiFindings),
        findings: apiFindings,
        icon: Server,
      }]),
      nodes: [
        {
          id: "api-discovery",
          label: "API Discovery",
          type: "entry",
          severity: "medium",
          findings: apiFindings.slice(0, Math.ceil(apiFindings.length / 2)),
          icon: Globe,
        },
        {
          id: "api-abuse",
          label: "API Abuse",
          type: "pivot",
          severity: highestSeverity(apiFindings),
          findings: apiFindings.slice(Math.ceil(apiFindings.length / 2)),
          icon: Bug,
        },
        {
          id: "data-access",
          label: "Unauthorized Data Access",
          type: "impact",
          severity: "high",
          findings: [],
          icon: Key,
        },
      ],
      edges: [
        { from: "api-discovery", to: "api-abuse", label: "Enumerate endpoints" },
        { from: "api-abuse", to: "data-access", label: "Bypass auth / extract data" },
      ],
    });
  }

  return paths.sort((a, b) => b.riskScore - a.riskScore);
}

function highestSeverity(findings: Finding[]): "critical" | "high" | "medium" | "low" | "info" {
  const order = ["critical", "high", "medium", "low", "info"];
  for (const s of order) {
    if (findings.some((f) => f.severity === s)) return s as "critical" | "high" | "medium" | "low" | "info";
  }
  return "info";
}

function computePathRisk(nodes: AttackNode[]): number {
  const severityScores: Record<string, number> = { critical: 10, high: 7.5, medium: 5, low: 2.5, info: 1 };
  let total = 0;
  for (const node of nodes) {
    const nodeSeverityScore = severityScores[node.severity] ?? 1;
    total += nodeSeverityScore * Math.max(1, node.findings.length);
  }
  return Math.min(100, Math.round(total));
}

function NodeCard({ node }: { node: AttackNode }) {
  const Icon = node.icon;
  const colorClass = SEVERITY_COLORS[node.severity] ?? SEVERITY_COLORS.info;

  return (
    <div className={`rounded-lg border-2 p-3 min-w-[160px] ${colorClass}`}>
      <div className="flex items-center gap-2 mb-1">
        <Icon className="w-4 h-4" />
        <span className="font-semibold text-sm">{node.label}</span>
      </div>
      {node.findings.length > 0 && (
        <div className="text-xs opacity-80">
          {node.findings.length} finding{node.findings.length !== 1 ? "s" : ""}
        </div>
      )}
      {node.findings.length > 0 && (
        <div className="mt-2 space-y-1 max-h-24 overflow-y-auto">
          {node.findings.slice(0, 3).map((f) => (
            <div key={f.id} className="text-xs truncate opacity-75" title={f.title}>
              {f.title}
            </div>
          ))}
          {node.findings.length > 3 && (
            <div className="text-xs opacity-50">+{node.findings.length - 3} more</div>
          )}
        </div>
      )}
    </div>
  );
}

function AttackPathCard({ path }: { path: AttackPath }) {
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg">{path.name}</CardTitle>
          <Badge variant={path.riskScore >= 50 ? "destructive" : path.riskScore >= 25 ? "default" : "secondary"}>
            Risk: {path.riskScore}
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        <div className="flex items-center gap-2 overflow-x-auto pb-2">
          {path.nodes.map((node, idx) => (
            <div key={node.id} className="flex items-center gap-2 shrink-0">
              <NodeCard node={node} />
              {idx < path.nodes.length - 1 && (
                <div className="flex flex-col items-center shrink-0">
                  <ArrowRight className="w-5 h-5 text-muted-foreground" />
                  {path.edges[idx] && (
                    <span className="text-[10px] text-muted-foreground max-w-[100px] text-center leading-tight">
                      {path.edges[idx].label}
                    </span>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function AttackPathsPage() {
  const { selectedWorkspace: workspace } = useDomain();

  const { data: findings = [], isLoading } = useQuery<Finding[]>({
    queryKey: [`/api/workspaces/${workspace?.id}/findings`],
    enabled: !!workspace,
  });

  const attackPaths = useMemo(() => buildAttackPaths(findings), [findings]);

  if (!workspace) {
    return (
      <div className="p-6">
        <p className="text-muted-foreground">Select a workspace to view attack paths.</p>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Attack Path Visualization</h1>
        <p className="text-muted-foreground">
          Automated attack chains derived from scan findings, showing how vulnerabilities can be chained together.
        </p>
      </div>

      {isLoading ? (
        <p className="text-muted-foreground">Analyzing attack paths...</p>
      ) : attackPaths.length === 0 ? (
        <Card>
          <CardContent className="p-8 text-center">
            <Shield className="w-12 h-12 mx-auto mb-4 text-green-500/40" />
            <p className="text-muted-foreground">No attack paths detected. Run a scan to discover potential vulnerability chains.</p>
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-3 gap-4">
            <Card>
              <CardContent className="p-4 text-center">
                <div className="text-3xl font-bold">{attackPaths.length}</div>
                <div className="text-sm text-muted-foreground">Attack Chains</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4 text-center">
                <div className="text-3xl font-bold text-red-500">
                  {attackPaths.filter((p) => p.riskScore >= 50).length}
                </div>
                <div className="text-sm text-muted-foreground">High Risk Paths</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4 text-center">
                <div className="text-3xl font-bold">
                  {Math.max(...attackPaths.map((p) => p.riskScore))}
                </div>
                <div className="text-sm text-muted-foreground">Max Risk Score</div>
              </CardContent>
            </Card>
          </div>

          <div className="space-y-4">
            {attackPaths.map((path) => (
              <AttackPathCard key={path.id} path={path} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}

export default AttackPathsPage;
