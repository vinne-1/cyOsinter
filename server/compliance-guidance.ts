import { createLogger } from "./logger";

const log = createLogger("compliance-guidance");

interface RemediationStep {
  title: string;
  description: string;
  effort: "low" | "medium" | "high";
  codeExample?: string;
  configExample?: string;
}

interface FrameworkControl {
  id: string;
  title: string;
  remediationSteps: RemediationStep[];
}

interface FrameworkDefinition {
  name: string;
  controls: FrameworkControl[];
}

const FRAMEWORKS: Record<string, FrameworkDefinition> = {
  "pci-dss": {
    name: "PCI-DSS 4.0",
    controls: [
      {
        id: "req-1",
        title: "Requirement 1: Install and Maintain Network Security Controls",
        remediationSteps: [
          {
            title: "Implement firewall rules for cardholder data environment",
            description:
              "Configure network security controls (firewalls, security groups) to restrict inbound and outbound traffic to only what is necessary for the cardholder data environment (CDE).",
            effort: "high",
            configExample: `# iptables example: restrict CDE subnet
iptables -A INPUT -s 10.0.1.0/24 -d 10.0.2.0/24 -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -s 0.0.0.0/0 -d 10.0.2.0/24 -j DROP

# AWS Security Group (Terraform)
resource "aws_security_group" "cde" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}`,
          },
          {
            title: "Document and review all network connections",
            description:
              "Maintain an up-to-date network diagram showing all connections to and from the CDE. Review quarterly and after any network changes.",
            effort: "medium",
          },
          {
            title: "Restrict traffic between trusted and untrusted networks",
            description:
              "Ensure DMZ is properly configured to separate public-facing systems from the internal CDE. Deny all traffic by default and allow only by exception.",
            effort: "medium",
            configExample: `# nginx reverse proxy in DMZ
server {
    listen 443 ssl;
    server_name api.example.com;

    ssl_certificate     /etc/ssl/certs/api.crt;
    ssl_certificate_key /etc/ssl/private/api.key;

    location / {
        proxy_pass http://10.0.2.10:8080;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}`,
          },
        ],
      },
      {
        id: "req-2",
        title: "Requirement 2: Apply Secure Configurations to All System Components",
        remediationSteps: [
          {
            title: "Change all vendor-supplied default passwords",
            description:
              "Identify and change all default passwords, accounts, and SNMP community strings on all system components before deploying to production.",
            effort: "low",
            codeExample: `# Script to check for default credentials
#!/bin/bash
# Check common default credentials
services=("mysql" "postgres" "redis" "mongodb")
for svc in "\${services[@]}"; do
  echo "Checking $svc for default credentials..."
done
# Use a credential scanner like hydra or ncrack for automated checks`,
          },
          {
            title: "Disable unnecessary services and protocols",
            description:
              "Remove or disable unnecessary services, protocols, daemons, and functions. Enable only the services, protocols, and ports required for the system to function.",
            effort: "medium",
            configExample: `# Disable unnecessary systemd services
systemctl disable telnet.socket
systemctl disable rsh.socket
systemctl disable rlogin.socket
systemctl stop telnet.socket rsh.socket rlogin.socket

# Harden sshd_config
Protocol 2
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2`,
          },
        ],
      },
      {
        id: "req-3",
        title: "Requirement 3: Protect Stored Account Data",
        remediationSteps: [
          {
            title: "Implement strong encryption for stored cardholder data",
            description:
              "Encrypt stored PAN using strong cryptography with associated key-management processes. Use AES-256 or equivalent. Never store full magnetic stripe data, CVV, or PIN after authorization.",
            effort: "high",
            codeExample: `import crypto from "crypto";

const ALGORITHM = "aes-256-gcm";

function encryptPAN(pan: string, key: Buffer): { encrypted: string; iv: string; tag: string } {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  let encrypted = cipher.update(pan, "utf8", "hex");
  encrypted += cipher.final("hex");
  const tag = cipher.getAuthTag();
  return {
    encrypted,
    iv: iv.toString("hex"),
    tag: tag.toString("hex"),
  };
}`,
          },
          {
            title: "Implement data retention and disposal policies",
            description:
              "Define and implement a data retention policy. Securely delete cardholder data when no longer needed. Implement automated quarterly processes to identify and delete stale data.",
            effort: "medium",
          },
        ],
      },
      {
        id: "req-4",
        title: "Requirement 4: Protect Cardholder Data with Strong Cryptography During Transmission",
        remediationSteps: [
          {
            title: "Enforce TLS 1.2+ for all data transmissions",
            description:
              "Configure all systems to use TLS 1.2 or higher for transmitting cardholder data over open, public networks. Disable SSLv3, TLS 1.0, and TLS 1.1.",
            effort: "medium",
            configExample: `# nginx TLS configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers on;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;

# HSTS
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;`,
          },
          {
            title: "Implement certificate pinning for mobile applications",
            description:
              "For mobile apps handling cardholder data, implement certificate pinning to prevent MITM attacks. Maintain a pin rotation schedule.",
            effort: "high",
          },
        ],
      },
      {
        id: "req-6",
        title: "Requirement 6: Develop and Maintain Secure Systems and Software",
        remediationSteps: [
          {
            title: "Implement secure coding practices",
            description:
              "Train developers on secure coding. Address OWASP Top 10 vulnerabilities. Perform code reviews for all custom code changes before release.",
            effort: "high",
            codeExample: `// Input validation example
import { z } from "zod";

const paymentSchema = z.object({
  amount: z.number().positive().max(999999),
  currency: z.enum(["USD", "EUR", "GBP"]),
  cardToken: z.string().min(10).max(100),
});

function processPayment(input: unknown) {
  const validated = paymentSchema.parse(input);
  // Process only validated data
}`,
          },
          {
            title: "Deploy a Web Application Firewall (WAF)",
            description:
              "Place a WAF in front of public-facing web applications to detect and prevent web-based attacks. Keep WAF rules updated.",
            effort: "medium",
            configExample: `# ModSecurity WAF rule example
SecRuleEngine On
SecRequestBodyAccess On

# Block SQL injection
SecRule ARGS "@detectSQLi" "id:1,phase:2,deny,status:403,msg:'SQL Injection Detected'"

# Block XSS
SecRule ARGS "@detectXSS" "id:2,phase:2,deny,status:403,msg:'XSS Detected'"`,
          },
          {
            title: "Maintain a vulnerability management program",
            description:
              "Keep all system components patched. Install critical security patches within one month of release. Perform regular vulnerability scans.",
            effort: "medium",
          },
        ],
      },
      {
        id: "req-11",
        title: "Requirement 11: Test Security of Systems and Networks Regularly",
        remediationSteps: [
          {
            title: "Run quarterly vulnerability scans",
            description:
              "Perform internal and external network vulnerability scans at least quarterly and after any significant change. Use an ASV for external scans.",
            effort: "medium",
          },
          {
            title: "Conduct annual penetration testing",
            description:
              "Perform network and application layer penetration tests at least annually and after significant infrastructure or application changes.",
            effort: "high",
          },
          {
            title: "Implement file integrity monitoring",
            description:
              "Deploy file integrity monitoring (FIM) tools to alert personnel to unauthorized modification of critical system files, configuration files, and content files.",
            effort: "medium",
            configExample: `# AIDE (Advanced Intrusion Detection Environment) config
# /etc/aide/aide.conf
/etc    p+i+n+u+g+s+b+m+c+sha256
/bin    p+i+n+u+g+s+b+m+c+sha256
/sbin   p+i+n+u+g+s+b+m+c+sha256
/var/log p+i+n+u+g+s+b+m+c+sha256

# Initialize and check
# aide --init
# aide --check`,
          },
        ],
      },
    ],
  },

  hipaa: {
    name: "HIPAA",
    controls: [
      {
        id: "access-control",
        title: "Access Control (164.312(a))",
        remediationSteps: [
          {
            title: "Implement role-based access control (RBAC)",
            description:
              "Assign access rights based on the minimum necessary standard. Implement unique user identification and enforce automatic logoff after periods of inactivity.",
            effort: "high",
            codeExample: `// RBAC middleware example
const ROLE_PERMISSIONS: Record<string, string[]> = {
  physician: ["read:phi", "write:phi", "read:records"],
  nurse: ["read:phi", "read:records"],
  admin: ["read:records", "manage:users"],
  billing: ["read:billing", "read:demographics"],
};

function requirePermission(permission: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const userRole = req.user?.role;
    if (!userRole || !ROLE_PERMISSIONS[userRole]?.includes(permission)) {
      return res.status(403).json({ error: "Insufficient permissions" });
    }
    next();
  };
}`,
          },
          {
            title: "Enable multi-factor authentication for PHI access",
            description:
              "Require MFA for all users accessing systems containing Protected Health Information (PHI). Use TOTP or FIDO2 as the second factor.",
            effort: "medium",
          },
          {
            title: "Implement emergency access procedures",
            description:
              "Establish procedures for obtaining necessary ePHI during an emergency. Document break-glass procedures and audit all emergency access events.",
            effort: "medium",
          },
        ],
      },
      {
        id: "audit-controls",
        title: "Audit Controls (164.312(b))",
        remediationSteps: [
          {
            title: "Implement comprehensive audit logging",
            description:
              "Log all access to PHI including who accessed it, when, what was accessed, and from where. Retain logs for a minimum of 6 years.",
            effort: "high",
            codeExample: `// Audit logging for PHI access
interface AuditEntry {
  userId: string;
  action: "read" | "write" | "delete" | "export";
  resourceType: string;
  resourceId: string;
  timestamp: string;
  ipAddress: string;
  userAgent: string;
  outcome: "success" | "failure";
}

async function logPHIAccess(entry: AuditEntry): Promise<void> {
  // Write to immutable audit log (append-only)
  await auditStore.append(entry);
}`,
          },
          {
            title: "Set up automated log review and alerting",
            description:
              "Configure SIEM or log analysis to automatically detect and alert on suspicious access patterns, such as bulk PHI exports, after-hours access, or access from unusual locations.",
            effort: "medium",
          },
        ],
      },
      {
        id: "integrity",
        title: "Integrity Controls (164.312(c))",
        remediationSteps: [
          {
            title: "Implement data integrity verification",
            description:
              "Use checksums, digital signatures, or HMACs to ensure ePHI has not been altered or destroyed in an unauthorized manner during storage and transmission.",
            effort: "medium",
            codeExample: `import crypto from "crypto";

function computeIntegrityHash(data: string, secret: string): string {
  return crypto.createHmac("sha256", secret).update(data).digest("hex");
}

function verifyIntegrity(data: string, expectedHash: string, secret: string): boolean {
  const computed = computeIntegrityHash(data, secret);
  return crypto.timingSafeEqual(Buffer.from(computed), Buffer.from(expectedHash));
}`,
          },
          {
            title: "Enable database-level integrity constraints",
            description:
              "Use database constraints, triggers, and row-level security to prevent unauthorized modifications. Implement versioning for PHI records.",
            effort: "medium",
          },
        ],
      },
      {
        id: "transmission-security",
        title: "Transmission Security (164.312(e))",
        remediationSteps: [
          {
            title: "Encrypt all PHI in transit",
            description:
              "Use TLS 1.2+ for all connections transmitting ePHI. Implement end-to-end encryption for messages containing PHI.",
            effort: "medium",
            configExample: `# nginx config for HIPAA-compliant TLS
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers on;
ssl_ecdh_curve secp384r1;

add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;`,
          },
          {
            title: "Implement VPN for remote access to PHI systems",
            description:
              "Require VPN connections for any remote access to systems containing PHI. Use IKEv2 or WireGuard with strong authentication.",
            effort: "high",
          },
        ],
      },
    ],
  },

  "soc-2": {
    name: "SOC 2",
    controls: [
      {
        id: "cc6.1",
        title: "CC6.1: Logical and Physical Access Controls",
        remediationSteps: [
          {
            title: "Implement centralized identity management",
            description:
              "Use a centralized identity provider (IdP) with SSO for all critical systems. Enforce password complexity requirements and account lockout policies.",
            effort: "high",
            codeExample: `// Password policy enforcement
const PASSWORD_POLICY = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecial: true,
  maxAgeDays: 90,
  historyCount: 12,
};

function validatePassword(password: string): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  if (password.length < PASSWORD_POLICY.minLength) {
    errors.push(\`Minimum length: \${PASSWORD_POLICY.minLength}\`);
  }
  if (PASSWORD_POLICY.requireUppercase && !/[A-Z]/.test(password)) {
    errors.push("Must contain uppercase letter");
  }
  if (PASSWORD_POLICY.requireSpecial && !/[!@#$%^&*]/.test(password)) {
    errors.push("Must contain special character");
  }
  return { valid: errors.length === 0, errors };
}`,
          },
          {
            title: "Implement least-privilege access",
            description:
              "Review and restrict user access to the minimum required for their role. Conduct quarterly access reviews and promptly revoke access for terminated employees.",
            effort: "medium",
          },
          {
            title: "Enable MFA for all privileged accounts",
            description:
              "Require multi-factor authentication for administrative access, production systems, and cloud console access.",
            effort: "low",
          },
        ],
      },
      {
        id: "cc6.6",
        title: "CC6.6: System Operations Security",
        remediationSteps: [
          {
            title: "Implement network segmentation",
            description:
              "Segment production, staging, and development environments. Restrict lateral movement between network zones using firewalls and ACLs.",
            effort: "high",
            configExample: `# Kubernetes NetworkPolicy example
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-production
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              env: production
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              env: production`,
          },
          {
            title: "Implement endpoint detection and response",
            description:
              "Deploy EDR agents on all production servers and workstations. Configure alerts for suspicious activities such as unusual process execution or file modifications.",
            effort: "medium",
          },
        ],
      },
      {
        id: "cc7.2",
        title: "CC7.2: Monitoring Activities",
        remediationSteps: [
          {
            title: "Implement centralized security monitoring",
            description:
              "Deploy a SIEM solution to aggregate logs from all systems. Create correlation rules for common attack patterns and configure real-time alerting.",
            effort: "high",
          },
          {
            title: "Establish an incident response plan",
            description:
              "Document and maintain an incident response plan. Define severity levels, escalation procedures, communication templates, and conduct tabletop exercises quarterly.",
            effort: "medium",
          },
          {
            title: "Configure uptime and performance monitoring",
            description:
              "Monitor system availability, performance metrics, and error rates. Set up alerting thresholds and on-call rotation.",
            effort: "low",
            configExample: `# Prometheus alerting rules example
groups:
  - name: availability
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"
      - alert: ServiceDown
        expr: up == 0
        for: 1m
        labels:
          severity: critical`,
          },
        ],
      },
      {
        id: "cc8.1",
        title: "CC8.1: Change Management",
        remediationSteps: [
          {
            title: "Implement formal change management process",
            description:
              "Require change requests, peer review, and approval for all production changes. Use pull requests with mandatory code review and CI/CD pipelines with automated testing.",
            effort: "medium",
            codeExample: `# GitHub Actions CI/CD pipeline
# .github/workflows/deploy.yml
name: Production Deploy
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm test
      - run: npm run build
      # Requires manual approval via GitHub environment protection rules
      - run: npm run deploy`,
          },
          {
            title: "Maintain a change log and rollback procedures",
            description:
              "Document all changes to production systems including who made the change, what was changed, and when. Ensure rollback procedures are tested and documented.",
            effort: "low",
          },
        ],
      },
    ],
  },
};

export function getRemediationGuidance(
  framework: string,
  controlId: string,
): RemediationStep[] {
  const normalizedFramework = framework.toLowerCase().replace(/\s+/g, "-");
  const frameworkDef = FRAMEWORKS[normalizedFramework];

  if (!frameworkDef) {
    log.warn({ framework }, "Unknown compliance framework requested");
    return [];
  }

  const control = frameworkDef.controls.find(
    (c) => c.id.toLowerCase() === controlId.toLowerCase(),
  );

  if (!control) {
    log.warn({ framework, controlId }, "Unknown control ID requested");
    return [];
  }

  return control.remediationSteps;
}

export function getFrameworkControls(framework: string): FrameworkControl[] {
  const normalizedFramework = framework.toLowerCase().replace(/\s+/g, "-");
  const frameworkDef = FRAMEWORKS[normalizedFramework];

  if (!frameworkDef) {
    log.warn({ framework }, "Unknown compliance framework requested");
    return [];
  }

  return frameworkDef.controls;
}
