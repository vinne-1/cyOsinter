import { computeSurfaceRiskScore, gradeToRisk } from "../scoring.js";
import { detectWAF, detectCDN, checkSecurityHeaders, detectServerInfo } from "./detection.js";

interface EvidenceItem {
  [key: string]: unknown;
  type: string;
  description: string;
  url?: string;
  snippet?: string;
  source?: string;
  verifiedAt?: string;
  raw?: Record<string, unknown>;
}

interface VerifiedFinding {
  title: string;
  description: string;
  severity: string;
  category: string;
  affectedAsset: string;
  cvssScore: string;
  remediation: string;
  evidence: EvidenceItem[];
}

interface ScanResults {
  subdomains: string[];
  assets: Array<{ type: string; value: string; tags: string[] }>;
  findings: VerifiedFinding[];
  reconData: import("./types.js").ReconData;
}

export async function buildReconModules(
  domain: string,
  easmResults: ScanResults | null,
  osintResults: ScanResults | null,
): Promise<Array<{ moduleType: string; data: Record<string, unknown>; confidence: number }>> {
  const modules: Array<{ moduleType: string; data: Record<string, unknown>; confidence: number }> = [];

  if (easmResults) {
    const dnsRecon = easmResults.reconData.dns;
    const discoveredDomains = easmResults.reconData.discoveredDomains || [];
    const liveCount = discoveredDomains.length || (dnsRecon?.liveSubdomains || []).length;
    modules.push({
      moduleType: "web_presence",
      confidence: 95,
      data: {
        source: "Certificate Transparency (crt.sh) + DNS resolution + HTTP probing + subdomain bruteforce",
        totalSubdomains: easmResults.subdomains.length,
        totalSubdomainsEnumerated: easmResults.subdomains.length,
        liveServices: liveCount,
        newSinceLastRun: 0,
        screenshots: [],
        discoveredDomains,
        liveSubdomains: dnsRecon?.liveSubdomains || [],
        danglingCnames: dnsRecon?.danglingCnames || [],
        subdomainBruteforce: easmResults.reconData.subdomainBruteforce ?? null,
        verifiedAt: new Date().toISOString(),
      },
    });

    if (easmResults.reconData.ssl) {
      const ssl = easmResults.reconData.ssl;
      let tlsGrade = "F";
      if (ssl.daysRemaining != null && ssl.daysRemaining <= 0) tlsGrade = "F";
      else if (ssl.daysRemaining != null && ssl.daysRemaining > 0) {
        const proto = (ssl.protocol || "").toLowerCase();
        if ((proto === "tlsv1.2" || proto === "tlsv1.3") && ssl.daysRemaining > 30) tlsGrade = "A";
        else if (proto === "tlsv1.2" || proto === "tlsv1.3") tlsGrade = "B";
        else tlsGrade = "C";
      }
      const rawHeaders = easmResults.reconData.securityHeaders;
      const securityHeaders: Record<string, { present: boolean; value: string | null; grade: string }> = {};
      if (rawHeaders) {
        for (const [k, v] of Object.entries(rawHeaders)) {
          const present = !!v?.present;
          securityHeaders[k] = { present, value: v?.value ?? null, grade: v?.grade ?? (present ? "A" : "N/A") };
        }
      }
      const ips = (dnsRecon?.ips || []) as string[];
      const openPorts = easmResults.reconData.openPorts;
      const openPortsByIp = easmResults.reconData.openPortsByIp;
      const PORT_SERVICES: Record<number, string> = { 21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 11211: "Memcached", 27017: "MongoDB" };
      const publicIPs = ips.map((ip) => ({
        ip,
        banner: "",
        services: ((openPortsByIp?.[ip] ?? openPorts) || []).map((p) => PORT_SERVICES[p] || `Port ${p}`),
        openPorts: openPortsByIp?.[ip] ?? openPorts ?? [],
      }));

      const mainHeaders = easmResults.reconData.serverInfo?.allHeaders;
      const mainWaf = mainHeaders ? detectWAF(mainHeaders) : { detected: false, provider: "" };
      const mainCdn = mainHeaders ? detectCDN(mainHeaders) : "None";

      const wafByHost: Record<string, { waf: boolean; wafProvider: string; cdn: string }> = {};
      if (mainHeaders) wafByHost[domain] = { waf: mainWaf.detected, wafProvider: mainWaf.provider, cdn: mainCdn };
      for (const d of discoveredDomains) {
        wafByHost[d.domain] = { waf: d.waf ?? false, wafProvider: d.wafProvider || "", cdn: d.cdn || "None" };
      }

      const wafCoverage = Object.values(wafByHost).filter(v => v.waf).length;
      const totalHosts = Object.keys(wafByHost).length;

      const serverLeaks = easmResults.reconData.serverInfo?.leaks || [];
      const { score: surfaceRiskScore, breakdown: riskBreakdown } = computeSurfaceRiskScore(tlsGrade, securityHeaders, serverLeaks);

      const perAssetTls = easmResults.reconData.perAssetTls;
      const perAssetHeaders = easmResults.reconData.perAssetHeaders;
      const perAssetLeaks = easmResults.reconData.perAssetLeaks;

      const domainToIp = new Map<string, string>();
      domainToIp.set(domain, ips[0] || "-");
      for (const d of discoveredDomains) {
        domainToIp.set(d.domain, (d as any).ip || "-");
      }

      const assetInventory: Array<{ host: string; ip: string; category: string; riskScore: number; tlsGrade: string; waf: string; cdn: string }> = [];
      for (const host of Object.keys(wafByHost)) {
        const wafInfo = wafByHost[host];
        const hostTls = perAssetTls?.[host];
        const hostHeaders = perAssetHeaders?.[host];
        const hostLeaks = perAssetLeaks?.[host] || [];
        let hostTlsGrade = tlsGrade;
        if (hostTls) {
          const proto = (hostTls.protocol || "").toLowerCase();
          if (hostTls.daysRemaining != null && hostTls.daysRemaining > 0) {
            if ((proto === "tlsv1.2" || proto === "tlsv1.3") && hostTls.daysRemaining > 30) hostTlsGrade = "A";
            else if (proto === "tlsv1.2" || proto === "tlsv1.3") hostTlsGrade = "B";
            else hostTlsGrade = "C";
          } else hostTlsGrade = "F";
        }
        const missingHdrs = hostHeaders ? Object.values(hostHeaders).filter((h) => !h?.present).length : 7;
        const hostRisk = gradeToRisk(hostTlsGrade) + Math.min(40, missingHdrs * 8) + Math.min(30, hostLeaks.length * 10);
        const riskScore = Math.min(100, hostRisk);
        const category = /api\.|app\.|dev\.|staging\./i.test(host) ? "api" : "web_app";
        assetInventory.push({
          host,
          ip: domainToIp.get(host) || "-",
          category,
          riskScore,
          tlsGrade: hostTlsGrade,
          waf: wafInfo.waf ? wafInfo.wafProvider : "",
          cdn: wafInfo.cdn !== "None" ? wafInfo.cdn : "",
        });
      }
      if (assetInventory.length === 0 && ips.length > 0) {
        assetInventory.push({
          host: domain,
          ip: ips[0],
          category: "web_app",
          riskScore: surfaceRiskScore,
          tlsGrade,
          waf: mainWaf.detected ? mainWaf.provider : "",
          cdn: mainCdn !== "None" ? mainCdn : "",
        });
      }

      modules.push({
        moduleType: "attack_surface",
        confidence: 95,
        data: {
          source: "TLS connection + HTTP header analysis + WAF/CDN detection",
          ssl: easmResults.reconData.ssl,
          tlsPosture: { grade: tlsGrade },
          securityHeaders,
          serverInfo: easmResults.reconData.serverInfo ? { leaks: serverLeaks } : {},
          dns: { ns: dnsRecon?.ns || [], ips },
          publicIPs,
          openPortsByIp: openPortsByIp || {},
          surfaceRiskScore,
          riskBreakdown,
          wafDetection: mainWaf,
          cdnDetection: mainCdn,
          wafByHost,
          wafCoverage: { protected: wafCoverage, total: totalHosts },
          perAssetTls: perAssetTls || {},
          perAssetHeaders: perAssetHeaders || {},
          perAssetLeaks: perAssetLeaks || {},
          assetInventory,
          // Raw flat header maps for tech-inventory/Wappalyzer (distinct from grading-wrapper perAssetHeaders)
          rawHeadersByHost: easmResults.reconData.rawHeadersByHost ?? {},
          htmlByHost: easmResults.reconData.htmlByHost ?? {},
          verifiedAt: new Date().toISOString(),
        },
      });
    } else if (easmResults && (dnsRecon?.ips?.length || 0) > 0) {
      const ips = (dnsRecon?.ips || []) as string[];
      const openPorts = easmResults.reconData.openPorts;
      const PORT_SERVICES: Record<number, string> = { 21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 11211: "Memcached", 27017: "MongoDB" };
      const publicIPs = ips.map((ip) => ({
        ip,
        banner: "",
        services: (openPorts || []).map((p) => PORT_SERVICES[p] || `Port ${p}`),
      }));
      modules.push({
        moduleType: "attack_surface",
        confidence: 70,
        data: {
          source: "DNS resolution (TLS check unavailable)",
          securityHeaders: {},
          publicIPs,
          surfaceRiskScore: 50,
          riskBreakdown: [{ category: "TLS/Certificate", score: 50, maxScore: 100 }],
          wafDetection: { detected: false, provider: "" },
          cdnDetection: "None",
          dns: { ns: dnsRecon?.ns || [], ips },
          rawHeadersByHost: easmResults.reconData.rawHeadersByHost ?? {},
          htmlByHost: easmResults.reconData.htmlByHost ?? {},
          verifiedAt: new Date().toISOString(),
        },
      });
    }
  }

  if (osintResults) {
    const emailSec = osintResults.reconData.emailSecurity;
    if (emailSec) {
      const spf = emailSec.spf;
      const dmarc = emailSec.dmarc;
      const dkim = emailSec.dkim;
      const cloudProviders = emailSec.cloudProviders ?? [];
      const spfGrade = !spf?.found ? "F" : (spf.issues?.length ?? 0) === 0 ? "A" : spf.record?.includes("+all") ? "D" : "B";
      const dmarcGrade = !dmarc?.found ? "F" : (dmarc.issues?.length ?? 0) === 0 ? "A" : dmarc.record?.includes("p=none") ? "C" : "B";
      const dkimGrade = dkim?.found ? "A" : "N/A";
      const gradeNum = (g: string) => ({ A: 4, B: 3, C: 2, D: 1, F: 0 }[g] ?? 0);
      const overallNum = dkimGrade === "N/A"
        ? (gradeNum(spfGrade) + gradeNum(dmarcGrade)) / 2
        : (gradeNum(spfGrade) + gradeNum(dmarcGrade) + gradeNum(dkimGrade)) / 3;
      const overallGrade = overallNum >= 3.5 ? "A" : overallNum >= 2.5 ? "B" : overallNum >= 1.5 ? "C" : overallNum >= 0.5 ? "D" : "F";
      modules.push({
        moduleType: "cloud_footprint",
        confidence: 90,
        data: {
          source: "DNS MX/TXT record analysis",
          grades: { spf: spfGrade, dmarc: dmarcGrade, dkim: dkimGrade, overall: overallGrade },
          emailSecurity: {
            spf: spf ? { status: spf.found && (spf.issues?.length ?? 0) === 0 ? "pass" : spf.found ? "fail" : "none", record: spf.record || "", issue: (spf.issues?.length ? spf.issues.join("; ") : undefined) } : undefined,
            dmarc: dmarc ? { status: dmarc.found && (dmarc.issues?.length ?? 0) === 0 ? "pass" : dmarc.found ? "fail" : "none", record: dmarc.record || "", issue: (dmarc.issues?.length ? dmarc.issues.join("; ") : undefined) } : undefined,
            dkim: dkim ? { status: dkim.found ? "pass" : "none", selector: dkim.selector, record: dkim.record } : undefined,
            mx: emailSec.mx,
          },
          cloudProviders,
          verifiedAt: new Date().toISOString(),
        },
      });
    }

    const pathChecks = osintResults.reconData.pathChecks;
    const rawDirBrute = osintResults.reconData.directoryBruteforce;
    const directoryBruteforce = rawDirBrute
      ? {
          ...rawDirBrute,
          hits: (rawDirBrute.hits || []).map((h) => ({
            ...h,
            evidenceUrl: `https://${domain}${h.path}`,
          })),
        }
      : null;
    if (pathChecks || directoryBruteforce) {
      const now = new Date().toISOString();
      const publicFiles = pathChecks ? Object.entries(pathChecks).map(([path, v]) => ({
        path,
        type: path.replace(/^\//, "").replace(/\//g, " ") || "path",
        severity: v.severity ?? (v.accessible ? "low" : "info"),
        responseType: v.responseType ?? "other",
        validated: v.validated,
        confidence: v.confidence,
        redirectTarget: v.redirectTarget,
        firstSeen: now,
        evidenceUrl: `https://${domain}${path}`,
      })) : [];
      modules.push({
        moduleType: "exposed_content",
        confidence: 95,
        data: {
          source: "HTTP path probing + directory bruteforce",
          pathChecks: pathChecks || {},
          publicFiles,
          directoryBruteforce,
          verifiedAt: now,
        },
      });
    }

    if (osintResults.reconData.dnsRecords) {
      modules.push({
        moduleType: "dns_overview",
        confidence: 95,
        data: {
          source: "DNS resolution",
          dnsRecords: osintResults.reconData.dnsRecords,
          dnssec: osintResults.reconData.dnssec,
          verifiedAt: new Date().toISOString(),
        },
      });
    }
    if (osintResults.reconData.redirectChain && osintResults.reconData.redirectChain.length > 0) {
      modules.push({
        moduleType: "redirect_chain",
        confidence: 95,
        data: {
          source: "HTTP redirect chain",
          redirectChain: osintResults.reconData.redirectChain,
          verifiedAt: new Date().toISOString(),
        },
      });
    }
    if (osintResults.reconData.domainInfo && Object.keys(osintResults.reconData.domainInfo).length > 0) {
      modules.push({
        moduleType: "domain_info",
        confidence: 90,
        data: {
          source: "WHOIS lookup",
          domainInfo: osintResults.reconData.domainInfo,
          verifiedAt: new Date().toISOString(),
        },
      });
    }
    const techStack = osintResults.reconData.techStack;
    if (techStack && techStack.length > 0) {
      const frontendKeywords = /react|vue|angular|jquery|bootstrap|tailwind|next\.js|nuxt|svelte|gatsby|vite|webpack/i;
      const backendKeywords = /django|laravel|express|wordpress|drupal|joomla|asp\.net|php|ruby|rails/i;
      const frontend = techStack.filter((t) => frontendKeywords.test(t.name)).map((t) => ({ name: t.name, source: t.source, confidence: 85 }));
      const backend = techStack.filter((t) => backendKeywords.test(t.name) || !frontendKeywords.test(t.name)).map((t) => ({ name: t.name, source: t.source, confidence: 85 }));
      if (frontend.length > 0 || backend.length > 0) {
        modules.push({
          moduleType: "tech_stack",
          confidence: 90,
          data: {
            source: "HTTP headers + HTML analysis",
            frontend,
            backend,
            totalTechnologies: techStack.length,
            thirdParty: [],
            riskFlags: [],
            verifiedAt: new Date().toISOString(),
          },
        });
      }
    }
    const w = osintResults.reconData;
    if (w.serverLocation || w.cookies || w.responseHeaders || w.securityTxt || w.sitemapUrls || w.robotsTxt || (w.techStack && w.techStack.length) || (w.socialTags && Object.keys(w.socialTags).length) || (w.openPorts && w.openPorts.length) || w.dnssec) {
      modules.push({
        moduleType: "website_overview",
        confidence: 90,
        data: {
          source: "HTTP + path probes",
          serverLocation: w.serverLocation,
          cookies: w.cookies || [],
          responseHeaders: w.responseHeaders || {},
          securityTxt: w.securityTxt,
          sitemapUrls: w.sitemapUrls || [],
          robotsTxt: w.robotsTxt,
          techStack: w.techStack || [],
          socialTags: w.socialTags || {},
          openPorts: w.openPorts || [],
          dnssec: w.dnssec,
          verifiedAt: new Date().toISOString(),
        },
      });
    }
  }

  // Phase 2: Advanced detection recon modules
  const easm = easmResults?.reconData;
  const osint = osintResults?.reconData;

  if (easm?.subdomainTakeover && easm.subdomainTakeover.length > 0) {
    modules.push({
      moduleType: "subdomain_takeover",
      data: {
        takeoverResults: easm.subdomainTakeover,
        checkedCount: easmResults?.subdomains.length ?? 0,
        vulnerableCount: easm.subdomainTakeover.length,
        verifiedAt: new Date().toISOString(),
      },
      confidence: 85,
    });
  }

  if (osint?.apiDiscovery && osint.apiDiscovery.endpoints.length > 0) {
    modules.push({
      moduleType: "api_discovery",
      data: {
        endpoints: osint.apiDiscovery.endpoints,
        openApiSpec: osint.apiDiscovery.openApiSpec,
        endpointCount: osint.apiDiscovery.endpoints.length,
        verifiedAt: new Date().toISOString(),
      },
      confidence: 80,
    });
  }

  if (osint?.secretExposure && (osint.secretExposure.matchCount > 0 || osint.secretExposure.leakyPaths.length > 0)) {
    modules.push({
      moduleType: "secret_exposure",
      data: {
        matchCount: osint.secretExposure.matchCount,
        leakyPaths: osint.secretExposure.leakyPaths,
        patternTypes: osint.secretExposure.patternTypes,
        verifiedAt: new Date().toISOString(),
      },
      confidence: 90,
    });
  }

  return modules;
}
