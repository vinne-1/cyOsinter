/**
 * TLS protocol version enumeration.
 *
 * `getCertificateInfo` reported `socket.getProtocol()` — the version the client
 * and server NEGOTIATED, which is the best one they both support. A server that
 * still accepts TLS 1.0 alongside 1.3 negotiates 1.3 with a modern scanner and
 * reports as perfectly healthy, while remaining vulnerable to downgrade attacks
 * and failing PCI DSS, which has forbidden TLS 1.0/1.1 since 2018. RFC 8996
 * deprecated both outright in 2021.
 *
 * Finding that out requires asking each version separately, which is what this
 * does.
 *
 * ── The trap this module exists to avoid ────────────────────────────────────
 * A naive probe pins `minVersion`/`maxVersion` and calls a failure "not
 * supported". Measured on Node 24 / OpenSSL 3.5, that is wrong: at the default
 * security level OpenSSL refuses to OFFER TLS 1.0 or 1.1 at all, and the
 * connection fails with ERR_SSL_NO_PROTOCOLS_AVAILABLE before a single byte
 * reaches the server. Every host on the internet would be reported as safely
 * refusing TLS 1.0 — a false negative on the exact thing the check exists to
 * find.
 *
 * `ciphers: "DEFAULT@SECLEVEL=0"` is therefore mandatory, and
 * ERR_SSL_NO_PROTOCOLS_AVAILABLE is treated as "this scanner could not ask",
 * never as "the server said no".
 *
 * Verified against badssl.com's single-version endpoints, which is the only way
 * to know the probe discriminates rather than merely returning plausible
 * answers: tls-v1-0.badssl.com:1010 accepted only TLS 1.0, tls-v1-1:1011 only
 * TLS 1.1, tls-v1-2:1012 only TLS 1.2.
 *
 * NOTE for anyone verifying this by hand: a TLS-intercepting proxy (corporate
 * middlebox, endpoint security product) terminates port 443 locally and will
 * answer for protocol versions the real server has long since disabled. If
 * every host on a network appears to accept TLS 1.0, suspect the network before
 * the hosts.
 */

import tls from "node:tls";
import type { VerifiedFinding } from "./constants.js";

export type TlsVersion = "TLSv1" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3";

/** Ordered oldest to newest. */
export const TLS_VERSIONS: readonly TlsVersion[] = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"];

/** Versions deprecated by RFC 8996 and forbidden by PCI DSS. */
export const OBSOLETE_VERSIONS: readonly TlsVersion[] = ["TLSv1", "TLSv1.1"];

export interface TlsVersionResult {
  version: TlsVersion;
  /** The server completed a handshake at this version. */
  supported: boolean;
  /**
   * True when the probe could not be made at all — the local TLS stack refused
   * to offer the version, or the host was unreachable. Distinct from
   * `supported: false`, which means the server actively declined.
   */
  indeterminate: boolean;
  cipher?: string;
  error?: string;
}

export interface TlsProtocolReport {
  host: string;
  port: number;
  results: TlsVersionResult[];
  /** Obsolete versions the server accepted. */
  obsoleteAccepted: TlsVersion[];
  /** Modern versions the server accepted. */
  modernAccepted: TlsVersion[];
  /** Nothing could be determined — do not report anything about this host. */
  unreachable: boolean;
}

/** Errors that mean "our own client could not ask", not "the server refused". */
const CLIENT_LIMITATION = /NO_PROTOCOLS_AVAILABLE|UNSUPPORTED_PROTOCOL_VERSION|no protocols available/i;

/** Errors that mean the host itself is not answering. */
const UNREACHABLE = /ENOTFOUND|ECONNREFUSED|EHOSTUNREACH|ENETUNREACH|EAI_AGAIN|timeout/i;

/** Attempts a handshake pinned to exactly one TLS version. */
export function probeTlsVersion(
  host: string,
  port: number,
  version: TlsVersion,
  timeoutMs = 8000,
): Promise<TlsVersionResult> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (r: Omit<TlsVersionResult, "version">) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        socket.destroy();
      } catch {
        /* already gone */
      }
      resolve({ version, ...r });
    };

    const timer = setTimeout(() => done({ supported: false, indeterminate: true, error: "timeout" }), timeoutMs);

    let socket: tls.TLSSocket;
    try {
      socket = tls.connect(
        {
          host,
          port,
          servername: host,
          // The certificate is checked elsewhere; here the question is only
          // which protocol versions the server will speak, and an expired or
          // self-signed certificate must not mask that answer.
          rejectUnauthorized: false,
          minVersion: version,
          maxVersion: version,
          // Without SECLEVEL=0, OpenSSL 3 will not offer TLS 1.0/1.1 at all and
          // every server looks like it refuses them. See the module comment.
          ciphers: "DEFAULT@SECLEVEL=0",
        },
        () => {
          const cipher = socket.getCipher?.()?.name;
          // Trust the negotiated protocol over the requested one: if a server
          // somehow answers at a different version, record what actually
          // happened rather than what was asked for.
          const negotiated = socket.getProtocol();
          done({ supported: negotiated === version, indeterminate: false, cipher });
        },
      );
    } catch (err) {
      done({ supported: false, indeterminate: true, error: err instanceof Error ? err.message : String(err) });
      return;
    }

    socket.on("error", (err: NodeJS.ErrnoException) => {
      const code = err.code ?? err.message ?? "";
      done({
        supported: false,
        // A client-side limitation or an unreachable host is not the server
        // declining. Conflating them produces a confident wrong answer.
        indeterminate: CLIENT_LIMITATION.test(code) || UNREACHABLE.test(code),
        error: code.slice(0, 60),
      });
    });
  });
}

/** Enumerates every TLS version a host will speak. */
export async function enumerateTlsVersions(
  host: string,
  port = 443,
  probe = probeTlsVersion,
): Promise<TlsProtocolReport> {
  // Sequential: four handshakes to one host, and opening them at once is both
  // rude and more likely to trip a rate limiter into refusing some of them,
  // which would read as "version not supported".
  const results: TlsVersionResult[] = [];
  for (const version of TLS_VERSIONS) {
    results.push(await probe(host, port, version));
  }

  const supported = results.filter((r) => r.supported).map((r) => r.version);
  return {
    host,
    port,
    results,
    obsoleteAccepted: supported.filter((v) => OBSOLETE_VERSIONS.includes(v)),
    modernAccepted: supported.filter((v) => !OBSOLETE_VERSIONS.includes(v)),
    // Every probe indeterminate means we learned nothing. Reporting "supports
    // no TLS versions" for a host that was simply unreachable would be worse
    // than saying nothing.
    unreachable: results.every((r) => r.indeterminate),
  };
}

/**
 * Findings for obsolete protocol support.
 *
 * Only obsolete versions are reported. A server that lacks TLS 1.3 is not
 * insecure, and flagging its absence would put a modernisation suggestion in a
 * list of security problems.
 */
export function buildTlsProtocolFindings(
  domain: string,
  report: TlsProtocolReport,
  now: string,
): VerifiedFinding[] {
  if (report.unreachable || report.obsoleteAccepted.length === 0) return [];

  const onlyObsolete = report.modernAccepted.length === 0;
  // "TLSv1" is the OpenSSL identifier, not how anyone writes or says it. Left
  // as-is the title read "accepts obsolete TLS TLSv1".
  const pretty = (v: TlsVersion) => v.replace(/^TLSv1$/, "1.0").replace(/^TLSv/, "");
  const versions = report.obsoleteAccepted.map(pretty).map((v) => `TLS ${v}`).join(" and ");

  return [
    {
      title: `${report.host} accepts obsolete TLS ${report.obsoleteAccepted.map(pretty).join("/")}`,
      description:
        `${report.host}:${report.port} completes a TLS handshake at ${versions}. ` +
        (onlyObsolete
          ? `It accepts no modern version at all, so every connection to this host is negotiated over a protocol that has been ` +
            `deprecated since 2021 and cannot be made safe.`
          : `It also supports TLS ${report.modernAccepted.map(pretty).join("/")}, so ordinary clients negotiate a modern version and the ` +
            `problem is invisible in normal use — but an attacker who can influence the handshake can force the connection ` +
            `down to TLS ${pretty(report.obsoleteAccepted[0])}, where the protocol's own weaknesses (CBC padding oracles, weak MACs, no ` +
            `modern cipher suites) become available.`) +
        ` RFC 8996 deprecated TLS 1.0 and 1.1 in 2021, and PCI DSS has prohibited them since June 2018, so this is also a ` +
        `compliance failure for anyone handling cardholder data.`,
      severity: onlyObsolete ? "high" : "medium",
      category: "ssl_issue",
      affectedAsset: report.host,
      cvssScore: onlyObsolete ? "7.4" : "5.9",
      remediation:
        `Disable TLS 1.0 and 1.1 on ${report.host}:${report.port} and require TLS 1.2 or better. Check client analytics ` +
        `before doing so if you support legacy devices — Android 4.4 and IE10 and earlier cannot negotiate TLS 1.2.`,
      evidence: [
        {
          type: "tls",
          description: "TLS version handshake probe",
          snippet: report.results
            .map(
              (r) =>
                `${r.version}: ${r.indeterminate ? "could not determine" : r.supported ? `accepted${r.cipher ? ` (${r.cipher})` : ""}` : "refused"}` +
                (r.error && !r.supported ? ` — ${r.error}` : ""),
            )
            .join("\n"),
          source: "Direct TLS handshake",
          verifiedAt: now,
        },
      ],
    },
  ];
}
