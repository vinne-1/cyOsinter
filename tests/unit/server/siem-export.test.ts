/**
 * Unit tests for server/siem-export.ts.
 *
 * Two properties matter more than the formatting itself. First, escaping: a
 * finding title is attacker-influenced text (it names a host, a cookie, a path),
 * and CEF is pipe-delimited — an unescaped pipe does not merely look wrong, it
 * splits the event into fields that were never sent, which is log injection.
 * Second, fail-soft: a SIEM outage must never throw into the emitter that is
 * storing a finding.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("../../../server/logger.js", () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));

import {
  toEcs,
  toCef,
  toSyslogRfc5424,
  escapeCefHeader,
  escapeCefExtension,
  parseEndpoint,
  readSiemConfig,
  formatEvent,
  sendToSiem,
  siemStats,
  resetSiemStats,
  type SiemEvent,
} from "../../../server/siem-export";

const event: SiemEvent = {
  type: "new_critical_finding",
  title: "Exposed Environment File (.env)",
  message: "The .env file is publicly accessible",
  severity: "critical",
  workspaceId: "ws-1",
  findingId: "f-1",
  scanId: "s-1",
  category: "data_leak",
  affectedAsset: "api.example.com",
  timestamp: new Date("2026-03-04T05:06:07.000Z"),
};

beforeEach(() => resetSiemStats());
afterEach(() => vi.unstubAllGlobals());

describe("readSiemConfig", () => {
  it("is disabled when no endpoint is configured", () => {
    expect(readSiemConfig({} as NodeJS.ProcessEnv).enabled).toBe(false);
  });

  it("defaults to ECS and accepts CEF", () => {
    expect(readSiemConfig({ SIEM_ENDPOINT: "https://x" } as NodeJS.ProcessEnv).format).toBe("ecs");
    expect(readSiemConfig({ SIEM_ENDPOINT: "https://x", SIEM_FORMAT: "CEF" } as NodeJS.ProcessEnv).format).toBe("cef");
    // An unknown format falls back rather than sending something no parser reads.
    expect(readSiemConfig({ SIEM_ENDPOINT: "https://x", SIEM_FORMAT: "xml" } as NodeJS.ProcessEnv).format).toBe("ecs");
  });
});

describe("CEF escaping", () => {
  /**
   * The injection case. A title containing a pipe would otherwise terminate the
   * header early and fabricate fields.
   */
  it("escapes pipes, backslashes and newlines in the header", () => {
    expect(escapeCefHeader("a|b")).toBe("a\\|b");
    expect(escapeCefHeader("a\\b")).toBe("a\\\\b");
    expect(escapeCefHeader("a\nb")).toBe("a b");
  });

  it("escapes equals signs in the extension, where they delimit key=value", () => {
    expect(escapeCefExtension("k=v")).toBe("k\\=v");
  });

  it("produces a header with exactly the seven CEF fields", () => {
    const line = toCef({ ...event, title: "Pipe | in | title" });
    const header = line.split("|cs1Label")[0];
    // CEF:0|vendor|product|version|signature|name|severity — the escaped pipes
    // in the name must not add fields.
    const unescaped = header.split(/(?<!\\)\|/);
    expect(unescaped[0]).toBe("CEF:0");
    expect(unescaped[1]).toBe("Cyshield");
    expect(unescaped[6]).toBe("10"); // critical
  });
});

describe("toCef", () => {
  it("carries the identifiers a responder needs to pivot back", () => {
    const line = toCef(event);
    expect(line).toContain("cs1=ws-1");
    expect(line).toContain("cs2=f-1");
    expect(line).toContain("cs3=s-1");
    expect(line).toContain("dhost=api.example.com");
    expect(line).toContain("cat=data_leak");
  });

  it("omits fields that have no value rather than sending empty ones", () => {
    const line = toCef({ type: "t", title: "x", message: "m", severity: "low", workspaceId: "ws" });
    expect(line).not.toContain("cs2=");
    expect(line).not.toContain("dhost=");
  });

  it("maps severity onto the CEF 0-10 scale", () => {
    expect(toCef({ ...event, severity: "critical" })).toContain("|10|");
    expect(toCef({ ...event, severity: "info" })).toContain("|1|");
  });
});

describe("toEcs", () => {
  it("emits the ECS fields an Elastic pipeline indexes on", () => {
    const doc = toEcs(event) as Record<string, any>;
    expect(doc["@timestamp"]).toBe("2026-03-04T05:06:07.000Z");
    expect(doc.event.action).toBe("new_critical_finding");
    expect(doc.event.kind).toBe("alert");
    expect(doc.event.severity).toBe(99);
    expect(doc.host.name).toBe("api.example.com");
    expect(doc.cyshield.finding_id).toBe("f-1");
  });

  it("is valid JSON once serialised, whatever the title contains", () => {
    const s = formatEvent({ ...event, title: 'quote " and \\ backslash' }, "ecs");
    expect(() => JSON.parse(s)).not.toThrow();
  });
});

describe("toSyslogRfc5424", () => {
  it("uses the log-audit facility and maps severity to the syslog scale", () => {
    // facility 13 * 8 + severity 2 (critical) = 106
    expect(toSyslogRfc5424("payload", "critical", "host")).toMatch(/^<106>1 /);
    // 13 * 8 + 6 (info) = 110
    expect(toSyslogRfc5424("payload", "info", "host")).toMatch(/^<110>1 /);
  });
});

describe("parseEndpoint", () => {
  it("recognises HTTP collectors and both syslog transports", () => {
    expect(parseEndpoint("https://splunk.internal:8088/services/collector")?.kind).toBe("http");
    expect(parseEndpoint("syslog+udp://siem.internal:514")).toEqual({ kind: "udp", host: "siem.internal", port: 514 });
    expect(parseEndpoint("syslog+tcp://siem.internal")).toEqual({ kind: "tcp", host: "siem.internal", port: 514 });
  });

  it("returns null for an unusable endpoint so a typo disables egress visibly", () => {
    expect(parseEndpoint("not-a-url")).toBeNull();
    expect(parseEndpoint("ftp://siem")).toBeNull();
  });
});

describe("sendToSiem", () => {
  it("does nothing when no SIEM is configured", async () => {
    const ok = await sendToSiem(event, { endpoint: "", format: "ecs", enabled: false });
    expect(ok).toBe(false);
    expect(siemStats()).toEqual({ delivered: 0, failed: 0 });
  });

  it("posts to an HTTP collector with the right content type", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal("fetch", fetchMock);

    const ok = await sendToSiem(event, { endpoint: "https://siem.internal/collector", format: "cef", enabled: true, token: "abc" });

    expect(ok).toBe(true);
    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers["content-type"]).toBe("text/plain");
    expect(init.headers.authorization).toBe("Bearer abc");
    expect(String(init.body)).toContain("CEF:0|Cyshield");
    expect(siemStats().delivered).toBe(1);
  });

  it("passes a pre-formed auth scheme through untouched, for Splunk HEC", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal("fetch", fetchMock);
    await sendToSiem(event, { endpoint: "https://hec/x", format: "ecs", enabled: true, token: "Splunk 1234" });
    expect(fetchMock.mock.calls[0][1].headers.authorization).toBe("Splunk 1234");
  });

  /**
   * The property that matters most: this runs inside the path that stores a
   * finding. A SIEM being down must degrade to a log line, never an exception.
   */
  it("never throws when the collector fails, and counts the failure", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("ECONNREFUSED")));
    await expect(sendToSiem(event, { endpoint: "https://siem/x", format: "ecs", enabled: true })).resolves.toBe(false);
    expect(siemStats().failed).toBe(1);
  });

  it("treats a non-2xx collector response as a failure, not a success", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 503 }));
    await expect(sendToSiem(event, { endpoint: "https://siem/x", format: "ecs", enabled: true })).resolves.toBe(false);
    expect(siemStats().failed).toBe(1);
  });

  it("disables egress on an unparseable endpoint instead of throwing", async () => {
    await expect(sendToSiem(event, { endpoint: "gopher://siem", format: "ecs", enabled: true })).resolves.toBe(false);
    expect(siemStats()).toEqual({ delivered: 0, failed: 0 });
  });
});
