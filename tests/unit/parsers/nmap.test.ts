import { describe, it, expect } from "vitest";
import { parseNmap, nmapToTextSummary } from "../../../server/parsers/nmap";

describe("parseNmap — normal text format", () => {
  it("parses a basic nmap text output", () => {
    const input = `
Nmap scan report for example.com (93.184.216.34)
PORT     STATE SERVICE
80/tcp   open  http
443/tcp  open  https
22/tcp   closed ssh
`;
    const result = parseNmap(input, "nmap");
    expect(result.hosts).toHaveLength(1);
    expect(result.hosts[0].address).toBe("93.184.216.34");
    expect(result.hosts[0].hostname).toBe("example.com");
    expect(result.hosts[0].ports).toHaveLength(3);
    expect(result.hosts[0].ports[0]).toEqual({ port: 80, protocol: "tcp", state: "open", service: "http" });
    expect(result.hosts[0].ports[1]).toEqual({ port: 443, protocol: "tcp", state: "open", service: "https" });
    expect(result.hosts[0].ports[2]).toEqual({ port: 22, protocol: "tcp", state: "closed", service: "ssh" });
  });

  it("parses multiple hosts", () => {
    const input = `
Nmap scan report for host1.com (10.0.0.1)
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for host2.com (10.0.0.2)
PORT    STATE SERVICE
443/tcp open  https
`;
    const result = parseNmap(input, "nmap");
    expect(result.hosts).toHaveLength(2);
    expect(result.hosts[0].address).toBe("10.0.0.1");
    expect(result.hosts[1].address).toBe("10.0.0.2");
  });

  it("parses IP-only report (no hostname)", () => {
    const input = `
Nmap scan report for 192.168.1.1
PORT   STATE SERVICE
22/tcp open  ssh
`;
    const result = parseNmap(input, "nmap");
    expect(result.hosts).toHaveLength(1);
    expect(result.hosts[0].address).toBe("192.168.1.1");
    expect(result.hosts[0].hostname).toBeUndefined();
  });

  it("returns empty hosts for empty input", () => {
    expect(parseNmap("", "nmap").hosts).toEqual([]);
  });
});

describe("parseNmap — XML format", () => {
  it("parses nmap XML output", () => {
    const xml = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <hostnames>
      <hostname name="example.com" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>`;
    const result = parseNmap(xml, "nmap");
    expect(result.hosts).toHaveLength(1);
    expect(result.hosts[0].address).toBe("93.184.216.34");
    expect(result.hosts[0].hostname).toBe("example.com");
    expect(result.hosts[0].ports).toHaveLength(2);
    expect(result.hosts[0].ports[0]).toMatchObject({ port: 80, protocol: "tcp", state: "open", service: "http", version: "nginx" });
  });

  it("handles malformed XML gracefully", () => {
    const result = parseNmap("<not valid xml!!!", "nmap");
    expect(result.hosts).toEqual([]);
  });
});

describe("parseNmap — generic/nikto types", () => {
  it("returns rawSummary for non-nmap types", () => {
    const input = "Some generic scan output";
    const result = parseNmap(input, "nikto");
    expect(result.hosts).toEqual([]);
    expect(result.rawSummary).toBe("Some generic scan output");
  });

  it("truncates rawSummary to 5000 chars", () => {
    const longInput = "x".repeat(10000);
    const result = parseNmap(longInput, "generic");
    expect(result.rawSummary?.length).toBe(5000);
  });
});

describe("nmapToTextSummary", () => {
  it("produces readable text from parsed hosts", () => {
    const parsed = {
      hosts: [{
        address: "10.0.0.1",
        hostname: "host.example.com",
        ports: [
          { port: 80, protocol: "tcp", state: "open", service: "http" },
          { port: 22, protocol: "tcp", state: "open", service: "ssh", version: "OpenSSH" },
        ],
      }],
    };
    const text = nmapToTextSummary(parsed);
    expect(text).toContain("Host: host.example.com (10.0.0.1)");
    expect(text).toContain("80/tcp open http");
    expect(text).toContain("22/tcp open ssh OpenSSH");
  });

  it("handles host without hostname", () => {
    const parsed = {
      hosts: [{ address: "10.0.0.1", ports: [] }],
    };
    const text = nmapToTextSummary(parsed);
    expect(text).toContain("Host: 10.0.0.1 (10.0.0.1)");
  });
});
