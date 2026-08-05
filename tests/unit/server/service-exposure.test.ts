/**
 * Unit tests for server/scanner/service-exposure.ts — DB-exposure elevation and
 * banner version advisories.
 */
import { describe, it, expect } from "vitest";
import { assessServiceExposure } from "../../../server/scanner/service-exposure";

describe("assessServiceExposure — database exposure", () => {
  it("flags an Internet-exposed MySQL port as HIGH", () => {
    const f = assessServiceExposure("1.2.3.4", [{ port: 3306, service: "mysql", banner: "5.7.23-log" }]);
    const db = f.find((x) => x.category === "network_exposure");
    expect(db).toBeTruthy();
    expect(db!.severity).toBe("high");
    expect(db!.cvssScore).toBe("7.5");
    expect(db!.affectedAsset).toBe("1.2.3.4:3306");
    expect(db!.title).toMatch(/MySQL/);
    expect(db!.evidence[0].snippet).toContain("5.7.23");
  });

  it("flags each known DB port (Postgres, Redis, Mongo, MSSQL, Elastic)", () => {
    for (const [port, needle] of [[5432, "PostgreSQL"], [6379, "Redis"], [27017, "MongoDB"], [1433, "SQL Server"], [9200, "Elasticsearch"]] as const) {
      const f = assessServiceExposure("10.0.0.1", [{ port }]);
      expect(f.some((x) => x.severity === "high" && x.title.includes(needle))).toBe(true);
    }
  });

  it("does NOT flag ordinary web/mail ports as DB exposure", () => {
    const f = assessServiceExposure("1.2.3.4", [
      { port: 80, service: "http" },
      { port: 443, service: "https" },
      { port: 25, service: "smtp" },
    ]);
    expect(f.filter((x) => x.category === "network_exposure")).toHaveLength(0);
  });

  it("handles a DB port with no banner (still HIGH, no banner text)", () => {
    const f = assessServiceExposure("1.2.3.4", [{ port: 6379 }]);
    expect(f[0].severity).toBe("high");
    expect(f[0].description).not.toMatch(/returns a service banner/);
  });
});

describe("assessServiceExposure — banner advisories", () => {
  it("flags OpenSSH < 8.0 as outdated (medium)", () => {
    const f = assessServiceExposure("1.2.3.4", [{ port: 22, banner: "SSH-2.0-OpenSSH_7.4" }]);
    const ssh = f.find((x) => x.category === "outdated_software");
    expect(ssh).toBeTruthy();
    expect(ssh!.severity).toBe("medium");
    expect(ssh!.title).toMatch(/OpenSSH 7\.4/);
  });

  it("does NOT flag OpenSSH >= 8.0", () => {
    const f = assessServiceExposure("1.2.3.4", [{ port: 22, banner: "SSH-2.0-OpenSSH_9.6" }]);
    expect(f.some((x) => x.category === "outdated_software")).toBe(false);
  });

  it("returns nothing for an empty port list", () => {
    expect(assessServiceExposure("1.2.3.4", [])).toEqual([]);
  });
});
