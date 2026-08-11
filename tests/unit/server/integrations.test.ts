/**
 * Unit tests for the Shodan integration wiring in server/api-integrations.ts —
 * status reporting, key resolution, and the fail-soft host lookup.
 */
import { describe, it, expect, afterEach } from "vitest";
import { getIntegrationsStatus, getShodanKey, shodanHostLookup } from "../../../server/api-integrations";

describe("Shodan integration", () => {
  afterEach(() => { delete process.env.SHODAN_API_KEY; });

  it("getIntegrationsStatus exposes a shodan.configured flag", () => {
    const s = getIntegrationsStatus();
    expect(s).toHaveProperty("shodan");
    expect(typeof s.shodan.configured).toBe("boolean");
  });

  it("getShodanKey reads the environment variable", () => {
    process.env.SHODAN_API_KEY = "test-shodan-key";
    expect(getShodanKey()).toBe("test-shodan-key");
  });

  it("shodanHostLookup returns null without a configured key (fail-soft, no request)", async () => {
    delete process.env.SHODAN_API_KEY;
    expect(await shodanHostLookup("8.8.8.8")).toBeNull();
  });

  it("shodanHostLookup returns null for private IPs even with a key", async () => {
    process.env.SHODAN_API_KEY = "test-shodan-key";
    expect(await shodanHostLookup("10.0.0.1")).toBeNull();
  });
});
