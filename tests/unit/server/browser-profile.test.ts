import { describe, it, expect } from "vitest";
import {
  BROWSER_PROFILES,
  DEFAULT_PROFILE,
  mergeHeaders,
  profileById,
  subResourceHeaders,
} from "../../../server/scanner/browser-profile";

/**
 * These tests encode ONE rule: a profile must be internally coherent. A
 * mismatched identity (Firefox UA carrying Chrome's client hints, a Chrome UA
 * with no `sec-ch-ua` at all) is a stronger detection signal than sending
 * nothing, so incoherence is the specific failure worth guarding.
 */

describe("browser profiles are internally coherent", () => {
  it.each(BROWSER_PROFILES.map((p) => [p.id, p] as const))(
    "%s: user-agent header matches the profile's userAgent",
    (_id, profile) => {
      expect(profile.headers["user-agent"]).toBe(profile.userAgent);
    },
  );

  it.each(BROWSER_PROFILES.filter((p) => p.engine === "chrome").map((p) => [p.id, p] as const))(
    "%s: Chrome sends client hints that agree with its UA version",
    (_id, profile) => {
      const major = profile.userAgent.match(/Chrome\/(\d+)/)?.[1];
      expect(major).toBeTruthy();
      expect(profile.headers["sec-ch-ua"]).toContain(`"Google Chrome";v="${major}"`);
      // The GREASE brand is not optional — Chrome always injects one, so its
      // absence is itself a fingerprint.
      expect(profile.headers["sec-ch-ua"]).toContain("Not-A.Brand");
      expect(profile.headers["sec-ch-ua-mobile"]).toBe("?0");
      expect(profile.headers["sec-ch-ua-platform"]).toBeTruthy();
    },
  );

  it.each(BROWSER_PROFILES.filter((p) => p.engine === "chrome").map((p) => [p.id, p] as const))(
    "%s: Chrome's sec-ch-ua-platform agrees with the UA's OS token",
    (_id, profile) => {
      const platform = profile.headers["sec-ch-ua-platform"];
      if (profile.platform === "windows") {
        expect(profile.userAgent).toContain("Windows NT");
        expect(platform).toBe('"Windows"');
      } else if (profile.platform === "macos") {
        expect(profile.userAgent).toContain("Mac OS X");
        expect(platform).toBe('"macOS"');
      } else {
        expect(profile.userAgent).toContain("Linux");
        expect(platform).toBe('"Linux"');
      }
    },
  );

  it.each(BROWSER_PROFILES.filter((p) => p.engine !== "chrome").map((p) => [p.id, p] as const))(
    "%s: non-Chromium browsers send NO client hints",
    (_id, profile) => {
      // Client hints are a Chromium feature. A Firefox UA carrying sec-ch-ua is
      // an immediate contradiction.
      for (const key of Object.keys(profile.headers)) {
        expect(key.startsWith("sec-ch-ua")).toBe(false);
      }
    },
  );

  it("Safari is only ever claimed on macOS", () => {
    for (const p of BROWSER_PROFILES.filter((x) => x.engine === "safari")) {
      expect(p.platform).toBe("macos");
      expect(p.userAgent).toContain("Macintosh");
    }
  });

  it("every profile sends an Accept and Accept-Language", () => {
    for (const p of BROWSER_PROFILES) {
      expect(p.headers.accept).toBeTruthy();
      expect(p.headers["accept-language"]).toBeTruthy();
    }
  });

  it("Chrome and Firefox send distinguishable Accept strings", () => {
    const chrome = BROWSER_PROFILES.find((p) => p.engine === "chrome")!;
    const firefox = BROWSER_PROFILES.find((p) => p.engine === "firefox")!;
    // Chrome's Accept carries signed-exchange; Firefox's never has.
    expect(chrome.headers.accept).toContain("application/signed-exchange");
    expect(firefox.headers.accept).not.toContain("application/signed-exchange");
  });

  it("header names are all lowercase, so overrides can be matched reliably", () => {
    for (const p of BROWSER_PROFILES) {
      for (const key of Object.keys(p.headers)) {
        expect(key).toBe(key.toLowerCase());
      }
    }
  });

  it("profile ids are unique", () => {
    const ids = BROWSER_PROFILES.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("exposes the default profile and lookup by id", () => {
    expect(DEFAULT_PROFILE.engine).toBe("chrome");
    expect(profileById(DEFAULT_PROFILE.id)).toBe(DEFAULT_PROFILE);
    expect(profileById("no-such-profile")).toBeUndefined();
  });
});

describe("subResourceHeaders", () => {
  const chrome = BROWSER_PROFILES.find((p) => p.engine === "chrome")!;

  it("switches Sec-Fetch-* from a navigation to a fetch", () => {
    const h = subResourceHeaders(chrome);
    // `Sec-Fetch-Dest: document` on a JSON endpoint is incoherent — a browser
    // only sends that for a top-level navigation.
    expect(h["sec-fetch-dest"]).toBe("empty");
    expect(h["sec-fetch-mode"]).toBe("cors");
    expect(h["sec-fetch-site"]).toBe("same-origin");
  });

  it("drops navigation-only headers", () => {
    const h = subResourceHeaders(chrome);
    expect(h["sec-fetch-user"]).toBeUndefined();
    expect(h["upgrade-insecure-requests"]).toBeUndefined();
  });

  it("asks for JSON rather than HTML", () => {
    expect(subResourceHeaders(chrome).accept).toContain("application/json");
  });

  it("keeps the identity headers intact", () => {
    const h = subResourceHeaders(chrome);
    expect(h["user-agent"]).toBe(chrome.userAgent);
    expect(h["sec-ch-ua"]).toBe(chrome.headers["sec-ch-ua"]);
  });

  it("does not mutate the source profile", () => {
    const before = { ...chrome.headers };
    subResourceHeaders(chrome);
    expect(chrome.headers).toEqual(before);
  });
});

describe("mergeHeaders", () => {
  const base = { "user-agent": "profile-ua", accept: "text/html", "sec-ch-ua": "hints" };

  it("returns the profile headers when there are no overrides", () => {
    expect(mergeHeaders(base)).toEqual(base);
  });

  it("lets a caller override a header", () => {
    expect(mergeHeaders(base, { accept: "application/json" }).accept).toBe("application/json");
  });

  it("matches overrides case-insensitively, never duplicating a header", () => {
    // Sending both `User-Agent` and `user-agent` with different values is a far
    // louder signal than either header alone.
    const merged = mergeHeaders(base, { "User-Agent": "caller-ua" });
    const uaKeys = Object.keys(merged).filter((k) => k.toLowerCase() === "user-agent");
    expect(uaKeys).toHaveLength(1);
    expect(merged[uaKeys[0]!]).toBe("caller-ua");
  });

  it("accepts a Headers instance", () => {
    const merged = mergeHeaders(base, new Headers({ "User-Agent": "from-headers" }));
    expect(merged["user-agent"]).toBe("from-headers");
    expect(Object.keys(merged).filter((k) => k.toLowerCase() === "user-agent")).toHaveLength(1);
  });

  it("accepts an array of tuples", () => {
    const merged = mergeHeaders(base, [["Accept", "text/plain"]]);
    expect(merged.accept).toBe("text/plain");
  });

  it("does not mutate the source headers", () => {
    const before = { ...base };
    mergeHeaders(base, { accept: "changed" });
    expect(base).toEqual(before);
  });

  it("keeps profile headers the caller did not override", () => {
    const merged = mergeHeaders(base, { accept: "application/json" });
    expect(merged["sec-ch-ua"]).toBe("hints");
    expect(merged["user-agent"]).toBe("profile-ua");
  });
});
