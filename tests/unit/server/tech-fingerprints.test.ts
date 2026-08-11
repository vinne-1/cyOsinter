/**
 * Unit tests for server/scanner/tech-fingerprints.ts — keyless technology +
 * third-party service fingerprinting from HTML, headers, and cookies.
 */
import { describe, it, expect } from "vitest";
import { detectTechnologies } from "../../../server/scanner/tech-fingerprints";

const names = (t: ReturnType<typeof detectTechnologies>) => t.map((x) => x.name);

describe("detectTechnologies", () => {
  it("detects frameworks and libraries from HTML + script src", () => {
    const html = `<html><head><script src="/_next/static/chunks/main.js"></script>
      <script id="__NEXT_DATA__">{}</script>
      <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script></head>
      <body data-reactroot></body></html>`;
    const got = names(detectTechnologies(html, {}, []));
    expect(got).toContain("Next.js");
    expect(got).toContain("React");
    expect(got).toContain("jQuery");
  });

  it("extracts a version where possible (jQuery, nginx)", () => {
    const html = `<script src="/js/jquery-3.6.0.min.js"></script>`;
    const jq = detectTechnologies(html, {}, []).find((t) => t.name === "jQuery");
    expect(jq?.version).toBe("3.6.0");
    const ng = detectTechnologies("", { server: "nginx/1.25.3" }, []).find((t) => t.name === "Nginx");
    expect(ng?.version).toBe("1.25.3");
  });

  it("detects backend/language from cookies", () => {
    const php = detectTechnologies("", {}, ["PHPSESSID=abc; path=/"]);
    expect(names(php)).toContain("PHP");
    const java = detectTechnologies("", {}, ["JSESSIONID=xyz"]);
    expect(names(java)).toContain("Java");
    const aspnet = detectTechnologies("", {}, ["ASP.NET_SessionId=q"]);
    expect(names(aspnet)).toContain("ASP.NET");
  });

  it("detects a CMS from HTML markers", () => {
    expect(names(detectTechnologies('<link href="/wp-content/themes/x/style.css">', {}, []))).toContain("WordPress");
    expect(names(detectTechnologies('<script src="//cdn.shopify.com/s/files/x.js"></script>', {}, []))).toContain("Shopify");
  });

  it("flags embedded third-party services as thirdParty", () => {
    const html = `<script src="https://www.googletagmanager.com/gtag/js?id=G-ABCDEFGH12"></script>
      <script src="https://js.stripe.com/v3/"></script>
      <script src="https://static.hotjar.com/c/hotjar.js"></script>
      <link href="https://fonts.googleapis.com/css2?family=Inter">`;
    const got = detectTechnologies(html, { "cf-ray": "abc-DFW" }, []);
    const byName = Object.fromEntries(got.map((t) => [t.name, t]));
    expect(byName["Google Analytics 4"]?.thirdParty).toBe(true);
    expect(byName["Stripe"]?.thirdParty).toBe(true);
    expect(byName["Hotjar"]?.thirdParty).toBe(true);
    expect(byName["Google Fonts"]?.thirdParty).toBe(true);
    expect(byName["Cloudflare"]?.thirdParty).toBe(true); // from cf-ray header
  });

  it("de-duplicates a technology detected via multiple signals", () => {
    const html = `<div data-reactroot></div><script src="/react-dom.production.min.js"></script>`;
    const react = detectTechnologies(html, {}, []).filter((t) => t.name === "React");
    expect(react).toHaveLength(1);
  });
});
