/**
 * Mobile apps published under the target's brand.
 *
 * ## Why this exists
 *
 * "Rogue app detection" is a headline module in every digital-risk product
 * (CloudSEK XVigil's Brand Monitor names it explicitly), and this engine had no
 * coverage at all: `typosquat.ts` watches lookalike DOMAINS, and nothing looked
 * at app stores. A fake banking app published under a company's name is the same
 * class of brand abuse as a lookalike login page, and it reaches users through a
 * channel the domain-based checks cannot see.
 *
 * ## Attribution, which is the whole problem
 *
 * The App Store search returns anything the store's relevance engine thinks
 * matches, so most results are noise or legitimate third-party integrations. Two
 * fields make attribution verifiable rather than guessed:
 *
 *  - **`sellerUrl`** — the developer's own website. When its host is the domain
 *    being scanned, the app is the customer's own, confirmed rather than assumed.
 *    This is the ONLY signal that confers ownership.
 *  - **`bundleId`** — conventionally the reverse domain (`com.stripe.dashboard`),
 *    but **self-declared and never verified by Apple against domain ownership**.
 *    Found live: `FacilePay: Stripe Payments`, published by *vBridge Technologies
 *    Inc.*, ships `com.stripe.credit.card.payment`. Treating that as proof would
 *    have put a stranger's app into the customer's own inventory. It is therefore
 *    recorded as brand usage — a third party putting your name in their
 *    identifier is a stronger signal than one merely using it in a title — and
 *    never as ownership.
 *
 * The asymmetry is deliberate: under-attributing an app costs a reviewer one
 * glance, while over-attributing one silently adopts somebody else's software.
 * Same stance as the bucket-ownership rule in `cloud-discovery`.
 *
 * ## What this deliberately does NOT say
 *
 * It never calls an app "fake" or "impersonation". A great many apps legitimately
 * carry another company's brand: payment integrations, resellers, partner
 * clients, third-party dashboards. Live example — searching `stripe` returns
 * "Payment for Stripe" by *PocketVendor Inc*, which is a real integration, not an
 * attack. What can be stated honestly is narrower and still useful: **this app
 * uses your brand name and is published by someone who is not you — confirm it is
 * authorised.** Asserting more would produce exactly the confident wrong answer
 * the severity rules in CLAUDE.md exist to prevent.
 *
 * ## Coverage is stated, not implied
 *
 * Apple's Search API is public and keyless. **Google Play has no equivalent**:
 * there is no free official API, and scraping the store is fragile and against
 * its terms. So Android is NOT covered, and the result says so rather than
 * leaving a reader to assume both stores were checked — the same rule as
 * `code-leak-watch` never reporting "clean" for a check that did not run.
 */

import { createLogger } from "../logger.js";
import { stealthFetch } from "./stealth.js";

const log = createLogger("mobile-app-monitor");

const ITUNES_SEARCH_URL = "https://itunes.apple.com/search";
const REQUEST_TIMEOUT_MS = 12_000;
const MAX_RESULTS = 50;

/**
 * Shortest brand token worth searching.
 *
 * Same threshold and same reason as `asn-expansion`'s org-token rule: matching
 * on "hp" or "ge" attributes half the store to a two-letter coincidence.
 */
const MIN_BRAND_TOKEN = 4;

export type AppAttribution = "official" | "third-party";

export interface StoreApp {
  name: string;
  seller: string;
  sellerUrl?: string;
  bundleId?: string;
  storeUrl?: string;
  store: "apple";
  /** Ratings count, a rough popularity signal for triage order. */
  ratings?: number;
  attribution: AppAttribution;
  /** Why it was attributed that way — stated so a reader can disagree. */
  reason: string;
  /**
   * The brand appears in a bundle identifier published by someone else. Not
   * ownership (identifiers are self-declared), but stronger brand usage than a
   * title alone, so it is worth a reviewer's attention first.
   */
  brandInBundleId?: boolean;
}

export interface MobileAppResult {
  brand: string;
  /** Apps confirmed to belong to the domain owner. */
  official: StoreApp[];
  /** Apps carrying the brand name published by somebody else. */
  thirdParty: StoreApp[];
  /** Stores that were actually searched. */
  storesChecked: string[];
  /** Stores NOT searched, with the reason — never silently omitted. */
  storesNotChecked: Array<{ store: string; reason: string }>;
  /** True when the store search itself failed. NOT "no apps found". */
  unavailable: boolean;
}

/**
 * The brand token to search for, derived from the domain.
 *
 * `stripe.com` → `stripe`. Returns null when the label is too short to search
 * without flooding.
 */
export function brandTokenFor(domain: string): string | null {
  const host = domain.trim().toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
  const label = host.split(".")[0] ?? "";
  return label.length >= MIN_BRAND_TOKEN ? label : null;
}

/** Registrable-ish root of a host, for comparing a seller URL to the target. */
function registrableRoot(host: string): string {
  const parts = host.toLowerCase().replace(/^www\./, "").split(".");
  return parts.length <= 2 ? parts.join(".") : parts.slice(-2).join(".");
}

/**
 * Decides whether an app belongs to the domain owner.
 *
 * Both signals are verifiable facts published by the store, not inferences: the
 * developer's stated website, and the bundle identifier's reverse-domain form.
 */
export function attributeApp(
  app: { sellerUrl?: string; bundleId?: string },
  domain: string,
): { attribution: AppAttribution; reason: string; brandInBundleId: boolean } {
  const target = registrableRoot(domain);
  const targetLabel = target.split(".")[0]!;

  // Self-declared, so this NEVER confers ownership — only attention.
  let brandInBundleId = false;
  if (app.bundleId) {
    const segments = app.bundleId.toLowerCase().split(".");
    brandInBundleId =
      segments.length >= 2 && segments[1] === targetLabel && /^(com|io|net|org|co)$/.test(segments[0]!);
  }

  if (app.sellerUrl) {
    try {
      const host = new URL(app.sellerUrl).hostname;
      if (registrableRoot(host) === target) {
        return {
          attribution: "official",
          reason: `the developer's listed website is on ${target}`,
          brandInBundleId,
        };
      }
    } catch {
      /* an unparseable seller URL simply proves nothing */
    }
  }

  return {
    attribution: "third-party",
    reason: brandInBundleId
      ? `the bundle identifier ${app.bundleId} uses your brand, but identifiers are self-declared and the developer's website is not on ${target}`
      : `neither the developer's website nor the bundle identifier ties this app to ${target}`,
    brandInBundleId,
  };
}

interface ItunesResult {
  trackName?: string;
  sellerName?: string;
  artistName?: string;
  sellerUrl?: string;
  bundleId?: string;
  trackViewUrl?: string;
  userRatingCount?: number;
}

/**
 * Searches Apple's App Store for apps carrying the brand name.
 *
 * Results whose name and bundle id contain no trace of the brand are DROPPED
 * rather than reported: the store's relevance engine returns competitors and
 * loosely related apps (searching "stripe" returns Square's point-of-sale app),
 * and reporting those as brand usage would bury the real signal.
 */
export async function findBrandedApps(domain: string): Promise<MobileAppResult> {
  const brand = brandTokenFor(domain);

  const result: MobileAppResult = {
    brand: brand ?? "",
    official: [],
    thirdParty: [],
    storesChecked: [],
    storesNotChecked: [
      {
        store: "Google Play",
        reason: "no free official search API exists; scraping the store is fragile and against its terms, so Android is not covered",
      },
    ],
    unavailable: false,
  };

  if (!brand) {
    result.storesNotChecked.push({
      store: "Apple App Store",
      reason: `the domain's name is shorter than ${MIN_BRAND_TOKEN} characters, so a search would match unrelated apps`,
    });
    return result;
  }

  let results: ItunesResult[];
  try {
    const url = `${ITUNES_SEARCH_URL}?term=${encodeURIComponent(brand)}&entity=software&limit=${MAX_RESULTS}&country=us`;
    const res = await stealthFetch(url, {}, REQUEST_TIMEOUT_MS);
    if (!res.ok) {
      log.warn({ status: res.status, brand }, "App Store search failed");
      result.unavailable = true;
      return result;
    }
    const body = (await res.json()) as { results?: ItunesResult[] };
    results = body.results ?? [];
    result.storesChecked.push("Apple App Store");
  } catch (err) {
    log.warn({ err, brand }, "App Store search unreachable");
    result.unavailable = true;
    return result;
  }

  for (const r of results) {
    const name = (r.trackName ?? "").trim();
    if (!name) continue;

    const haystack = `${name} ${r.bundleId ?? ""}`.toLowerCase();
    // Search relevance noise: nothing about this app mentions the brand.
    if (!haystack.includes(brand)) continue;

    const attributed = attributeApp(r, domain);
    const app: StoreApp = {
      name,
      seller: (r.sellerName ?? r.artistName ?? "unknown").trim(),
      sellerUrl: r.sellerUrl,
      bundleId: r.bundleId,
      storeUrl: r.trackViewUrl,
      store: "apple",
      ratings: r.userRatingCount,
      attribution: attributed.attribution,
      reason: attributed.reason,
      brandInBundleId: attributed.brandInBundleId,
    };

    if (app.attribution === "official") result.official.push(app);
    else result.thirdParty.push(app);
  }

  // Most-installed first: a brand-named app with 60,000 ratings matters more
  // than one with none, and a reviewer's time is the scarce resource.
  // Brand-in-identifier first, then by popularity: a third party shipping
  // `com.<yourbrand>.*` deserves a look before one that merely says your name.
  result.thirdParty.sort(
    (a, b) => Number(b.brandInBundleId ?? false) - Number(a.brandInBundleId ?? false) || (b.ratings ?? 0) - (a.ratings ?? 0),
  );
  result.official.sort((a, b) => (b.ratings ?? 0) - (a.ratings ?? 0));

  return result;
}

export interface MobileAppFinding {
  title: string;
  description: string;
  severity: "medium" | "low" | "info";
  category: string;
  affectedAsset: string;
  cvssScore: string;
  remediation: string;
  evidence: Record<string, unknown>;
}

/**
 * Renders the result as findings.
 *
 * One finding listing every third-party app rather than one per app: they are a
 * single review task for one person, and a row each would read as a list of
 * accusations. Apps the domain owner published are reported as `info` — knowing
 * your own app inventory is useful, and it is not a problem.
 */
export function buildMobileAppFindings(domain: string, result: MobileAppResult): MobileAppFinding[] {
  const findings: MobileAppFinding[] = [];

  if (result.thirdParty.length > 0) {
    const plural = result.thirdParty.length !== 1;
    const names = result.thirdParty.map((a) => `"${a.name}" by ${a.seller}`);
    findings.push({
      title: `${result.thirdParty.length} App Store app${plural ? "s" : ""} using the "${result.brand}" brand published by others`,
      description:
        // Verb agreement kept consistent across the whole sentence: an earlier
        // version read "1 app ... carry ... but is published".
        `${result.thirdParty.length} app${plural ? "s" : ""} on the Apple App Store ${plural ? "carry" : "carries"} the "${result.brand}" name but ` +
        `${plural ? "are" : "is"} published by a developer whose website and bundle identifier do not tie back to ${domain}: ` +
        `${names.slice(0, 8).join("; ")}${names.length > 8 ? `; and ${names.length - 8} more` : ""}. ` +
        `This does NOT establish that any of them is fake — payment integrations, resellers and partner clients legitimately carry another ` +
        `company's brand. What it establishes is that your name is in use by parties who are not you, which is worth confirming is authorised.`,
      severity: "medium",
      category: "brand_threat",
      affectedAsset: domain,
      cvssScore: "5.3",
      remediation:
        "Review each listing and confirm the publisher is an authorised partner. For any that are not, use Apple's content dispute process " +
        "to request removal, and register your brand with the store so future submissions are flagged.",
      evidence: { brand: result.brand, apps: result.thirdParty, storesChecked: result.storesChecked },
    });
  }

  if (result.official.length > 0) {
    findings.push({
      title: `${result.official.length} App Store app${result.official.length === 1 ? "" : "s"} confirmed published by ${domain}`,
      description:
        `${result.official.length} app${result.official.length === 1 ? " was" : "s were"} confirmed to belong to ${domain}: ` +
        `${result.official.map((a) => `"${a.name}"`).join(", ")}. Confirmed by the developer's listed website or the bundle identifier, ` +
        `not assumed from the name. Recorded so the mobile estate is part of the inventory rather than something only the app team knows about.`,
      severity: "info",
      category: "brand_threat",
      affectedAsset: domain,
      cvssScore: "0.0",
      remediation: "No action needed. Confirm this list matches what your organisation intends to publish.",
      evidence: { brand: result.brand, apps: result.official },
    });
  }

  // Coverage is stated rather than implied: a reader must be able to tell
  // "Android was not checked" from "no Android apps exist".
  if (result.unavailable || result.storesNotChecked.length > 0) {
    findings.push({
      title: `Mobile app stores not fully checked for ${domain}`,
      description: result.unavailable
        ? `The App Store search could not be completed, so no conclusion can be drawn about apps using the "${result.brand}" name. This is not a statement that none exist.`
        : `Not every store was searched: ${result.storesNotChecked.map((s) => `${s.store} — ${s.reason}`).join("; ")}.`,
      severity: "info",
      category: "brand_threat",
      affectedAsset: domain,
      cvssScore: "0.0",
      remediation: result.unavailable
        ? "Re-run when the store search is reachable."
        : "Check Google Play manually, or supply a commercial store-intelligence feed if Android coverage matters to you.",
      evidence: {
        unavailable: result.unavailable,
        storesChecked: result.storesChecked,
        storesNotChecked: result.storesNotChecked,
      },
    });
  }

  return findings;
}
