/**
 * Free, keyless technology fingerprinting (Wappalyzer-style).
 *
 * Detects frameworks, languages, CMSes, servers, and third-party services from the
 * data a scan already fetches — HTML body, response headers, and Set-Cookie names.
 * No API keys, no external calls. Each fingerprint can match on any of: html regex,
 * script-src regex, a response header (optionally with a value pattern), or a cookie
 * name, and can capture a version. Third-party services (analytics, CDNs, payment,
 * chat, captcha, fonts, maps) are flagged so the dashboard/report can separate the
 * org's own stack from embedded external services.
 */

export type TechCategory =
  | "framework" | "frontend" | "backend" | "language" | "cms" | "ecommerce"
  | "server" | "hosting" | "cdn" | "analytics" | "marketing" | "tag-manager"
  | "payment" | "chat" | "captcha" | "maps" | "video" | "fonts" | "ui" | "security" | "database";

export interface TechFingerprint {
  name: string;
  category: TechCategory;
  thirdParty?: boolean;
  html?: RegExp;
  script?: RegExp;
  header?: { name: string; value?: RegExp };
  cookie?: RegExp;
  /** Capture group 1 = version, tested against html then the joined header string. */
  version?: RegExp;
}

export interface DetectedTech {
  name: string;
  category: TechCategory;
  source: string;
  version?: string;
  thirdParty: boolean;
}

const THIRD_PARTY_CATEGORIES = new Set<TechCategory>([
  "cdn", "analytics", "marketing", "tag-manager", "payment", "chat", "captcha", "maps", "video", "fonts",
]);

export const TECH_FINGERPRINTS: TechFingerprint[] = [
  // ── Frameworks / frontend ──
  { name: "Next.js", category: "framework", html: /__NEXT_DATA__|\/_next\/static/i },
  { name: "Nuxt.js", category: "framework", html: /__NUXT__|\/_nuxt\//i },
  { name: "React", category: "frontend", html: /data-reactroot|react\.production|_reactListening/i, script: /react(?:-dom)?[.@-]/i },
  { name: "Vue.js", category: "frontend", html: /data-v-[0-9a-f]{8}|__vue__/i, script: /vue(?:\.min|@|\/dist)/i },
  { name: "Angular", category: "frontend", html: /ng-version|ng-app|_nghost|_ngcontent/i, script: /angular/i },
  { name: "AngularJS", category: "frontend", html: /ng-app|ng-controller/i },
  { name: "Svelte", category: "frontend", html: /__svelte|svelte-[0-9a-z]+/i },
  { name: "SvelteKit", category: "framework", html: /__sveltekit/i },
  { name: "Gatsby", category: "framework", html: /___gatsby|gatsby-/i },
  { name: "Ember.js", category: "frontend", html: /ember-application|data-ember/i },
  { name: "Alpine.js", category: "frontend", html: /\sx-data=|alpinejs/i, script: /alpine(?:js|\.min)/i },
  { name: "jQuery", category: "frontend", script: /jquery/i, version: /jquery[.-]?(\d+\.\d+\.\d+)/i },
  { name: "Backbone.js", category: "frontend", script: /backbone(?:\.min)?\.js/i },
  { name: "HTMX", category: "frontend", html: /\shx-(?:get|post|target)=/i, script: /htmx/i },
  { name: "Vite", category: "frontend", html: /\/@vite\/client|__vite__|data-vite-dev-id/i, script: /\/@vite\/|vite\/dist/i },
  { name: "Webpack", category: "frontend", html: /webpackJsonp|__webpack_require__/i, script: /webpack|chunk\.[0-9a-f]+\.js/i },

  // ── UI / CSS ──
  { name: "Bootstrap", category: "ui", html: /class="[^"]*\b(?:navbar-toggler|col-(?:sm|md|lg|xl)-\d|btn-(?:primary|secondary))\b/i, script: /bootstrap(?:\.bundle)?(?:\.min)?\.js/i, version: /bootstrap@?(\d+\.\d+\.\d+)/i },
  { name: "Tailwind CSS", category: "ui", html: /class="[^"]*\b(?:antialiased|min-h-screen|space-[xy]-\d|ring-offset-|backdrop-blur)\b/i, script: /tailwind(?:css)?(?:\.min)?\.js|cdn\.tailwindcss/i },
  { name: "Bulma", category: "ui", html: /\bnavbar-burger\b|class="[^"]*\bis-(?:primary|info|danger|warning|large)\b|bulma(?:\.min)?\.css/i },
  { name: "Foundation", category: "ui", html: /foundation(?:\.min)?\.(?:js|css)|data-zf-|zurb/i },
  { name: "Material UI", category: "ui", html: /MuiButton|MuiBox|makeStyles/i },
  { name: "Font Awesome", category: "ui", thirdParty: false, html: /fa-(?:solid|regular|brands)|fontawesome/i, script: /fontawesome/i },

  // ── CMS / ecommerce ──
  { name: "WordPress", category: "cms", html: /wp-content|wp-includes|\/wp-json\//i, version: /wordpress\s*(\d+\.\d+(?:\.\d+)?)/i },
  { name: "Drupal", category: "cms", html: /sites\/default\/files|drupal-settings-json/i, header: { name: "x-drupal-cache" }, cookie: /^SESS[0-9a-f]{32}/i },
  { name: "Joomla", category: "cms", html: /\/media\/jui\/|joomla|com_content/i },
  { name: "Ghost", category: "cms", html: /ghost-|content="Ghost/i },
  { name: "Wix", category: "cms", html: /wix\.com|_wixCssStates|X-Wix/i, header: { name: "x-wix-request-id" } },
  { name: "Squarespace", category: "cms", html: /squarespace|static1\.squarespace/i, header: { name: "x-servedby", value: /squarespace/i } },
  { name: "Webflow", category: "cms", html: /webflow|w-mod-|data-wf-/i },
  { name: "HubSpot CMS", category: "cms", thirdParty: false, html: /hs-scripts|hubspot|_hsq/i },
  { name: "Contentful", category: "cms", html: /cdn\.contentful\.com|images\.ctfassets\.net/i },
  { name: "Sitecore", category: "cms", cookie: /^SC_ANALYTICS_GLOBAL_COOKIE/i },
  { name: "Shopify", category: "ecommerce", html: /cdn\.shopify\.com|Shopify\.theme|shopify-section/i, header: { name: "x-shopify-stage" } },
  { name: "WooCommerce", category: "ecommerce", html: /woocommerce|wc-block/i, cookie: /^woocommerce_/i },
  { name: "Magento", category: "ecommerce", html: /\/static\/frontend\/|mage\/cookies|Magento_/i, cookie: /^X-Magento|^mage-/i },
  { name: "BigCommerce", category: "ecommerce", html: /bigcommerce/i },
  { name: "PrestaShop", category: "ecommerce", html: /prestashop/i, cookie: /^PrestaShop-/i },

  // ── Languages / backend ──
  { name: "PHP", category: "language", header: { name: "x-powered-by", value: /php/i }, cookie: /^PHPSESSID/i, version: /php\/(\d+\.\d+\.\d+)/i },
  { name: "ASP.NET", category: "backend", header: { name: "x-powered-by", value: /asp\.net/i }, cookie: /^ASP\.NET_SessionId|\.AspNetCore/i },
  { name: "ASP.NET", category: "backend", header: { name: "x-aspnet-version" }, version: /x-aspnet-version:\s*([\d.]+)/i },
  { name: "Java", category: "language", cookie: /^JSESSIONID/i },
  { name: "Ruby on Rails", category: "backend", header: { name: "x-powered-by", value: /phusion|passenger/i }, cookie: /^_rails|_session_id/i },
  { name: "Django", category: "backend", html: /csrfmiddlewaretoken/i, cookie: /^(?:csrftoken|django)/i },
  { name: "Flask", category: "backend", cookie: /^session=eyJ/i, header: { name: "server", value: /werkzeug/i } },
  { name: "Laravel", category: "backend", cookie: /^laravel_session|^XSRF-TOKEN/i, html: /laravel/i },
  { name: "Express", category: "backend", header: { name: "x-powered-by", value: /express/i } },
  { name: "Node.js", category: "backend", header: { name: "x-powered-by", value: /node/i } },
  { name: "Spring", category: "backend", html: /org\.springframework|spring-/i },
  { name: "Symfony", category: "backend", header: { name: "x-debug-token" }, html: /symfony/i },

  // ── Web servers / hosting ──
  { name: "Nginx", category: "server", header: { name: "server", value: /nginx/i }, version: /nginx\/(\d+\.\d+\.\d+)/i },
  { name: "Apache", category: "server", header: { name: "server", value: /apache/i }, version: /apache\/(\d+\.\d+\.\d+)/i },
  { name: "Microsoft IIS", category: "server", header: { name: "server", value: /iis|microsoft/i }, version: /iis\/(\d+\.\d+)/i },
  { name: "LiteSpeed", category: "server", header: { name: "server", value: /litespeed/i } },
  { name: "Caddy", category: "server", header: { name: "server", value: /caddy/i } },
  { name: "OpenResty", category: "server", header: { name: "server", value: /openresty/i } },
  { name: "Vercel", category: "hosting", header: { name: "server", value: /vercel/i } },
  { name: "Vercel", category: "hosting", header: { name: "x-vercel-id" } },
  { name: "Netlify", category: "hosting", header: { name: "server", value: /netlify/i }, cookie: /^nf_ab/i },
  { name: "GitHub Pages", category: "hosting", header: { name: "server", value: /github\.com|GitHub/i } },
  { name: "Heroku", category: "hosting", header: { name: "via", value: /vegur/i } },
  { name: "AWS Amplify", category: "hosting", header: { name: "x-amz-cf-id" } },
  { name: "Google Cloud", category: "hosting", header: { name: "server", value: /gws|Google Frontend/i } },

  // ── CDN / edge (third-party) ──
  { name: "Cloudflare", category: "cdn", thirdParty: true, header: { name: "cf-ray" } },
  { name: "Fastly", category: "cdn", thirdParty: true, header: { name: "x-served-by", value: /cache-|fastly/i } },
  { name: "Akamai", category: "cdn", thirdParty: true, header: { name: "x-akamai-transformed" } },
  { name: "Amazon CloudFront", category: "cdn", thirdParty: true, header: { name: "x-amz-cf-pop" } },
  { name: "jsDelivr", category: "cdn", thirdParty: true, script: /cdn\.jsdelivr\.net/i },
  { name: "unpkg", category: "cdn", thirdParty: true, script: /unpkg\.com/i },
  { name: "cdnjs", category: "cdn", thirdParty: true, script: /cdnjs\.cloudflare\.com/i },

  // ── Analytics / tag managers / marketing (third-party) ──
  { name: "Google Analytics", category: "analytics", thirdParty: true, html: /google-analytics\.com\/(?:analytics|ga)\.js|gtag\('config'|GoogleAnalyticsObject/i },
  { name: "Google Analytics 4", category: "analytics", thirdParty: true, html: /gtag\/js\?id=G-|G-[A-Z0-9]{8,}/ },
  { name: "Google Tag Manager", category: "tag-manager", thirdParty: true, html: /googletagmanager\.com\/gtm\.js|GTM-[A-Z0-9]+/ },
  { name: "Facebook Pixel", category: "marketing", thirdParty: true, html: /connect\.facebook\.net\/[^"']+\/fbevents\.js|fbq\('init'/i },
  { name: "LinkedIn Insight", category: "marketing", thirdParty: true, html: /snap\.licdn\.com|_linkedin_partner_id/i },
  { name: "TikTok Pixel", category: "marketing", thirdParty: true, html: /analytics\.tiktok\.com|ttq\.load/i },
  { name: "Hotjar", category: "analytics", thirdParty: true, html: /static\.hotjar\.com|hjSiteSettings/i },
  { name: "Segment", category: "analytics", thirdParty: true, html: /cdn\.segment\.com\/analytics\.js|analytics\.track/i },
  { name: "Mixpanel", category: "analytics", thirdParty: true, html: /cdn\.mxpnl\.com|mixpanel/i },
  { name: "Amplitude", category: "analytics", thirdParty: true, html: /cdn\.amplitude\.com|amplitude\.getInstance/i },
  { name: "Plausible", category: "analytics", thirdParty: true, html: /plausible\.io\/js/i },
  { name: "Matomo", category: "analytics", thirdParty: true, html: /matomo\.js|_paq\.push/i },
  { name: "Cloudflare Web Analytics", category: "analytics", thirdParty: true, html: /static\.cloudflareinsights\.com/i },

  // ── Payment / chat / captcha / maps / video / fonts (third-party) ──
  { name: "Stripe", category: "payment", thirdParty: true, html: /js\.stripe\.com/i },
  { name: "PayPal", category: "payment", thirdParty: true, html: /paypal\.com\/sdk|paypalobjects/i },
  { name: "Razorpay", category: "payment", thirdParty: true, html: /checkout\.razorpay\.com/i },
  { name: "Intercom", category: "chat", thirdParty: true, html: /widget\.intercom\.io|intercomSettings/i },
  { name: "Drift", category: "chat", thirdParty: true, html: /js\.driftt\.com|drift\.load/i },
  { name: "Zendesk", category: "chat", thirdParty: true, html: /static\.zdassets\.com|zE\(/i },
  { name: "Crisp", category: "chat", thirdParty: true, html: /client\.crisp\.chat/i },
  { name: "Tawk.to", category: "chat", thirdParty: true, html: /embed\.tawk\.to/i },
  { name: "reCAPTCHA", category: "captcha", thirdParty: true, html: /www\.google\.com\/recaptcha|grecaptcha/i },
  { name: "hCaptcha", category: "captcha", thirdParty: true, html: /hcaptcha\.com\/1\/api\.js/i },
  { name: "Cloudflare Turnstile", category: "captcha", thirdParty: true, html: /challenges\.cloudflare\.com\/turnstile/i },
  { name: "Google Maps", category: "maps", thirdParty: true, html: /maps\.googleapis\.com|maps\.google\.com\/maps/i },
  { name: "Mapbox", category: "maps", thirdParty: true, html: /api\.mapbox\.com|mapbox-gl/i },
  { name: "YouTube", category: "video", thirdParty: true, html: /youtube\.com\/embed|youtube-nocookie/i },
  { name: "Vimeo", category: "video", thirdParty: true, html: /player\.vimeo\.com/i },
  { name: "Google Fonts", category: "fonts", thirdParty: true, html: /fonts\.googleapis\.com|fonts\.gstatic\.com/i },
  { name: "Adobe Fonts", category: "fonts", thirdParty: true, html: /use\.typekit\.net|typekit/i },
];

function headerValue(headers: Record<string, string>, name: string): string | undefined {
  return headers[name.toLowerCase()] ?? headers[name];
}

/**
 * Run the full fingerprint set against a page. `cookies` are raw Set-Cookie strings.
 * Returns de-duplicated technologies (highest-signal source wins), version-annotated
 * where a version could be extracted.
 */
export function detectTechnologies(
  html: string,
  headers: Record<string, string>,
  cookies: string[] = [],
): DetectedTech[] {
  const found = new Map<string, DetectedTech>();
  const headerBlob = Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join("\n");
  const scriptSrcs = (html.match(/<script[^>]+src=["']([^"']+)["']/gi) ?? []).join("\n");
  const linkHrefs = (html.match(/<link[^>]+href=["']([^"']+)["']/gi) ?? []).join("\n");
  const externalRefs = `${scriptSrcs}\n${linkHrefs}`;

  for (const fp of TECH_FINGERPRINTS) {
    let matched = false;
    let source = "";
    if (fp.header) {
      const v = headerValue(headers, fp.header.name);
      if (v !== undefined && (!fp.header.value || fp.header.value.test(v))) { matched = true; source = `${fp.header.name} header`; }
    }
    if (!matched && fp.cookie && cookies.some((c) => fp.cookie!.test(c.split("=")[0].trim()) || fp.cookie!.test(c))) { matched = true; source = "cookie"; }
    if (!matched && fp.script && fp.script.test(externalRefs)) { matched = true; source = "script/link src"; }
    if (!matched && fp.html && fp.html.test(html)) { matched = true; source = "HTML"; }
    if (!matched) continue;

    let version: string | undefined;
    if (fp.version) {
      const m = fp.version.exec(html) ?? fp.version.exec(headerBlob);
      if (m) version = m[1];
    }
    const thirdParty = fp.thirdParty ?? THIRD_PARTY_CATEGORIES.has(fp.category);
    const key = fp.name.toLowerCase();
    const existing = found.get(key);
    if (!existing) {
      found.set(key, { name: fp.name, category: fp.category, source, version, thirdParty });
    } else if (version && !existing.version) {
      existing.version = version; // enrich with a version from a later fingerprint
    }
  }
  return Array.from(found.values());
}
