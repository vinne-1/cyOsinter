/**
 * Lookalike / typosquat domain discovery — brand-threat monitoring.
 *
 * Generates the domains an attacker would plausibly register to impersonate the
 * target, then resolves each one to find which are actually live. A registered
 * lookalike with an MX record is phishing-capable infrastructure; one serving
 * HTTP is likely already hosting a clone of the brand's login page.
 *
 * Everything here is keyless: permutations are computed locally and confirmed
 * with plain DNS, so this needs no paid brand-monitoring feed.
 *
 * Reference: the permutation families are the ones catalogued by dnstwist —
 * omission, insertion, repetition, transposition, replacement (keyboard
 * adjacency), homoglyph, hyphenation, subdomain, bitsquatting and TLD swap.
 */

import { createLogger } from "../logger";

const log = createLogger("typosquat");

export type PermutationKind =
  | "omission"
  | "insertion"
  | "repetition"
  | "transposition"
  | "replacement"
  | "homoglyph"
  | "hyphenation"
  | "subdomain"
  | "bitsquatting"
  | "tld-swap"
  | "combosquat";

export interface Permutation {
  domain: string;
  kind: PermutationKind;
}

/** Adjacent keys on a QWERTY keyboard — the typos a human actually makes. */
const KEYBOARD_ADJACENCY: Record<string, string> = {
  q: "wa", w: "qes", e: "wrd", r: "etf", t: "ryg", y: "tuh", u: "yij",
  i: "uok", o: "ipl", p: "ol",
  a: "qsz", s: "awdx", d: "serfc", f: "drtgv", g: "ftyhb", h: "gyujn",
  j: "huikm", k: "jiol", l: "kop",
  z: "asx", x: "zsdc", c: "xdfv", v: "cfgb", b: "vghn", n: "bhjm", m: "njk",
  "0": "9o", "1": "2q", "2": "13w", "3": "24e", "4": "35r", "5": "46t",
  "6": "57y", "7": "68u", "8": "79i", "9": "80o",
};

/** Characters that render near-identically in common fonts. */
const HOMOGLYPHS: Record<string, string[]> = {
  a: ["à", "á", "â", "ä", "å", "ã", "@"],
  b: ["d", "lb", "ib", "6"],
  c: ["e", "ç", "ć"],
  d: ["b", "cl", "dl"],
  e: ["c", "é", "è", "ê", "ë"],
  g: ["q", "9", "ğ"],
  h: ["lh", "ih", "n"],
  i: ["1", "l", "!", "í", "ì", "ï"],
  j: ["i"],
  k: ["lk", "ik"],
  l: ["1", "i", "I", "|"],
  m: ["n", "nn", "rn"],
  n: ["m", "r", "ñ"],
  o: ["0", "ο", "ó", "ò", "ö", "q"],
  q: ["g", "9", "o"],
  r: ["n"],
  s: ["5", "$", "š"],
  t: ["7", "+"],
  u: ["v", "ú", "ü", "µ"],
  v: ["u", "w"],
  w: ["vv", "ω"],
  y: ["v", "ý"],
  z: ["2", "ž"],
  "0": ["o", "O"],
  "1": ["l", "i"],
  "5": ["s"],
};

/** TLDs an impersonator commonly swaps in. */
const COMMON_TLDS = [
  "com", "net", "org", "co", "io", "info", "biz", "online", "site", "shop",
  "app", "xyz", "top", "live", "cc", "me", "in", "us", "store", "web",
];

/** Words appended or prepended to a brand to look official. */
const COMBO_WORDS = [
  "login", "secure", "account", "verify", "support", "help", "mail", "portal",
  "auth", "signin", "update", "billing", "pay", "my", "app", "web", "online",
  "service", "id", "security",
];

/** Splits `sub.example.co.uk` into its registrable name and its suffix. */
export function splitDomain(domain: string): { name: string; tld: string } {
  const clean = domain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/\.$/, "");
  const parts = clean.split(".");
  if (parts.length < 2) return { name: clean, tld: "" };

  // Two-part public suffixes (co.uk, com.au, co.in …) must not be mistaken for
  // the registrable name, or every permutation would mangle the suffix instead.
  const twoPartSuffixes = new Set([
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "net.in", "org.in",
    "com.au", "net.au", "org.au", "co.nz", "co.za", "com.br", "com.mx",
    "co.jp", "com.sg", "com.tr", "com.cn",
  ]);
  const lastTwo = parts.slice(-2).join(".");
  if (parts.length >= 3 && twoPartSuffixes.has(lastTwo)) {
    return { name: parts[parts.length - 3]!, tld: lastTwo };
  }
  return { name: parts[parts.length - 2]!, tld: parts[parts.length - 1]! };
}

/** Characters dropped one at a time: `example` → `exmple`. */
function omissions(name: string): string[] {
  const out = new Set<string>();
  for (let i = 0; i < name.length; i++) {
    out.add(name.slice(0, i) + name.slice(i + 1));
  }
  return Array.from(out);
}

/** An adjacent key typed alongside the intended one: `example` → `exqample`. */
function insertions(name: string): string[] {
  const out = new Set<string>();
  for (let i = 0; i < name.length; i++) {
    for (const adj of KEYBOARD_ADJACENCY[name[i]!] ?? "") {
      out.add(name.slice(0, i) + adj + name.slice(i));
      out.add(name.slice(0, i + 1) + adj + name.slice(i + 1));
    }
  }
  return Array.from(out);
}

/** A held key: `example` → `exaample`. */
function repetitions(name: string): string[] {
  const out = new Set<string>();
  for (let i = 0; i < name.length; i++) {
    out.add(name.slice(0, i) + name[i] + name.slice(i));
  }
  out.delete(name);
  return Array.from(out);
}

/** Two characters swapped: `example` → `exmaple`. */
function transpositions(name: string): string[] {
  const out = new Set<string>();
  for (let i = 0; i < name.length - 1; i++) {
    if (name[i] === name[i + 1]) continue;
    out.add(name.slice(0, i) + name[i + 1] + name[i] + name.slice(i + 2));
  }
  return Array.from(out);
}

/** A neighbouring key hit instead: `example` → `exsmple`. */
function replacements(name: string): string[] {
  const out = new Set<string>();
  for (let i = 0; i < name.length; i++) {
    for (const adj of KEYBOARD_ADJACENCY[name[i]!] ?? "") {
      out.add(name.slice(0, i) + adj + name.slice(i + 1));
    }
  }
  out.delete(name);
  return Array.from(out);
}

/** Visually confusable substitutions: `example` → `exampl3`, `rn` for `m`. */
function homoglyphs(name: string): string[] {
  const out = new Set<string>();
  for (let i = 0; i < name.length; i++) {
    for (const glyph of HOMOGLYPHS[name[i]!] ?? []) {
      out.add(name.slice(0, i) + glyph + name.slice(i + 1));
    }
  }
  out.delete(name);
  return Array.from(out);
}

/** A hyphen inserted at each boundary: `example` → `ex-ample`. */
function hyphenations(name: string): string[] {
  const out = new Set<string>();
  for (let i = 1; i < name.length; i++) {
    out.add(name.slice(0, i) + "-" + name.slice(i));
  }
  return Array.from(out);
}

/** A dot inserted, making the brand look like a subdomain of another site. */
function subdomains(name: string): string[] {
  const out = new Set<string>();
  for (let i = 1; i < name.length; i++) {
    if (name[i - 1] === "-" || name[i] === "-") continue;
    out.add(name.slice(0, i) + "." + name.slice(i));
  }
  return Array.from(out);
}

/**
 * Single-bit flips of each character — domains a machine reaches when RAM
 * corrupts a cached hostname. Only flips landing on a valid DNS character count.
 */
function bitsquats(name: string): string[] {
  const out = new Set<string>();
  for (let i = 0; i < name.length; i++) {
    const code = name.charCodeAt(i);
    for (let bit = 0; bit < 7; bit++) {
      const flipped = String.fromCharCode(code ^ (1 << bit));
      if (/^[a-z0-9-]$/.test(flipped)) {
        out.add(name.slice(0, i) + flipped + name.slice(i + 1));
      }
    }
  }
  out.delete(name);
  return Array.from(out);
}

export interface GenerateOptions {
  /** Cap on returned permutations, so a long brand cannot explode the scan. */
  limit?: number;
  kinds?: PermutationKind[];
}

const ALL_KINDS: PermutationKind[] = [
  "omission", "insertion", "repetition", "transposition", "replacement",
  "homoglyph", "hyphenation", "subdomain", "bitsquatting", "tld-swap", "combosquat",
];

/**
 * Generates candidate lookalike domains for a target.
 * The original domain is never included in the result.
 */
export function generatePermutations(domain: string, opts: GenerateOptions = {}): Permutation[] {
  const { name, tld } = splitDomain(domain);
  if (!name || name.length < 2) return [];

  const kinds = new Set(opts.kinds ?? ALL_KINDS);
  const limit = opts.limit ?? 2000;
  const seen = new Set<string>([`${name}.${tld}`]);
  const out: Permutation[] = [];

  const push = (candidate: string, kind: PermutationKind) => {
    const d = candidate.toLowerCase();
    // Reject anything DNS would not accept: empty labels, leading/trailing
    // hyphens, or a label over 63 octets.
    if (seen.has(d)) return;
    const labels = d.split(".");
    if (labels.some((l) => l.length === 0 || l.length > 63 || l.startsWith("-") || l.endsWith("-"))) return;
    seen.add(d);
    out.push({ domain: d, kind });
  };

  const families: Array<[PermutationKind, string[]]> = [
    ["omission", kinds.has("omission") ? omissions(name) : []],
    ["insertion", kinds.has("insertion") ? insertions(name) : []],
    ["repetition", kinds.has("repetition") ? repetitions(name) : []],
    ["transposition", kinds.has("transposition") ? transpositions(name) : []],
    ["replacement", kinds.has("replacement") ? replacements(name) : []],
    ["homoglyph", kinds.has("homoglyph") ? homoglyphs(name) : []],
    ["hyphenation", kinds.has("hyphenation") ? hyphenations(name) : []],
    ["subdomain", kinds.has("subdomain") ? subdomains(name) : []],
    ["bitsquatting", kinds.has("bitsquatting") ? bitsquats(name) : []],
  ];

  for (const [kind, variants] of families) {
    for (const v of variants) push(tld ? `${v}.${tld}` : v, kind);
  }

  if (kinds.has("tld-swap") && tld) {
    for (const alt of COMMON_TLDS) {
      if (alt !== tld) push(`${name}.${alt}`, "tld-swap");
    }
  }

  if (kinds.has("combosquat") && tld) {
    for (const word of COMBO_WORDS) {
      push(`${name}-${word}.${tld}`, "combosquat");
      push(`${word}-${name}.${tld}`, "combosquat");
    }
  }

  return out.slice(0, limit);
}

export interface LookalikeResult extends Permutation {
  /** A-record addresses, empty when the name does not resolve. */
  addresses: string[];
  /** Mail exchangers — presence means the domain can send/receive phishing mail. */
  mx: string[];
  nameservers: string[];
  /** Registered but parked/unused names still matter: they are pre-positioned. */
  resolves: boolean;
  /**
   * Risk ranking used to sort results:
   *  - `high`   resolves AND has MX → live and mail-capable
   *  - `medium` resolves            → live host, likely a clone or parking page
   *  - `low`    registered only     → held for later use
   */
  risk: "high" | "medium" | "low";
}

type Resolver = {
  resolve4(host: string): Promise<string[]>;
  resolveMx(host: string): Promise<Array<{ exchange: string; priority: number }>>;
  resolveNs(host: string): Promise<string[]>;
};

/**
 * 127.0.53.53 is the address ICANN reserves to signal a *name collision*: the
 * TLD is delegated but the name is not actually registered to anyone. Treating
 * it as a live lookalike produces confident false positives — a sweep of
 * bigbasket.com reported `bigbasket.web` as high risk purely because of it.
 */
const NAME_COLLISION_ADDRESS = "127.0.53.53";

/** Loopback and collision answers mean "not really hosted anywhere". */
function isRealAddress(address: string): boolean {
  return address !== NAME_COLLISION_ADDRESS && !address.startsWith("127.");
}

/** The MX an operator gets when a TLD is delegated but the name is unregistered. */
function isPlaceholderMx(exchange: string): boolean {
  return (
    exchange === "" ||
    exchange === "localhost" ||
    exchange.includes("your-dns-needs-immediate-attention")
  );
}

/** Runs `tasks` with at most `limit` in flight — DNS floods get you rate-limited. */
async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const index = cursor++;
      if (index >= items.length) return;
      results[index] = await fn(items[index]!);
    }
  });
  await Promise.all(workers);
  return results;
}

/**
 * Resolves each candidate and keeps only those that exist.
 *
 * A domain counts as registered if ANY of A/MX/NS answers — a parked name often
 * has nameservers and nothing else, and those are exactly the ones worth
 * flagging before they are weaponised.
 */
export async function resolveLookalikes(
  permutations: Permutation[],
  opts: { concurrency?: number; resolver?: Resolver } = {},
): Promise<LookalikeResult[]> {
  const concurrency = opts.concurrency ?? 20;
  const resolver: Resolver = opts.resolver ?? (await import("dns")).promises;

  const settled = await mapWithConcurrency(permutations, concurrency, async (perm) => {
    const [rawAddresses, rawMx, nameservers] = await Promise.all([
      resolver.resolve4(perm.domain).catch(() => [] as string[]),
      resolver.resolveMx(perm.domain).then((r) => r.map((m) => m.exchange)).catch(() => [] as string[]),
      resolver.resolveNs(perm.domain).catch(() => [] as string[]),
    ]);

    // Drop collision/loopback answers before they can imply the name is hosted.
    const addresses = rawAddresses.filter(isRealAddress);
    const mx = rawMx.filter((exchange) => !isPlaceholderMx(exchange));

    // A name that resolved ONLY to the collision address is not registered at
    // all, so it should not appear in the results in any risk band.
    const collisionOnly = rawAddresses.length > 0 && addresses.length === 0;
    if (collisionOnly) return null;

    const resolves = addresses.length > 0;
    const registered = resolves || mx.length > 0 || nameservers.length > 0;
    if (!registered) return null;

    const risk: LookalikeResult["risk"] =
      resolves && mx.length > 0 ? "high" : resolves ? "medium" : "low";

    return { ...perm, addresses, mx, nameservers, resolves, risk };
  });

  const found = settled.filter((r): r is LookalikeResult => r !== null);

  const order = { high: 0, medium: 1, low: 2 } as const;
  found.sort((a, b) => order[a.risk] - order[b.risk] || a.domain.localeCompare(b.domain));

  log.info(
    { checked: permutations.length, registered: found.length, high: found.filter((f) => f.risk === "high").length },
    "Lookalike domain sweep complete",
  );
  return found;
}

export interface TyposquatScanResult {
  target: string;
  generated: number;
  checked: number;
  registered: LookalikeResult[];
  counts: { high: number; medium: number; low: number };
}

/**
 * End-to-end sweep: generate candidates for `domain`, resolve them, and return
 * the ones that exist, ranked by how immediately dangerous they are.
 */
export async function scanForLookalikes(
  domain: string,
  opts: GenerateOptions & { concurrency?: number; resolver?: Resolver } = {},
): Promise<TyposquatScanResult> {
  const permutations = generatePermutations(domain, opts);
  const registered = await resolveLookalikes(permutations, opts);

  return {
    target: domain,
    generated: permutations.length,
    checked: permutations.length,
    registered,
    counts: {
      high: registered.filter((r) => r.risk === "high").length,
      medium: registered.filter((r) => r.risk === "medium").length,
      low: registered.filter((r) => r.risk === "low").length,
    },
  };
}

export interface TyposquatFinding {
  title: string;
  description: string;
  severity: "high" | "medium" | "low" | "info";
  category: string;
  affectedAsset: string;
  cvssScore: string;
  remediation: string;
  evidence: Record<string, unknown>;
}

const BAND_SCORE: Record<TyposquatFinding["severity"], string> = {
  high: "7.5",
  medium: "5.3",
  low: "3.7",
  info: "0.0",
};

/**
 * Renders a lookalike sweep as findings.
 *
 * One finding per RISK TIER, not one per registered domain: a sweep can turn
 * up dozens of registered permutations, and a row each would bury the actual
 * question ("are any of these phishing-ready right now?") under a list. High
 * risk (live and mail-capable — ready to receive phishing replies or host a
 * credential-harvesting clone) gets its own finding because it is the one
 * tier that warrants acting on immediately; medium (live, no mail) and low
 * (registered but dormant — pre-positioned for later) are reported but at
 * lower urgency, matching `LookalikeResult.risk`'s own definition.
 */
export function buildTyposquatFindings(domain: string, result: TyposquatScanResult): TyposquatFinding[] {
  const findings: TyposquatFinding[] = [];
  const high = result.registered.filter((r) => r.risk === "high");
  const medium = result.registered.filter((r) => r.risk === "medium");
  const low = result.registered.filter((r) => r.risk === "low");

  if (high.length > 0) {
    findings.push({
      title: `${high.length} lookalike domain${high.length === 1 ? "" : "s"} registered and mail-capable — highest phishing risk`,
      description:
        `${high.length} domain${high.length === 1 ? "" : "s"} resembling ${domain} ${high.length === 1 ? "resolves" : "resolve"} to a live host ` +
        `AND publish${high.length === 1 ? "es" : ""} a mail exchanger, out of ${result.generated} candidate permutations checked: ` +
        `${high.slice(0, 10).map((r) => r.domain).join(", ")}${high.length > 10 ? `, and ${high.length - 10} more` : ""}. ` +
        `A domain in this state can both host a credential-harvesting clone of your site AND receive replies to phishing email sent from it — ` +
        `this is infrastructure an attacker could weaponise today, not merely a registered name. Registration alone does not prove malicious intent, ` +
        `but the combination of live hosting and mail capability on a name this close to yours warrants investigation.`,
      severity: "high",
      category: "brand_threat",
      affectedAsset: domain,
      cvssScore: BAND_SCORE.high,
      remediation:
        "Investigate each domain's hosted content and WHOIS registrant. For confirmed phishing/clone use, file a UDRP complaint or use the registrar's " +
        "abuse process to request takedown, and consider defensively registering close variants before they are taken.",
      evidence: { target: domain, generated: result.generated, checked: result.checked, domains: high },
    });
  }

  if (medium.length > 0) {
    findings.push({
      title: `${medium.length} lookalike domain${medium.length === 1 ? "" : "s"} registered and live`,
      description:
        `${medium.length} domain${medium.length === 1 ? "" : "s"} resembling ${domain} ${medium.length === 1 ? "resolves" : "resolve"} to a live host ` +
        `with no mail exchanger configured: ${medium.slice(0, 10).map((r) => r.domain).join(", ")}${medium.length > 10 ? `, and ${medium.length - 10} more` : ""}. ` +
        `This is typically a parking page or a clone under construction. It does not yet receive mail, but a live host can serve content at any time.`,
      severity: "medium",
      category: "brand_threat",
      affectedAsset: domain,
      cvssScore: BAND_SCORE.medium,
      remediation: "Periodically re-check what these domains serve. Escalate to the takedown process above if any starts hosting a clone or phishing content.",
      evidence: { target: domain, generated: result.generated, checked: result.checked, domains: medium },
    });
  }

  if (low.length > 0) {
    findings.push({
      title: `${low.length} lookalike domain${low.length === 1 ? "" : "s"} registered but dormant`,
      description:
        `${low.length} domain${low.length === 1 ? "" : "s"} resembling ${domain} ${low.length === 1 ? "is" : "are"} registered (nameservers respond) ` +
        `but ${low.length === 1 ? "does" : "do"} not yet resolve to a host or accept mail: ${low.slice(0, 10).map((r) => r.domain).join(", ")}` +
        `${low.length > 10 ? `, and ${low.length - 10} more` : ""}. Held but unused names are still pre-positioned — an attacker who has already ` +
        `registered a name can activate it without warning, unlike one who has not.`,
      severity: "low",
      category: "brand_threat",
      affectedAsset: domain,
      cvssScore: BAND_SCORE.low,
      remediation: "No immediate action required. Worth a periodic re-check, since activation would move these to medium or high risk with no new registration to notice.",
      evidence: { target: domain, generated: result.generated, checked: result.checked, domains: low },
    });
  }

  if (result.registered.length === 0) {
    findings.push({
      title: `No registered lookalike domains found for ${domain}`,
      description:
        `${result.generated} candidate permutation${result.generated === 1 ? "" : "s"} of ${domain} (typo, homoglyph, hyphenation, TLD-swap and ` +
        `combosquat variants) were checked against DNS and none are registered. This is a real, checked result, not an assumption — re-run periodically, ` +
        `since a lookalike can be registered at any time.`,
      severity: "info",
      category: "brand_threat",
      affectedAsset: domain,
      cvssScore: BAND_SCORE.info,
      remediation: "No action needed now. Re-run this sweep periodically to catch a new registration early.",
      evidence: { target: domain, generated: result.generated, checked: result.checked },
    });
  }

  return findings;
}
