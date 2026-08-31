import { describe, it, expect } from "vitest";
import {
  countSpfLookups,
  analyzeSpfDeep,
  analyzeDmarcDeep,
  findSpfRecord,
  SPF_LOOKUP_LIMIT,
} from "../../../server/scanner/spf-dmarc-deep";

/** DNS stub: domain -> TXT strings. */
function dns(zone: Record<string, string[]>) {
  return async (name: string): Promise<string[][]> => {
    const rec = zone[name];
    if (!rec) throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
    return rec.map((r) => [r]);
  };
}

const txt = (...records: string[]): string[][] => records.map((r) => [r]);

describe("findSpfRecord", () => {
  it("finds the SPF record among unrelated TXT records", () => {
    expect(findSpfRecord(["google-site-verification=abc", "v=spf1 -all"])).toBe("v=spf1 -all");
  });

  it("does not match a record that merely mentions spf1", () => {
    expect(findSpfRecord(["notes: we use v=spf1 somewhere"])).toBeUndefined();
  });
});

describe("countSpfLookups", () => {
  it("counts nothing for a record with only ip4 and all", () => {
    // ip4, ip6 and all require no DNS query and do not count (RFC 7208 §4.6.4).
    return expect(
      countSpfLookups("example.com", "v=spf1 ip4:1.2.3.4 ip6:2001:db8::/32 -all", dns({})),
    ).resolves.toMatchObject({ count: 0, exceeded: false });
  });

  it("counts a, mx, ptr and exists", async () => {
    const r = await countSpfLookups("example.com", "v=spf1 a mx ptr exists:%{i}.e.com -all", dns({}));
    expect(r.count).toBe(4);
  });

  it("follows include: and counts the nested mechanisms", async () => {
    const zone = {
      "provider.com": ["v=spf1 a mx -all"],
    };
    const r = await countSpfLookups("example.com", "v=spf1 include:provider.com -all", dns(zone));
    // 1 for the include itself, plus a and mx inside it.
    expect(r.count).toBe(3);
    expect(r.chain).toEqual(["example.com", "provider.com"]);
  });

  it("follows redirect= as a lookup", async () => {
    const zone = { "other.com": ["v=spf1 a -all"] };
    const r = await countSpfLookups("example.com", "v=spf1 redirect=other.com", dns(zone));
    expect(r.count).toBe(2);
  });

  it("detects the real-world case of a domain over the limit", async () => {
    // Four SaaS providers, each bringing its own nested includes. Every record
    // here is individually reasonable and the total is a permerror.
    const zone = {
      "a.com": ["v=spf1 include:a1.com include:a2.com a mx -all"],
      "a1.com": ["v=spf1 a mx -all"],
      "a2.com": ["v=spf1 a mx -all"],
      "b.com": ["v=spf1 a mx include:b1.com -all"],
      "b1.com": ["v=spf1 a mx -all"],
    };
    const r = await countSpfLookups("example.com", "v=spf1 include:a.com include:b.com -all", dns(zone));
    expect(r.count).toBeGreaterThan(SPF_LOOKUP_LIMIT);
    expect(r.exceeded).toBe(true);
  });

  it("counts a void lookup when an include resolves to nothing", async () => {
    // A stale include of a decommissioned vendor. Two of these are themselves
    // a permerror.
    const r = await countSpfLookups("example.com", "v=spf1 include:gone.com -all", dns({}));
    expect(r.voidLookups).toBe(1);
  });

  it("flags more than two void lookups as exceeding the limit", async () => {
    const r = await countSpfLookups(
      "example.com",
      "v=spf1 include:x1.com include:x2.com include:x3.com -all",
      dns({}),
    );
    expect(r.voidLookups).toBe(3);
    expect(r.exceeded).toBe(true);
  });

  it("cuts an include loop instead of recursing forever", async () => {
    // Real records do contain these, usually after a provider migration.
    const zone = {
      "a.com": ["v=spf1 include:b.com -all"],
      "b.com": ["v=spf1 include:a.com -all"],
    };
    const r = await countSpfLookups("a.com", zone["a.com"][0], dns(zone));
    expect(r.loop).toBe(true);
  });

  it("stops counting once the limit is blown", async () => {
    // A receiver aborts too; resolving hundreds more names to report a bigger
    // number would just be slow.
    const zone: Record<string, string[]> = {};
    for (let i = 0; i < 60; i += 1) zone[`p${i}.com`] = ["v=spf1 a mx -all"];
    const record = `v=spf1 ${Array.from({ length: 60 }, (_, i) => `include:p${i}.com`).join(" ")} -all`;
    const r = await countSpfLookups("example.com", record, dns(zone));
    expect(r.exceeded).toBe(true);
    // Far below the ~180 a full walk would produce.
    expect(r.count).toBeLessThan(40);
  });
});

describe("analyzeSpfDeep", () => {
  it("reports a clean, minimal record as having no issues", async () => {
    const r = await analyzeSpfDeep("example.com", txt("v=spf1 ip4:1.2.3.4 -all"), dns({}));
    expect(r.found).toBe(true);
    expect(r.issues).toEqual([]);
  });

  it("explains that exceeding the lookup limit means NO SPF, not weak SPF", async () => {
    // The distinction is the whole point: the record looks fine and provides
    // nothing, so the finding has to say so explicitly.
    const zone: Record<string, string[]> = {};
    for (let i = 0; i < 12; i += 1) zone[`p${i}.com`] = ["v=spf1 a -all"];
    const record = `v=spf1 ${Array.from({ length: 12 }, (_, i) => `include:p${i}.com`).join(" ")} -all`;
    const r = await analyzeSpfDeep("example.com", txt(record), dns(zone));
    expect(r.issues.join(" ")).toMatch(/NO SPF record at all/i);
  });

  it("warns when a domain is one provider away from breaking", async () => {
    const zone: Record<string, string[]> = {};
    for (let i = 0; i < 9; i += 1) zone[`p${i}.com`] = ["v=spf1 -all"];
    const record = `v=spf1 ${Array.from({ length: 9 }, (_, i) => `include:p${i}.com`).join(" ")} -all`;
    const r = await analyzeSpfDeep("example.com", txt(record), dns(zone));
    expect(r.issues.join(" ")).toMatch(/adding one more provider will break it/i);
  });

  it("treats two SPF records as no SPF, because a receiver cannot choose", async () => {
    const r = await analyzeSpfDeep("example.com", txt("v=spf1 -all", "v=spf1 ip4:1.2.3.4 ~all"), dns({}));
    expect(r.issues.join(" ")).toMatch(/permerror/i);
  });

  it("distinguishes softfail from a hard fail rather than accepting both", async () => {
    const soft = await analyzeSpfDeep("example.com", txt("v=spf1 ip4:1.2.3.4 ~all"), dns({}));
    const hard = await analyzeSpfDeep("example.com", txt("v=spf1 ip4:1.2.3.4 -all"), dns({}));
    expect(soft.issues.join(" ")).toMatch(/softfail/i);
    expect(hard.issues).toEqual([]);
  });

  it("flags +all as authorising the whole internet", async () => {
    const r = await analyzeSpfDeep("example.com", txt("v=spf1 +all"), dns({}));
    expect(r.issues.join(" ")).toMatch(/every sender on the internet/i);
  });

  it("flags the deprecated ptr mechanism", async () => {
    const r = await analyzeSpfDeep("example.com", txt("v=spf1 ptr -all"), dns({}));
    expect(r.issues.join(" ")).toMatch(/ptr.*deprecated/i);
  });

  it("flags an absurdly broad ip4 range", async () => {
    const r = await analyzeSpfDeep("example.com", txt("v=spf1 ip4:10.0.0.0/8 -all"), dns({}));
    expect(r.issues.join(" ")).toMatch(/extremely broad/i);
  });

  it("reports a missing record", async () => {
    const r = await analyzeSpfDeep("example.com", txt("some-other-txt"), dns({}));
    expect(r.found).toBe(false);
  });
});

describe("analyzeDmarcDeep", async () => {
  it("accepts a fully configured policy", async () => {
    const r = await analyzeDmarcDeep("example.com", txt("v=DMARC1; p=reject; rua=mailto:d@example.com"));
    expect(r.found).toBe(true);
    expect(r.policy).toBe("reject");
    expect(r.issues).toEqual([]);
  });

  it("catches the subdomain bypass", async () => {
    // p=reject with sp=none is the trap: everyone believes the domain is
    // protected, and mail from any subdomain sails through.
    const r = await analyzeDmarcDeep("example.com", txt("v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com"));
    expect(r.issues.join(" ")).toMatch(/exempting every subdomain/i);
  });

  it("flags a policy with nowhere to send reports", async () => {
    const r = await analyzeDmarcDeep("example.com", txt("v=DMARC1; p=none"));
    expect(r.issues.join(" ")).toMatch(/no rua=/i);
  });

  it("flags an external reporter that has NOT authorised the domain", async () => {
    // Without the authorisation record the reports are silently discarded, and
    // the owner concludes from an empty dashboard that nothing is wrong.
    const r = await analyzeDmarcDeep(
      "example.com",
      txt("v=DMARC1; p=reject; rua=mailto:x@dmarc-vendor.com"),
      dns({}),
    );
    expect(r.issues.join(" ")).toMatch(/example\.com\._report\._dmarc\.dmarc-vendor\.com/);
  });

  it("stays silent when the external reporter HAS authorised the domain", async () => {
    // Most large domains send reports to a DMARC vendor and do publish this
    // record — measured on salesforce.com, which uses two. Asserting a problem
    // without checking would put a false positive on nearly every well-run
    // domain, which is exactly what the first version of this check did.
    const r = await analyzeDmarcDeep(
      "example.com",
      txt("v=DMARC1; p=reject; rua=mailto:x@dmarc-vendor.com"),
      dns({ "example.com._report._dmarc.dmarc-vendor.com": ["v=DMARC1"] }),
    );
    expect(r.issues.join(" ")).not.toMatch(/silently discarded/i);
  });

  it("skips the authorisation check entirely when no resolver is supplied", async () => {
    // "We did not look" must never render as "there is a problem".
    const r = await analyzeDmarcDeep("example.com", txt("v=DMARC1; p=reject; rua=mailto:x@vendor.com"));
    expect(r.issues.join(" ")).not.toMatch(/silently discarded/i);
  });

  it("does not treat the domain's own subdomain as an external reporter", async () => {
    const r = await analyzeDmarcDeep("example.com", txt("v=DMARC1; p=reject; rua=mailto:d@mail.example.com"));
    expect(r.issues.join(" ")).not.toMatch(/authorisation record/i);
  });

  it("flags a record with no policy tag", async () => {
    const r = await analyzeDmarcDeep("example.com", txt("v=DMARC1; rua=mailto:d@example.com"));
    expect(r.issues.join(" ")).toMatch(/no p= tag/i);
  });

  it("flags an invalid policy value", async () => {
    const r = await analyzeDmarcDeep("example.com", txt("v=DMARC1; p=block; rua=mailto:d@example.com"));
    expect(r.issues.join(" ")).toMatch(/not valid/i);
  });

  it("reports partial application", async () => {
    const r = await analyzeDmarcDeep("example.com", txt("v=DMARC1; p=reject; pct=20; rua=mailto:d@example.com"));
    expect(r.issues.join(" ")).toMatch(/pct=20/);
  });

  it("reports a missing record", async () => {
    expect((await analyzeDmarcDeep("example.com", txt("unrelated"))).found).toBe(false);
  });

  it("reassembles a DMARC record DNS split into chunks", async () => {
    const r = await analyzeDmarcDeep("example.com", [["v=DMARC1; p=re", "ject; rua=mailto:d@example.com"]]);
    expect(r.policy).toBe("reject");
  });
});
