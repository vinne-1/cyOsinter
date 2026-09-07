# Detection Accuracy — Measured, Not Claimed

## The bar

Every EASM vendor advertises a **false-positive rate below 1%**. Buyer's guides for the
category are blunt about how little that means on its own, and the useful follow-up question
they recommend is *how* the rate is achieved: filtering findings after the fact is not the same
as **structural validation**, where a finding is tested against the live environment before it
reaches an analyst.

That distinction is the bar this document measures against, because it is the one that can
actually be checked.

## Method

Rather than scan something new and grade my own homework, this audits the findings **already
in the database from real scans** — 51 findings across 6 workspaces, of which 36 are
`kind = security` (the rest are `recon` technology detections and `control` good-news items,
neither of which asserts a weakness).

Each finding that can be checked against public ground truth was verified independently of the
scanner: DNS records resolved directly, HTTP headers fetched with `curl`, the TLS certificate
read with `openssl s_client`.

**11 of the 36 security findings are independently verifiable this way.** The rest depend on
scan-time state (Shodan index contents, discovered email addresses) that cannot be reproduced
after the fact, and are excluded rather than assumed correct.

## Result

| Verdict | Count | Findings |
|---|---|---|
| **Confirmed true** | 8 | 3× No DMARC, 1× No SPF on non-mail subdomain, 3× missing security headers / CSP, 1× weak HSTS |
| **False positive** | 2 | `SPF Record Issues for alkemlabs.com` (×2) — single root cause, **fixed** |
| **Not reproducible** | 1 | `Weak HSTS on alkemlabs.com` (apex) |

Sample false-positive rate: **2 of 11 (18%) before the fix, 0 of 11 after.**

This is a sample, not a corpus rate. Extrapolating "<1%" from eleven findings would be exactly
the kind of unsupported claim this document exists to avoid.

## The false positive, and what caused it

`alkemlabs.com` publishes:

```
v=spf1 redirect=_spf.mailhostbox.com
```

The scanner reported *"SPF record may not have a restrictive -all or ~all terminator"*.

It has no `all` mechanism, so the terminator test found none. But per **RFC 7208 §6.1** a record
using `redirect=` is *supposed* to have no `all` — the redirect target's policy becomes this
domain's policy, and the RFC further specifies that if `all` **is** present, `redirect` must be
ignored entirely. Resolving the target confirms it:

```
_spf.mailhostbox.com  →  v=spf1 include:… include:… ~all
```

The domain's SPF terminates correctly. The check was testing one record in isolation while a
receiving mail server evaluates the chain.

**Fix:** `effectiveTerminator` in `server/scanner/spf-dmarc-deep.ts` now follows `redirect=`
(bounded depth, loop-guarded) and reports the policy that actually applies, with provenance.
The same record now yields:

> SPF ends in ~all (softfail); mail from unauthorised senders is usually still delivered, to
> spam *(policy inherited from redirect=_spf.mailhostbox.com)*

An unresolvable redirect target reports **unresolved** — "the effective policy could not be
determined" — rather than "there is no policy". Those are different claims, and collapsing
them is how a scanner produces a confident wrong answer.

Pinned by `tests/unit/server/spf-redirect.test.ts` (14 tests), including the substring trap that
caused it: `all` is an SPF term, not a fragment, so `redirect=_spf.mailhostbox.com` and
`include:install.example.com` must not register as terminators.

## Two results worth reading carefully

**A remediated finding is not a false positive.** `SSL Certificate Issue on webmail.alkem.com`
was recorded on 2026-08-11 as "expires in 26 days" — an expiry around 2026-09-06. The
certificate serving that host today was issued 2026-08-27: the operator renewed it. The finding
was true when observed and has since been fixed. Grading it against today's state would score a
correct finding as an error, and would also punish the product for working.

**One true positive is the direct result of structural validation.**
`theranymbio.in.wss.workspaceone.com` runs a **wildcard DNS** that answers every name with the
TXT record `India=india account` — including `_dmarc.theranymbio…`. A scanner asking "does a TXT
record exist at `_dmarc`?" would conclude DMARC is configured and stay silent. This one requires
the record to actually begin `v=DMARC1`, so it correctly reported DMARC as absent — and
separately reported the wildcard itself as recon. That is the difference between checking for a
response and checking for the artefact, and it is the same rule the HTTP detectors follow
(`server/scanner/body-signatures.ts`).

## Where the structural validation lives

The claim "tested against the live environment before it reaches an analyst" maps to three
gates, documented in `CLAUDE.md`:

1. **`response-oracle.ts`** — auto-calibrates each origin's not-found behaviour (ffuf-style,
   normalised-token Jaccard) so a soft-404 cannot be read as a discovered path. A `200` is not
   evidence.
2. **`body-signatures.ts`** — a detector may not name an artefact without the artefact's
   structure present. No "Kubernetes API exposed" without a Kubernetes document.
3. **`verification-gate.ts`** — re-probes at report time and withholds anything it cannot
   reproduce, recording *what* it withheld so "we looked and could not confirm" stays distinct
   from "we never looked".

## Honest limits

- Eleven findings is a small sample, drawn from four domains.
- Findings that depend on third-party index state (Shodan) were not verified.
- `Weak HSTS on alkemlabs.com` (apex) could not be reproduced: the apex sends no HSTS header
  today, while `www` sends `max-age=7775999` (90 days — genuinely weak, and that finding is
  confirmed). The likely explanation is that the Nuclei template followed the apex→www redirect
  and attributed the response header to the requested host. Recorded as indeterminate rather
  than counted either way.
