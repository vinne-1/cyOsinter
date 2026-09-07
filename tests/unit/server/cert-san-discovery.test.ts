/**
 * Certificate SANs as a discovery source.
 *
 * `getCertificateInfo` has returned `altNames` since it was written, and they
 * were stored for display and nothing else — another case of data collected and
 * never consumed. A SAN list is the organisation's own statement about which
 * hostnames it serves, read from the live handshake rather than from a log of
 * what was once issued.
 */
import { describe, it, expect } from "vitest";
import { inScopeSans } from "../../../server/scanner/tls";

describe("inScopeSans", () => {
  it("keeps hostnames under the scanned domain", () => {
    expect(inScopeSans(["api.example.com", "mail.example.com"], "example.com"))
      .toEqual(["api.example.com", "mail.example.com"]);
  });

  /**
   * A wildcard is not a host. Resolving it is meaningless and putting it in an
   * inventory asserts an asset that does not exist — what it actually tells you
   * is that unknown siblings exist, which is the permutation stage's job.
   */
  it("drops wildcard entries", () => {
    expect(inScopeSans(["*.example.com", "api.example.com"], "example.com"))
      .toEqual(["api.example.com"]);
  });

  /**
   * Shared and multi-domain certificates routinely cover unrelated domains.
   * Attributing somebody else's hostname to this target is the same attribution
   * error asn-expansion refuses by default.
   */
  it("drops names belonging to other domains", () => {
    expect(inScopeSans(["api.example.com", "www.othercorp.net", "cdn.vendor.io"], "example.com"))
      .toEqual(["api.example.com"]);
  });

  /** `notexample.com` must not be read as being under `example.com`. */
  it("is not fooled by a suffix that merely ends with the domain text", () => {
    expect(inScopeSans(["notexample.com", "example.com.evil.net"], "example.com")).toEqual([]);
  });

  it("includes the apex itself when the certificate names it", () => {
    expect(inScopeSans(["example.com"], "example.com")).toEqual(["example.com"]);
  });

  it("normalises case, DNS: prefixes and trailing dots", () => {
    expect(inScopeSans(["DNS:API.Example.com."], "example.com")).toEqual(["api.example.com"]);
  });

  it("deduplicates and sorts", () => {
    expect(inScopeSans(["b.example.com", "a.example.com", "b.example.com"], "example.com"))
      .toEqual(["a.example.com", "b.example.com"]);
  });

  it("rejects malformed entries rather than passing them through", () => {
    expect(inScopeSans(["", "  ", "-bad-.example.com", "has space.example.com"], "example.com")).toEqual([]);
  });

  it("returns nothing for an empty certificate", () => {
    expect(inScopeSans([], "example.com")).toEqual([]);
  });
});
