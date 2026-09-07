/**
 * Locale-stable formatting.
 *
 * `toLocaleString()` with no locale formats per the SERVER's locale. In a
 * browser that is correct — the locale belongs to the reader. On a server it is
 * wrong, because the output is a report read by someone else, and the same
 * report renders differently depending on which machine produced it.
 *
 * Measured on the development machine: 152,445,165 rendered as `15,24,45,165`,
 * and a February date rendered as `9/2/2026` where a US reader would read
 * `2/9/2026` — the same instant, two different days, with no way for the reader
 * to tell which was meant. In a security report where dates carry the
 * remediation clock, that is not cosmetic.
 */
import { describe, it, expect } from "vitest";
import { formatReportDate, formatReportDateOnly, formatCount } from "../../../server/utils/format";

describe("formatCount", () => {
  it("groups the same way regardless of the server's locale", () => {
    expect(formatCount(152_445_165)).toBe("152,445,165");
    expect(formatCount(1_500_000)).toBe("1,500,000");
    expect(formatCount(999)).toBe("999");
    expect(formatCount(0)).toBe("0");
  });

  it("does not produce a broken string for non-finite input", () => {
    expect(formatCount(Number.NaN)).toBe("0");
    expect(formatCount(Number.POSITIVE_INFINITY)).toBe("0");
  });
});

describe("formatReportDate", () => {
  /**
   * The whole point: a spelled month cannot be read as a day, so `9 Feb` is
   * unambiguous where `9/2` and `2/9` are not.
   */
  it("spells the month so day/month order cannot be confused", () => {
    const s = formatReportDate("2026-02-09T10:30:00Z");
    expect(s).toContain("Feb");
    expect(s).toContain("2026");
    expect(s).not.toMatch(/\d{1,2}\/\d{1,2}\/\d{4}/);
  });

  /** A timestamp near midnight shifts a day if the zone is left to assumption. */
  it("states the timezone and renders in UTC", () => {
    const s = formatReportDate("2026-02-09T23:30:00Z");
    expect(s).toMatch(/UTC$/);
    expect(s).toContain("9 Feb 2026");
    expect(s).toContain("23:30");
  });

  it("accepts a Date as well as a string", () => {
    expect(formatReportDate(new Date("2026-02-09T10:30:00Z"))).toBe(formatReportDate("2026-02-09T10:30:00Z"));
  });

  it("returns N/A rather than 'Invalid Date' for unusable input", () => {
    for (const bad of [null, undefined, "", "not a date"]) {
      expect(formatReportDate(bad as never)).toBe("N/A");
    }
  });

  it("is deterministic", () => {
    expect(formatReportDate("2026-02-09T10:30:00Z")).toBe(formatReportDate("2026-02-09T10:30:00Z"));
  });
});

describe("formatReportDateOnly", () => {
  it("omits the time but keeps the unambiguous month", () => {
    const s = formatReportDateOnly("2026-02-09T10:30:00Z");
    expect(s).toBe("9 Feb 2026");
    expect(s).not.toMatch(/\d{2}:\d{2}/);
  });

  it("returns N/A for unusable input", () => {
    expect(formatReportDateOnly(undefined)).toBe("N/A");
    expect(formatReportDateOnly("rubbish")).toBe("N/A");
  });
});
