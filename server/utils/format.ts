/**
 * Locale-stable formatting for anything a customer reads.
 *
 * ## The defect this exists to prevent
 *
 * `Date.toLocaleString()` and `Number.toLocaleString()` with no locale argument
 * format according to the **server's** locale. That is fine in a browser, where
 * the locale belongs to the person reading. It is wrong on a server, where the
 * output is a report that will be read by someone else entirely — the same
 * report renders differently depending on which machine generated it.
 *
 * For numbers it produced grouping the reader may not recognise: 152,445,165
 * rendered as `15,24,45,165` on a machine set to an Indian locale.
 *
 * For dates it is worse, because the result is not merely unfamiliar but
 * genuinely **ambiguous**. The same instant renders as `9/2/2026` or `2/9/2026`,
 * and a reader cannot tell 9 February from 2 September. In a security report
 * where dates carry the remediation clock, that is not a cosmetic problem.
 *
 * Both helpers therefore pin the format rather than inheriting it.
 */

/**
 * A date a reader cannot misinterpret: `9 Feb 2026, 16:00 UTC`.
 *
 * The month is spelled, so day/month order cannot be confused, and the zone is
 * stated, so a timestamp near midnight is not silently shifted a day by the
 * reader's assumption about which zone it was in.
 */
export function formatReportDate(value: Date | string | null | undefined): string {
  if (!value) return "N/A";
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return "N/A";

  const parts = new Intl.DateTimeFormat("en-GB", {
    day: "numeric",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
    timeZone: "UTC",
  }).format(d);

  return `${parts} UTC`;
}

/** Date only, same unambiguous shape: `9 Feb 2026`. */
export function formatReportDateOnly(value: Date | string | null | undefined): string {
  if (!value) return "N/A";
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return "N/A";

  return new Intl.DateTimeFormat("en-GB", {
    day: "numeric",
    month: "short",
    year: "numeric",
    timeZone: "UTC",
  }).format(d);
}

/**
 * Thousands grouping that does not depend on the server's locale.
 *
 * Pinned to `en-US` because that is the grouping convention the rest of this
 * product's English output already assumes.
 */
export function formatCount(n: number): string {
  if (!Number.isFinite(n)) return "0";
  return n.toLocaleString("en-US");
}
