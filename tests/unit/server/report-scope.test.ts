/**
 * Which findings belong in a report.
 *
 * This rule was open-coded in three independent deliverable paths — the JSON
 * content, the DOCX assembler, and the CSV/XLSX export route — and all three
 * got the same half of it wrong: "everything" meant every ROW rather than every
 * finding. A client's export listed "DNSSEC Detection" and "security.txt File"
 * (protections that are WORKING) and "robots.txt file" (a technology fact)
 * under a summary reading *"This report covers 14 security findings"* when four
 * of them were.
 *
 * They were found one at a time, each fix revealing the next copy. The tests
 * that matter here are the two halves of the asymmetry, because getting either
 * backwards is silent: too many rows overstates the client's exposure, too few
 * drops findings an operator deliberately chose.
 */
import { describe, it, expect } from "vitest";

import { selectReportFindings } from "../../../server/report-scope";

const f = (id: string, kind?: string | null) => ({ id, kind, title: id });

const ALL = [
  f("sec-1", "security"),
  f("sec-2"),                 // legacy row, no kind
  f("ctl-1", "control"),
  f("rec-1", "recon"),
  f("sec-3", "security"),
];

describe("selectReportFindings", () => {
  it("includes only security findings when no selection is given", () => {
    const out = selectReportFindings(ALL, undefined).map((x) => x.id);
    expect(out).toEqual(["sec-1", "sec-2", "sec-3"]);
  });

  it("treats an empty selection the same as none", () => {
    expect(selectReportFindings(ALL, []).map((x) => x.id)).toEqual(["sec-1", "sec-2", "sec-3"]);
  });

  /**
   * A row written before the `kind` column existed has no value, and dropping
   * those would silently shrink every historical report.
   */
  it("keeps a legacy row with no kind", () => {
    expect(selectReportFindings([f("legacy")], undefined)).toHaveLength(1);
    expect(selectReportFindings([f("legacy", null)], undefined)).toHaveLength(1);
  });

  /**
   * The other half of the asymmetry. An operator who picked specific rows has
   * made a decision — including a control as evidence that something IS
   * configured is a legitimate thing to put in a report — and filtering it back
   * out would quietly disobey them.
   */
  it("honours an explicit selection exactly, including non-security rows", () => {
    const out = selectReportFindings(ALL, ["ctl-1", "rec-1"]).map((x) => x.id);
    expect(out).toEqual(["ctl-1", "rec-1"]);
  });

  it("ignores selected ids that do not exist rather than inventing rows", () => {
    const out = selectReportFindings(ALL, ["sec-1", "does-not-exist"]).map((x) => x.id);
    expect(out).toEqual(["sec-1"]);
  });

  it("preserves the input order", () => {
    const out = selectReportFindings(ALL, ["sec-3", "sec-1"]).map((x) => x.id);
    expect(out).toEqual(["sec-1", "sec-3"]);
  });

  it("returns nothing for an empty workspace", () => {
    expect(selectReportFindings([], undefined)).toEqual([]);
    expect(selectReportFindings([], ["anything"])).toEqual([]);
  });
});
