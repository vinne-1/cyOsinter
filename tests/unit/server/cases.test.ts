import { describe, it, expect } from "vitest";
import { CASE_TRANSITIONS, isValidCaseTransition } from "../../../server/case-workflow";

/**
 * The lifecycle is the part worth pinning: it decides what an analyst is allowed
 * to do next, and a wrong edge either blocks legitimate work or lets a case skip
 * the states that make the audit trail meaningful.
 */

describe("case lifecycle", () => {
  it("moves forward through the expected states", () => {
    expect(isValidCaseTransition("open", "investigating")).toBe(true);
    expect(isValidCaseTransition("investigating", "contained")).toBe(true);
    expect(isValidCaseTransition("contained", "resolved")).toBe(true);
    expect(isValidCaseTransition("resolved", "closed")).toBe(true);
  });

  it("allows reopening a closed case", () => {
    // A remediation that did not hold is a normal outcome, not an exception.
    expect(isValidCaseTransition("closed", "open")).toBe(true);
  });

  it("allows stepping back when an investigation reopens", () => {
    expect(isValidCaseTransition("contained", "investigating")).toBe(true);
    expect(isValidCaseTransition("resolved", "investigating")).toBe(true);
    expect(isValidCaseTransition("investigating", "open")).toBe(true);
  });

  it("refuses to skip straight from open to resolved", () => {
    // Jumping the middle states leaves no record that anyone looked at it.
    expect(isValidCaseTransition("open", "resolved")).toBe(false);
    expect(isValidCaseTransition("open", "contained")).toBe(false);
  });

  it("refuses to reopen a closed case into a mid-lifecycle state", () => {
    expect(isValidCaseTransition("closed", "contained")).toBe(false);
    expect(isValidCaseTransition("closed", "resolved")).toBe(false);
  });

  it("treats a no-op transition as valid", () => {
    // A PATCH that resends the current status must not fail.
    for (const state of Object.keys(CASE_TRANSITIONS)) {
      expect(isValidCaseTransition(state, state)).toBe(true);
    }
  });

  it("rejects an unknown source state", () => {
    expect(isValidCaseTransition("not-a-state", "open")).toBe(false);
  });

  it("lets any active state be closed directly", () => {
    // Abandoning work must always be possible, whatever state it is in.
    for (const state of ["open", "investigating", "contained", "resolved"]) {
      expect(isValidCaseTransition(state, "closed")).toBe(true);
    }
  });

  it("has no state that is a dead end", () => {
    for (const [state, targets] of Object.entries(CASE_TRANSITIONS)) {
      expect(targets.length, `${state} has no outgoing transitions`).toBeGreaterThan(0);
    }
  });

  it("never lists a state as a transition to itself", () => {
    for (const [state, targets] of Object.entries(CASE_TRANSITIONS)) {
      expect(targets).not.toContain(state);
    }
  });

  it("only names states that exist", () => {
    const known = new Set(Object.keys(CASE_TRANSITIONS));
    for (const targets of Object.values(CASE_TRANSITIONS)) {
      for (const t of targets) expect(known.has(t)).toBe(true);
    }
  });

  it("can reach every state from open", () => {
    // Breadth-first: an unreachable state would be dead configuration.
    const seen = new Set(["open"]);
    const queue = ["open"];
    while (queue.length) {
      for (const next of CASE_TRANSITIONS[queue.shift()!] ?? []) {
        if (!seen.has(next)) { seen.add(next); queue.push(next); }
      }
    }
    expect(seen.size).toBe(Object.keys(CASE_TRANSITIONS).length);
  });
});
