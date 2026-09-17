/**
 * Unit-level coverage of `computeFieldBound`'s tighten-never-loosen
 * combinator, added for FINDING 2 (L4 M5 review).
 *
 * Before this file existed, mutating `computeFieldBound` to
 * `return candidates[0]` (discarding the tightest-bound logic entirely)
 * broke only 1 of 196 tests — and NOT the dedicated
 * `type-boundary.test.ts` proof, because in that fixture the correct
 * answer happens to be the first candidate pushed (the credential's own
 * scope), so returning the first candidate passed by coincidence.
 * Tighten-never-loosen is the entire reason this milestone exists; these
 * fixtures make it true by TEST, not by chance — covering each of the
 * three bound sources (the credential's own scope, a policy
 * `ActionScopeRule.maxScope` ceiling, a triggered
 * `HistoryNarrowRule`) being the tightest in turn, in fixtures where the
 * tightest bound is deliberately NOT the first candidate
 * `computeFieldBound` pushes (which is always: credential scope, then
 * policy ceiling, then triggered history constraints, in that order).
 */
import { describe, expect, it } from "vitest";
import type { Did } from "../identity/index.js";
import { computeFieldBound } from "./permitted-scope.js";
import type { AuthorityEnvelope } from "./envelope.js";
import type { ActionScopeRule, HistoryNarrowRule } from "./policy-types.js";
import { ACTION_SCOPE_RULE_KIND, HISTORY_NARROW_RULE_KIND } from "./policy-types.js";
import type { TriggeredHistoryConstraint } from "./history-constraints.js";

const ISSUER: Did = "did:key:z6MkissuerFixtureDidNotARealKey000000000001" as Did;
const ATTESTER: Did = "did:key:z6MkattesterFixtureDidNotARealKey00000000001" as Did;

function envelope(scope: Record<string, number>): AuthorityEnvelope {
  return { action: "purchase", scope, issuer: ISSUER };
}

function actionScopeRule(maxScope: Record<string, number>): ActionScopeRule {
  return { kind: ACTION_SCOPE_RULE_KIND, id: "R-policy", description: "policy ceiling", action: "purchase", maxScope };
}

function historyRule(overrides: Partial<HistoryNarrowRule> = {}): HistoryNarrowRule {
  return {
    kind: HISTORY_NARROW_RULE_KIND,
    id: "R-history",
    description: "history narrowing",
    action: "purchase",
    observationType: "disputes-observed",
    metric: "disputeCount",
    operator: "gte",
    threshold: 1,
    scopeField: "maxAmount",
    narrowedMax: 100,
    ...overrides,
  };
}

function triggeredFrom(rule: HistoryNarrowRule, metricValue = 5): TriggeredHistoryConstraint {
  return { rule, attestationIssuer: ATTESTER, metricValue };
}

describe("computeFieldBound — tighten-never-loosen, mutation-resistant fixtures (FINDING 2)", () => {
  it("returns null when nothing bounds the field", () => {
    expect(computeFieldBound("maxAmount", envelope({}), actionScopeRule({}), [])).toBeNull();
  });

  it("the credential's own scope is tightest, and it IS the first candidate (baseline / sanity check)", () => {
    const bound = computeFieldBound("maxAmount", envelope({ maxAmount: 100 }), actionScopeRule({ maxAmount: 500 }), [triggeredFrom(historyRule({ narrowedMax: 1_000 }))]);
    expect(bound?.value).toBe(100);
    expect(bound?.source.kind).toBe("authority-credential");
  });

  it("the POLICY ceiling is tightest, even though it is pushed SECOND (not first) — a `candidates[0]` mutation would wrongly return the credential's own (looser) scope", () => {
    const bound = computeFieldBound("maxAmount", envelope({ maxAmount: 1_000 }), actionScopeRule({ maxAmount: 200 }), []);
    expect(bound?.value).toBe(200);
    expect(bound?.source.kind).toBe("policy-rule");
  });

  it("a TRIGGERED HISTORY constraint is tightest, even though it is pushed LAST — a `candidates[0]` mutation would wrongly return the credential's own (looser) scope", () => {
    const triggered = [triggeredFrom(historyRule({ narrowedMax: 50 }))];
    const bound = computeFieldBound("maxAmount", envelope({ maxAmount: 1_000 }), actionScopeRule({}), triggered);
    expect(bound?.value).toBe(50);
    expect(bound?.source.kind).toBe("history-constraint");
  });

  it("a triggered history constraint is tightest among THREE candidates, with the policy ceiling in between", () => {
    const triggered = [triggeredFrom(historyRule({ narrowedMax: 25 }))];
    const bound = computeFieldBound("maxAmount", envelope({ maxAmount: 1_000 }), actionScopeRule({ maxAmount: 300 }), triggered);
    expect(bound?.value).toBe(25);
    expect(bound?.source.kind).toBe("history-constraint");
  });

  it("the POLICY ceiling is tightest among THREE candidates (middle position, not first or last) — a `candidates[0]` mutation would wrongly return the credential's own scope", () => {
    const triggered = [triggeredFrom(historyRule({ narrowedMax: 900 }))];
    const bound = computeFieldBound("maxAmount", envelope({ maxAmount: 1_000 }), actionScopeRule({ maxAmount: 150 }), triggered);
    expect(bound?.value).toBe(150);
    expect(bound?.source.kind).toBe("policy-rule");
  });

  it("multiple triggered history constraints on the same field: the tightest of THEM wins too, regardless of trigger order", () => {
    const triggered = [triggeredFrom(historyRule({ id: "R-h1", narrowedMax: 400 }), 1), triggeredFrom(historyRule({ id: "R-h2", narrowedMax: 60 }), 2), triggeredFrom(historyRule({ id: "R-h3", narrowedMax: 900 }), 3)];
    const bound = computeFieldBound("maxAmount", envelope({ maxAmount: 1_000 }), actionScopeRule({ maxAmount: 800 }), triggered);
    expect(bound?.value).toBe(60);
    expect(bound?.rule.ruleId).toBe("R-h2");
  });

  it("only the policy ceiling names the field at all (credential scope silent, no history) — still returns it", () => {
    const bound = computeFieldBound("maxCount", envelope({ maxAmount: 500 }), actionScopeRule({ maxCount: 10 }), []);
    expect(bound?.value).toBe(10);
    expect(bound?.source.kind).toBe("policy-rule");
  });

  it("a tie between the credential's own scope and the policy ceiling picks either (both equally tight, arithmetic is still `Math.min`)", () => {
    const bound = computeFieldBound("maxAmount", envelope({ maxAmount: 500 }), actionScopeRule({ maxAmount: 500 }), []);
    expect(bound?.value).toBe(500);
  });
});

describe("computeFieldBound — real Math.min semantics, incl. NaN poisoning (FINDING 3)", () => {
  it("uses literal Math.min: an out-of-order NaN candidate still poisons the result (a hand-rolled `<`-reduce would only poison if NaN were first)", () => {
    // The credential's own scope (pushed FIRST) is a real, finite 500;
    // a triggered history constraint (pushed LAST) is NaN. A `<`
    // comparison reduce keeps the finite 500 here (`NaN < 500` is
    // `false`), silently discarding the fact that one candidate was
    // non-finite. Real `Math.min(500, NaN)` is unconditionally `NaN`.
    const triggered = [triggeredFrom(historyRule({ narrowedMax: Number.NaN }))];
    const bound = computeFieldBound("maxAmount", envelope({ maxAmount: 500 }), actionScopeRule({}), triggered);
    expect(bound).not.toBeNull();
    expect(Number.isNaN(bound?.value)).toBe(true);
    // Attributed to the actual non-finite candidate, not an arbitrary one.
    expect(bound?.source.kind).toBe("history-constraint");
  });

  it("poisons to NaN even when the NaN candidate is pushed FIRST (credential's own scope)", () => {
    const bound = computeFieldBound("maxAmount", envelope({ maxAmount: Number.NaN }), actionScopeRule({ maxAmount: 500 }), []);
    expect(Number.isNaN(bound?.value)).toBe(true);
    expect(bound?.source.kind).toBe("authority-credential");
  });

  it("a non-finite (Infinity) credential scope value does not poison Math.min away, but is still reported as the bound when it is genuinely tightest is impossible — Infinity is never tightest, but is still surfaced when it's the ONLY candidate (FINDING 8: M3 does not validate scope-value finiteness)", () => {
    const bound = computeFieldBound("maxAmount", envelope({ maxAmount: Number.POSITIVE_INFINITY }), actionScopeRule({}), []);
    expect(bound).not.toBeNull();
    expect(bound?.value).toBe(Number.POSITIVE_INFINITY);
    expect(Number.isFinite(bound?.value)).toBe(false);
  });
});
