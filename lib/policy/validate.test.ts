import { describe, expect, it } from "vitest";
import { validatePolicy } from "./validate.js";
import { PolicyContradictionError, PolicyMalformedError, PolicyUnknownRuleTypeError } from "./errors.js";
import { ACTION_SCOPE_RULE_KIND, HISTORY_NARROW_RULE_KIND } from "./policy-types.js";

const VALID_POLICY = {
  id: "p1",
  version: "1.0.0",
  revocationHandling: { requireChecked: true },
  rules: [{ kind: ACTION_SCOPE_RULE_KIND, id: "R1", description: "purchase ceiling", action: "purchase", maxScope: { maxAmount: 500 } }],
};

describe("validatePolicy — malformed/empty policy", () => {
  it("accepts a well-formed policy and returns it typed", () => {
    const policy = validatePolicy(VALID_POLICY);
    expect(policy.id).toBe("p1");
    expect(policy.rules).toHaveLength(1);
  });

  it("throws PolicyMalformedError, never an unhandled error, for an empty object", () => {
    expect(() => validatePolicy({})).toThrow(PolicyMalformedError);
  });

  it("throws PolicyMalformedError for null", () => {
    expect(() => validatePolicy(null)).toThrow(PolicyMalformedError);
  });

  it("throws PolicyMalformedError for a bare string", () => {
    expect(() => validatePolicy("not a policy")).toThrow(PolicyMalformedError);
  });

  it("throws PolicyMalformedError when rules is missing", () => {
    const { rules, ...rest } = VALID_POLICY;
    void rules;
    expect(() => validatePolicy(rest)).toThrow(PolicyMalformedError);
  });

  it("throws PolicyMalformedError when rules is not an array", () => {
    expect(() => validatePolicy({ ...VALID_POLICY, rules: "nope" })).toThrow(PolicyMalformedError);
  });

  it("throws PolicyMalformedError when revocationHandling is missing", () => {
    const { revocationHandling, ...rest } = VALID_POLICY;
    void revocationHandling;
    expect(() => validatePolicy(rest)).toThrow(PolicyMalformedError);
  });

  it("throws PolicyMalformedError when revocationHandling opts out without justification", () => {
    expect(() => validatePolicy({ ...VALID_POLICY, revocationHandling: { requireChecked: false } })).toThrow(PolicyMalformedError);
  });

  it("does NOT throw for a policy with zero rules (a legitimate, fail-closed deny-everything policy)", () => {
    expect(() => validatePolicy({ ...VALID_POLICY, rules: [] })).not.toThrow();
  });

  it("throws PolicyMalformedError for a rule missing required fields", () => {
    expect(() => validatePolicy({ ...VALID_POLICY, rules: [{ kind: ACTION_SCOPE_RULE_KIND, id: "R1" }] })).toThrow(PolicyMalformedError);
  });

  it("throws PolicyMalformedError for a history-narrow rule with an invalid operator", () => {
    expect(() =>
      validatePolicy({
        ...VALID_POLICY,
        rules: [
          {
            kind: HISTORY_NARROW_RULE_KIND,
            id: "R2",
            description: "x",
            action: "purchase",
            observationType: "disputes-observed",
            metric: "disputeCount",
            operator: "not-a-real-operator",
            threshold: 1,
            scopeField: "maxAmount",
            narrowedMax: 100,
          },
        ],
      }),
    ).toThrow(PolicyMalformedError);
  });
});

describe("validatePolicy — contradictory rules", () => {
  it("throws PolicyContradictionError when two action-scope rules govern the same action", () => {
    expect(() =>
      validatePolicy({
        ...VALID_POLICY,
        rules: [
          { kind: ACTION_SCOPE_RULE_KIND, id: "R1", description: "first", action: "purchase", maxScope: { maxAmount: 500 } },
          { kind: ACTION_SCOPE_RULE_KIND, id: "R2", description: "second, contradicting", action: "purchase", maxScope: { maxAmount: 100 } },
        ],
      }),
    ).toThrow(PolicyContradictionError);
  });

  // FINDING 7 (L4 M5 review): a `ruleId` shared across rule KINDS — e.g.
  // an "action-scope" rule and an unrelated "history-narrow" rule both
  // named "R-shared" — used to slip through unnoticed entirely (the
  // duplicate-id check only ever compared action-scope rules governing
  // the SAME action). Any `Explanation` that later cites "R-shared"
  // would be ambiguous about which of the two rules actually fired.
  it("throws PolicyContradictionError when an action-scope rule and a history-narrow rule share the same ruleId", () => {
    expect(() =>
      validatePolicy({
        ...VALID_POLICY,
        rules: [
          { kind: ACTION_SCOPE_RULE_KIND, id: "R-shared", description: "purchase ceiling", action: "purchase", maxScope: { maxAmount: 500 } },
          {
            kind: HISTORY_NARROW_RULE_KIND,
            id: "R-shared",
            description: "narrows on disputes",
            action: "purchase",
            observationType: "disputes-observed",
            metric: "disputeCount",
            operator: "gte",
            threshold: 3,
            scopeField: "maxAmount",
            narrowedMax: 100,
          },
        ],
      }),
    ).toThrow(PolicyContradictionError);
  });

  it("throws PolicyContradictionError when two history-narrow rules for DIFFERENT actions share the same ruleId", () => {
    expect(() =>
      validatePolicy({
        ...VALID_POLICY,
        rules: [
          { kind: ACTION_SCOPE_RULE_KIND, id: "R1", description: "purchase ceiling", action: "purchase", maxScope: { maxAmount: 500 } },
          {
            kind: HISTORY_NARROW_RULE_KIND,
            id: "R-dup",
            description: "narrows purchase on disputes",
            action: "purchase",
            observationType: "disputes-observed",
            metric: "disputeCount",
            operator: "gte",
            threshold: 3,
            scopeField: "maxAmount",
            narrowedMax: 100,
          },
          {
            kind: HISTORY_NARROW_RULE_KIND,
            id: "R-dup",
            description: "narrows a different action entirely",
            action: "refund",
            observationType: "disputes-observed",
            metric: "disputeCount",
            operator: "gte",
            threshold: 3,
            scopeField: "maxAmount",
            narrowedMax: 100,
          },
        ],
      }),
    ).toThrow(PolicyContradictionError);
  });
});

describe("validatePolicy — unknown rule type", () => {
  it("throws PolicyUnknownRuleTypeError for an unrecognised rule kind", () => {
    expect(() => validatePolicy({ ...VALID_POLICY, rules: [{ kind: "some-future-rule-kind", id: "R9" }] })).toThrow(PolicyUnknownRuleTypeError);
  });
});
