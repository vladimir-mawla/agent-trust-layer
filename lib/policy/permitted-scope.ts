/**
 * TIGHTEN_NEVER_LOOSEN, part 3: combining every source of a numeric
 * bound on one scope field into a single permitted ceiling, using the
 * real, literal `Math.min` — never `Math.max`, never "last one wins",
 * never an override. Three sources can name a bound for a field:
 *
 *   1. the authority credential's OWN scope value (`RULE_AUTHORITY_OWN_SCOPE`)
 *   2. a policy-authored `ActionScopeRule.maxScope` ceiling
 *   3. a triggered `HistoryNarrowRule` (see `history-constraints.ts`)
 *
 * Because the combinator is a strict minimum over whichever of these
 * are present, a history-sourced bound can only ever REDUCE the
 * effective ceiling below what the credential + policy already allow —
 * setting a `narrowedMax` above the existing ceiling has, and can only
 * ever have, zero effect. This is the arithmetic half of
 * TIGHTEN_NEVER_LOOSEN; `envelope.ts`'s doc comment is the gating half
 * (history can't even be consulted without an accepted authority
 * credential already producing an envelope). `type-boundary.test.ts`
 * exercises this arithmetic at runtime with a deliberately-oversized
 * `narrowedMax`, and `permitted-scope.test.ts` exercises it with
 * fixtures where the tightest bound is deliberately NOT the first
 * candidate (see FINDING 2, L4 M5 review — a hand-rolled `reduce` with a
 * `<` comparison used to sit here, and happened to agree with `Math.min`
 * on every fixture that existed at the time, entirely by chance: mutating
 * it to `return candidates[0]` broke only 1 of 196 tests).
 *
 * ## Why the REAL `Math.min`, not a hand-rolled reduce (FINDING 3)
 *
 * ADR 0004 and this module both used to claim "`Math.min`, exclusively"
 * while the implementation was actually
 * `candidates.reduce((tightest, c) => (c.value < tightest.value ? c : tightest))`
 * — a DIFFERENT function with different semantics for non-finite values:
 * `Math.min(500, NaN)` is always `NaN` (poisons unconditionally), whereas
 * that reduce only returns `NaN` when `NaN` happens to be the FIRST
 * candidate — for any other position, `c.value < tightest.value` is
 * `false` for a `NaN` `c.value`, so the reduce silently keeps the
 * previous (finite, but not actually tighter) candidate and DISCARDS a
 * genuinely non-finite bound instead of surfacing it. Prose and code
 * disagreed, so now they agree: this uses the real `Math.min`, and its
 * NaN-poisoning is the deliberate, safer behaviour — poisoning to `NaN`
 * and then REFUSING (a non-finite bound must never be compared with `>`
 * and read as "nothing is over scope" — see `engine.ts`'s explicit
 * `Number.isFinite` check on the returned `FieldBound.value`, FINDING 3 /
 * FINDING 8) is fail-closed, where silently dropping a tighter ceiling
 * would not have been.
 */
import type { Did } from "../identity/index.js";
import type { ActionScopeRule } from "./policy-types.js";
import type { RuleRef } from "./explanation.js";
import { RULE_AUTHORITY_OWN_SCOPE } from "./explanation.js";
import type { TriggeredHistoryConstraint } from "./history-constraints.js";
import type { AuthorityEnvelope } from "./envelope.js";

export type FieldBoundSource =
  | { readonly kind: "authority-credential" }
  | { readonly kind: "policy-rule" }
  | { readonly kind: "history-constraint"; readonly attestationIssuer: Did; readonly metricValue: number };

export interface FieldBound {
  readonly value: number;
  readonly rule: RuleRef;
  readonly source: FieldBoundSource;
}

/**
 * Compute the tightest (minimum) bound on `field` across every source
 * that names one, or `null` if no source constrains this field at all
 * (in which case the engine does not check it — see DELIBERATE_OMISSIONS
 * in the M5 report on scope fields with no numeric bound anywhere).
 */
export function computeFieldBound(
  field: string,
  envelope: AuthorityEnvelope,
  actionScopeRule: ActionScopeRule,
  triggeredHistoryConstraints: readonly TriggeredHistoryConstraint[],
): FieldBound | null {
  const candidates: FieldBound[] = [];

  const envelopeValue = envelope.scope[field];
  if (typeof envelopeValue === "number") {
    candidates.push({ value: envelopeValue, rule: RULE_AUTHORITY_OWN_SCOPE, source: { kind: "authority-credential" } });
  }

  const policyValue = actionScopeRule.maxScope[field];
  if (typeof policyValue === "number") {
    candidates.push({
      value: policyValue,
      rule: { ruleId: actionScopeRule.id, description: actionScopeRule.description },
      source: { kind: "policy-rule" },
    });
  }

  for (const triggered of triggeredHistoryConstraints) {
    if (triggered.rule.scopeField !== field) {
      continue;
    }
    candidates.push({
      value: triggered.rule.narrowedMax,
      rule: { ruleId: triggered.rule.id, description: triggered.rule.description },
      source: { kind: "history-constraint", attestationIssuer: triggered.attestationIssuer, metricValue: triggered.metricValue },
    });
  }

  if (candidates.length === 0) {
    return null;
  }

  // The real, literal `Math.min` — see the module comment (FINDING 3).
  // `Math.min(...)` on an empty array would be `Infinity`, which is why
  // the length check above runs first; with at least one candidate,
  // `minValue` is either a real finite tightest value, or `NaN` if ANY
  // candidate is non-finite.
  const minValue = Math.min(...candidates.map((candidate) => candidate.value));

  // `candidates.length > 0` was already checked above, so `candidates[0]`
  // is a guaranteed, real fallback here — never reached in practice
  // (every branch below is exhaustive over how `Math.min` could have
  // produced `minValue`), just defensive against `noUncheckedIndexedAccess`.
  const first = candidates[0] as FieldBound;

  if (Number.isNaN(minValue)) {
    // `Math.min` poisons to `NaN` the instant any candidate is `NaN` —
    // no candidate's `value === NaN` (NaN never equals anything, itself
    // included), so attribute this to whichever candidate actually IS
    // non-finite, so the explanation names the real offending source
    // rather than an arbitrary one.
    return candidates.find((candidate) => !Number.isFinite(candidate.value)) ?? first;
  }

  return candidates.find((candidate) => candidate.value === minValue) ?? first;
}
