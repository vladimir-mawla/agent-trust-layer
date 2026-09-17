/**
 * TIGHTEN_NEVER_LOOSEN, part 3: combining every source of a numeric
 * bound on one scope field into a single permitted ceiling, using
 * `Math.min` and ONLY `Math.min` — never `Math.max`, never "last one
 * wins", never an override. Three sources can name a bound for a field:
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
 * `narrowedMax`.
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

  // Strict minimum — see the module comment. `reduce` with no initial
  // value would throw on an empty array, which is why the length check
  // above runs first.
  return candidates.reduce((tightest, candidate) => (candidate.value < tightest.value ? candidate : tightest));
}
