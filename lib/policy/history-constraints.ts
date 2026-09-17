/**
 * TIGHTEN_NEVER_LOOSEN, part 2: computing which `HistoryNarrowRule`s
 * actually fire for a given action, from VERIFIED history alone.
 *
 * This module's return type, `TriggeredHistoryConstraint`, has no field
 * that could express a grant — it carries `narrowedMax` (a ceiling to
 * intersect with, via `Math.min`, in `permitted-scope.ts`) and nothing
 * resembling a lower bound, an "allow" flag, or a scope key not already
 * present on the authority envelope it will be applied to. Combined with
 * `permitted-scope.ts` only ever combining bounds with `Math.min`, a
 * `HistoryNarrowRule` cannot widen an envelope even if a policy author
 * sets `narrowedMax` to `Infinity` — the runtime half of the
 * TIGHTEN_NEVER_LOOSEN proof in `type-boundary.test.ts` exercises
 * exactly that.
 *
 * Only ACCEPTED history decisions are consulted (`decision.accepted ===
 * true`, i.e. already passed M3's verification chain — no bare/raw
 * claim reaches here, honouring `no-unverified-claim-reaches-policy`
 * for history the same way `engine.ts` honours it for authority). A
 * history attestation that failed its own verification is simply
 * skipped, never treated as a fatal error for the whole request: an
 * unverifiable OBSERVATION doesn't invalidate an otherwise-good,
 * separately-verified authority credential, it just contributes no
 * constraint — the same "one bad candidate doesn't sink the whole
 * evaluation" posture `lib/trust/anchors.ts` documents for vouches.
 */
import type { Did } from "../identity/index.js";
import type { HistoryTrustDecision } from "../trust/index.js";
import type { ComparisonOperator, HistoryNarrowRule } from "./policy-types.js";

export interface TriggeredHistoryConstraint {
  readonly rule: HistoryNarrowRule;
  readonly attestationIssuer: Did;
  readonly metricValue: number;
}

function compare(operator: ComparisonOperator, value: number, threshold: number): boolean {
  switch (operator) {
    case "lte":
      return value <= threshold;
    case "lt":
      return value < threshold;
    case "gte":
      return value >= threshold;
    case "gt":
      return value > threshold;
    case "eq":
      return value === threshold;
  }
}

/**
 * Evaluate every `HistoryNarrowRule` governing `action` against every
 * verified, accepted entry in `history`, returning one
 * `TriggeredHistoryConstraint` per (rule, attestation) pair whose
 * `metric`/`operator`/`threshold` condition holds. A rule that never
 * matches any attestation (wrong `observationType`, metric missing or
 * non-numeric, condition not met) contributes nothing — narrowing a
 * ceiling is opt-in per matching observation, never assumed.
 */
export function computeHistoryConstraints(
  rules: readonly HistoryNarrowRule[],
  action: string,
  history: readonly HistoryTrustDecision[],
): readonly TriggeredHistoryConstraint[] {
  const triggered: TriggeredHistoryConstraint[] = [];

  for (const rule of rules) {
    if (rule.action !== action) {
      continue;
    }
    for (const decision of history) {
      if (!decision.accepted) {
        continue;
      }
      const claim = decision.credentialVerification.credential.credentialSubject;
      if (claim.observationType !== rule.observationType) {
        continue;
      }
      const metricValue = claim.metrics[rule.metric];
      if (typeof metricValue !== "number") {
        continue;
      }
      if (!compare(rule.operator, metricValue, rule.threshold)) {
        continue;
      }
      triggered.push({ rule, attestationIssuer: decision.credentialVerification.verifiedIssuer, metricValue });
    }
  }

  return triggered;
}
