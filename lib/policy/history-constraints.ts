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
 *
 * ## FINDING 6 (L4 M5 review): the mandatory revocation gate deliberately
 * does NOT apply here
 *
 * `engine.ts`'s `GATE_REVOCATION_UNCHECKED` gate — refusing an authority
 * credential whose `revocation.outcome === "not-checked"`, unless
 * `policy.revocationHandling.requireChecked === false` — is checked ONLY
 * for the `authority` decision, never for a `HistoryTrustDecision`: an
 * accepted history attestation whose revocation was never checked
 * narrows a ceiling exactly like one that was checked and clean (this
 * function does not even look at `decision.revocation` at all).
 *
 * This is a deliberate choice, not an oversight, and it is NOT the same
 * risk as the authority gap `GATE_REVOCATION_UNCHECKED` closes. The
 * authority gate exists because an unchecked-but-actually-revoked
 * authority credential being treated as clean would GRANT something
 * that should have been refused — a real widening of what's permitted.
 * History can only ever narrow (`permitted-scope.ts`'s `Math.min`, and
 * `HistoryNarrowRule` has no field that could express a grant — see
 * `policy-types.ts`): the worst an unchecked-and-actually-revoked
 * history attestation could do is contribute a narrowing that, in
 * hindsight, shouldn't have been trusted — REFUSING a request that a
 * fully-vetted history would have permitted. That is a false negative
 * (a request wrongly narrowed/refused), never a false positive (nothing
 * is ever granted because of it) — the opposite of the failure mode
 * `GATE_REVOCATION_UNCHECKED` exists to prevent. Extending that gate to
 * history would trade a real safety property (fail-closed: an
 * unverifiable narrowing still narrows) for a cosmetic symmetry with the
 * authority path, at the cost of becoming MORE permissive whenever a
 * history attestation's revocation happens not to have been checked —
 * exactly backwards for an engine whose whole point is tighten-never-
 * loosen. See `history-constraints.test.ts` for a test asserting this
 * explicitly (an unchecked-revocation history attestation narrows a
 * ceiling identically to a checked-and-clean one).
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
