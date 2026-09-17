/**
 * Public API of the policy module (M5): a declarative policy model,
 * evaluation over M4's verified `TrustDecision`/`HistoryTrustDecision`
 * results only, and a structured, machine-readable explanation for
 * every accept/refuse decision. See `engine.ts`'s module comment for how
 * `no-unverified-claim-reaches-policy` and "history may tighten a
 * decision but never loosen one" (ADR 0002) are both enforced
 * structurally here, not by convention.
 *
 * Framework-free by design, same as `lib/identity`, `lib/credentials`,
 * and `lib/trust` — nothing here may import from Next.js or React.
 * Fully synchronous: unlike `lib/trust`'s `checkRevocation`, nothing in
 * this module performs I/O — it only reasons over results `lib/trust`
 * already computed.
 */

export {
  ACTION_SCOPE_RULE_KIND,
  HISTORY_NARROW_RULE_KIND,
  type ComparisonOperator,
  type ActionScopeRule,
  type HistoryNarrowRule,
  type PolicyRule,
  type RevocationRequirement,
  type Policy,
  type PolicyRequest,
} from "./policy-types.js";

export { validatePolicy } from "./validate.js";

export { PolicyMalformedError, PolicyContradictionError, PolicyUnknownRuleTypeError, type PolicyDefinitionFailureKind, type PolicyDefinitionError } from "./errors.js";

export { computeAuthorityEnvelope, type AuthorityEnvelope } from "./envelope.js";
export { computeHistoryConstraints, type TriggeredHistoryConstraint } from "./history-constraints.js";
export { computeFieldBound, type FieldBound, type FieldBoundSource } from "./permitted-scope.js";

export {
  type RefusalKind,
  type RuleRef,
  type FieldEvidence,
  type ExplanationCaveat,
  type RevocationNotCheckedCaveat,
  type Explanation,
  fieldEvidence,
  permittedExplanation,
  refusedExplanation,
  renderExplanation,
  GATE_AUTHORITY_REQUIRED,
  GATE_CREDENTIAL_VERIFICATION,
  GATE_ISSUER_TRUST,
  GATE_REVOCATION,
  GATE_REVOCATION_UNCHECKED,
  GATE_ACTION_MATCH,
  GATE_NO_MATCHING_RULE,
  RULE_AUTHORITY_OWN_SCOPE,
} from "./explanation.js";

export { type ParseFailureRefinement, refineParseFailure, describeParseFailureRefinement } from "./verification-step-detail.js";

export { evaluatePolicyRequest, type EvaluatePolicyRequestInput, type PolicyDecision } from "./engine.js";
