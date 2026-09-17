/**
 * The composition root of M5: turn a `Policy` (declarative, authored
 * data — `policy-types.ts`), a `PolicyRequest` (what a counterparty
 * wants to do), and M4's own verified `TrustDecision`/`HistoryTrustDecision`
 * results into one explainable `PolicyDecision`.
 *
 * ## `no-unverified-claim-reaches-policy`, made structural
 *
 * `evaluatePolicyRequest`'s `authority` parameter is typed
 * `TrustDecision<AuthorityCredential> | null` and `history` is typed
 * `readonly HistoryTrustDecision[]` — never `string`, never `unknown`,
 * never a bare JWT. There is no code path in this module that calls
 * `verifyAuthorityCredential`/`verifyHistoryAttestation` itself, or that
 * accepts a raw credential and verifies it inline: the ONLY way to
 * produce a `TrustDecision`/`HistoryTrustDecision` is to actually run
 * `lib/trust`'s `evaluateAuthorityCredentialTrust`/
 * `evaluateHistoryAttestationTrust`, which themselves can only be
 * produced by running M3's real verification chain first (see those
 * modules' own comments). A caller cannot "accidentally" hand this
 * engine something unverified and have it type-check.
 *
 * ## TIGHTEN_NEVER_LOOSEN, tied together
 *
 * `computeAuthorityEnvelope` (`envelope.ts`) is called ONLY when
 * `authority !== null && authority.accepted === true` — i.e. only after
 * a real, verified, trusted, non-revoked (or explicitly-accepted-
 * unchecked) authority credential exists. History
 * (`history-constraints.ts` + `permitted-scope.ts`) is consulted only
 * AFTER that envelope already exists, and only ever narrows it via
 * `Math.min`. If `authority` is `null` — including when `history` is
 * non-empty — this function refuses under `GATE_AUTHORITY_REQUIRED`
 * before any envelope is ever computed, which is exactly how "history
 * attestations present but no authority -> still refused" holds: there
 * is no code path in which history alone produces a permit.
 *
 * ## The mandatory revocation gate
 *
 * `authority.revocation.outcome === "not-checked"` is the exact gap
 * `lib/trust/trust-decision.ts`'s own warning comment names as
 * "M5's problem". This engine closes it by consulting
 * `policy.revocationHandling` (`RevocationRequirement` — see
 * `policy-types.ts`): the default, and the only value that requires no
 * extra justification to write, REFUSES an unchecked credential
 * (`"revocation-not-checked"`); a policy may only permit one through by
 * supplying `{ requireChecked: false, acknowledgedBy, reason }`, and
 * doing so is recorded as an explicit `caveats` entry on the resulting
 * PERMIT, never silently folded into an ordinary "accepted" explanation.
 *
 * ## Malformed policies are configuration errors, not refusals
 *
 * `evaluatePolicyRequest` calls `validatePolicy` on its `policy` input
 * every time, and lets `PolicyDefinitionError` propagate rather than
 * catching it — a broken policy is a bug in how this engine was
 * configured, and reporting it as an ordinary `PolicyDecision` refusal
 * would make a misconfigured policy indistinguishable from a policy
 * correctly refusing a real request. Every other failure mode in this
 * function is caught and turned into a structured `PolicyDecision` —
 * nothing throws an unhandled error for a REQUEST-shaped problem, only
 * for a POLICY-shaped one.
 */
import type { Did } from "../identity/index.js";
import type { AuthorityCredential } from "../credentials/index.js";
import type { HistoryTrustDecision, TrustDecision } from "../trust/index.js";
import {
  ACTION_SCOPE_RULE_KIND,
  HISTORY_NARROW_RULE_KIND,
  type ActionScopeRule,
  type Policy,
  type PolicyRequest,
} from "./policy-types.js";
import { validatePolicy } from "./validate.js";
import { computeAuthorityEnvelope, type AuthorityEnvelope } from "./envelope.js";
import { computeHistoryConstraints } from "./history-constraints.js";
import { computeFieldBound } from "./permitted-scope.js";
import {
  GATE_ACTION_MATCH,
  GATE_AUTHORITY_REQUIRED,
  GATE_CREDENTIAL_VERIFICATION,
  GATE_ISSUER_TRUST,
  GATE_NO_MATCHING_RULE,
  GATE_REVOCATION,
  GATE_REVOCATION_UNCHECKED,
  fieldEvidence,
  permittedExplanation,
  refusedExplanation,
  type Explanation,
  type ExplanationCaveat,
} from "./explanation.js";
import { describeParseFailureRefinement, refineParseFailure } from "./verification-step-detail.js";

/**
 * `explanation`'s type is deliberately tied to `permitted` via
 * `Extract<Explanation, { outcome: ... }>` in EACH branch, not the bare
 * `Explanation` union in both: this is what lets a caller's own
 * `if (!decision.permitted) throw ...`-style narrowing (the same idiom
 * `lib/trust`'s own tests use on `TrustDecision`) narrow
 * `decision.explanation.refusalKind` into scope too, instead of leaving
 * it typed as "might be the permitted variant" even after `permitted`
 * itself has been checked.
 */
export type PolicyDecision =
  | { readonly permitted: true; readonly explanation: Extract<Explanation, { readonly outcome: "permitted" }>; readonly envelope: AuthorityEnvelope }
  | { readonly permitted: false; readonly explanation: Extract<Explanation, { readonly outcome: "refused" }> };

export interface EvaluatePolicyRequestInput {
  /** Untrusted data (see `validate.ts`) — re-validated on every call. */
  readonly policy: unknown;
  readonly request: PolicyRequest;
  /** The M4 result for the presented authority credential, or `null` if
   *  none was presented at all. Never a raw JWT — see the module
   *  comment. */
  readonly authority: TrustDecision<AuthorityCredential> | null;
  /** The M4 results for whatever history attestations accompanied the
   *  request. Unverified/failed entries are ignored (never treated as
   *  a fatal error) — see `history-constraints.ts`. */
  readonly history: readonly HistoryTrustDecision[];
}

function permit(rule: { readonly ruleId: string; readonly description: string }, field: ReturnType<typeof fieldEvidence>, narrative: string, envelope: AuthorityEnvelope, caveats: readonly ExplanationCaveat[]): PolicyDecision {
  return { permitted: true, explanation: permittedExplanation(rule, field, narrative, caveats), envelope };
}

function refuse(kind: Parameters<typeof refusedExplanation>[0], rule: { readonly ruleId: string; readonly description: string }, field: ReturnType<typeof fieldEvidence>, narrative: string): PolicyDecision {
  return { permitted: false, explanation: refusedExplanation(kind, rule, field, narrative) };
}

function isActionScopeRule(rule: { readonly kind: string }): rule is ActionScopeRule {
  return rule.kind === ACTION_SCOPE_RULE_KIND;
}

export function evaluatePolicyRequest(input: EvaluatePolicyRequestInput): PolicyDecision {
  const policy: Policy = validatePolicy(input.policy);
  const { request, authority, history } = input;

  // --- Gate: an authority credential is always required -------------
  if (authority === null) {
    return refuse(
      "no-authority-credential",
      GATE_AUTHORITY_REQUIRED,
      fieldEvidence("authority", { requested: request.action, permitted: null }),
      `no authority credential was presented at all for action "${request.action}"; ${history.length} history attestation(s) were present but history alone can never grant authority (ADR 0002)`,
    );
  }

  // --- Gate: the presented authority credential must itself be accepted by M4
  if (!authority.accepted) {
    if (authority.stage === "credential-verification") {
      const refinement = refineParseFailure(authority.credentialVerification.step, authority.credentialVerification.reason);
      const note = describeParseFailureRefinement(refinement);
      return refuse(
        "credential-verification-failed",
        GATE_CREDENTIAL_VERIFICATION,
        fieldEvidence(`credentialVerification.step:${authority.credentialVerification.step}`, {
          actual: authority.credentialVerification.reason,
          ...(note !== undefined ? { note } : {}),
        }),
        authority.reason,
      );
    }
    if (authority.stage === "issuer-trust") {
      return refuse(
        "untrusted-issuer",
        GATE_ISSUER_TRUST,
        fieldEvidence("issuerTrust.reason.kind", { actual: authority.issuerTrust.reason.kind }),
        authority.reason,
      );
    }
    // authority.stage === "revocation"
    return refuse(
      "revoked",
      GATE_REVOCATION,
      fieldEvidence("revocation.outcome", { actual: authority.revocation.outcome }),
      authority.reason,
    );
  }

  // --- Gate: revocation must have been checked, unless the POLICY (not
  //     the caller of this one function) explicitly opted in ----------
  const revocation = authority.revocation;
  const caveats: ExplanationCaveat[] = [];
  if (revocation.outcome === "not-checked") {
    if (policy.revocationHandling.requireChecked) {
      return refuse(
        "revocation-not-checked",
        GATE_REVOCATION_UNCHECKED,
        fieldEvidence("revocation.outcome", { actual: "not-checked" }),
        `revocation was never checked for this credential (${revocation.reason}), and policy "${policy.id}" v${policy.version} requires it to be checked by default — refusing rather than silently treating an unchecked credential as clean`,
      );
    }
    caveats.push({
      kind: "revocation-not-checked-accepted",
      acknowledgedBy: policy.revocationHandling.acknowledgedBy,
      reason: policy.revocationHandling.reason,
    });
  }

  const envelope = computeAuthorityEnvelope(authority);

  // --- Wrong action, distinct from over-scope ------------------------
  if (request.action !== envelope.action) {
    return refuse(
      "wrong-action",
      GATE_ACTION_MATCH,
      fieldEvidence("credentialSubject.action", { requested: request.action, permitted: envelope.action }),
      `the presented authority credential grants action "${envelope.action}", not the requested "${request.action}"`,
    );
  }

  const matchingRule = policy.rules.find((rule) => isActionScopeRule(rule) && rule.action === envelope.action) as ActionScopeRule | undefined;
  if (matchingRule === undefined) {
    return refuse(
      "no-matching-rule",
      GATE_NO_MATCHING_RULE,
      fieldEvidence("policy.rules", { requested: envelope.action, permitted: null }),
      `policy "${policy.id}" v${policy.version} has no "action-scope" rule governing action "${envelope.action}"`,
    );
  }

  const historyRules = policy.rules.filter((rule) => rule.kind === HISTORY_NARROW_RULE_KIND);
  const triggered = computeHistoryConstraints(historyRules, envelope.action, history);

  for (const [field, requestedValue] of Object.entries(request.scope)) {
    if (typeof requestedValue !== "number") {
      // Non-numeric scope dimensions are out of scope for this
      // milestone's bound-checking — see DELIBERATE_OMISSIONS in the M5
      // report. Not silently ignored forever: it is simply not a field
      // this engine's numeric-ceiling mechanism can evaluate.
      continue;
    }
    const bound = computeFieldBound(field, envelope, matchingRule, triggered);
    if (bound === null) {
      continue;
    }
    if (requestedValue > bound.value) {
      if (bound.source.kind === "history-constraint") {
        return refuse(
          "history-constraint",
          bound.rule,
          fieldEvidence(`scope.${field}`, { requested: requestedValue, permitted: bound.value }),
          `history attestation from ${bound.source.attestationIssuer} (metric value ${bound.source.metricValue}) triggered constraint "${bound.rule.ruleId}" (${bound.rule.description}), narrowing "${field}" to a maximum of ${bound.value}; requested ${requestedValue} exceeds it`,
        );
      }
      return refuse(
        "over-scope",
        bound.rule,
        fieldEvidence(`scope.${field}`, { requested: requestedValue, permitted: bound.value }),
        `requested "${field}" = ${requestedValue} exceeds the permitted maximum of ${bound.value} (source: ${bound.source.kind === "authority-credential" ? "the credential's own scope" : "policy rule " + bound.rule.ruleId})`,
      );
    }
  }

  return permit(
    { ruleId: matchingRule.id, description: matchingRule.description },
    fieldEvidence("credentialSubject.action", { requested: request.action, permitted: envelope.action }),
    `action "${envelope.action}" permitted under rule "${matchingRule.id}"; issuer ${envelope.issuer}; ${
      revocation.outcome === "active" ? "revocation checked and clean" : `revocation not checked (accepted per policy: ${revocation.reason})`
    }`,
    envelope,
    caveats,
  );
}

export type { Did };
