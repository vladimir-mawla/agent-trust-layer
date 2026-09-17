/**
 * The composition root of M5: turn a `Policy` (declarative, authored
 * data — `policy-types.ts`), a `PolicyRequest` (what a counterparty
 * wants to do), and M4's own verified `TrustDecision`/`HistoryTrustDecision`
 * results into one explainable `PolicyDecision`.
 *
 * ## `no-unverified-claim-reaches-policy`, made structural — for a
 * TypeScript caller, and made to FAIL CLOSED for everyone else
 *
 * `evaluatePolicyRequest`'s `authority` parameter is typed
 * `TrustDecision<AuthorityCredential> | null` and `history` is typed
 * `readonly HistoryTrustDecision[]` — never `string`, never a bare JWT.
 * There is no code path in this module that calls
 * `verifyAuthorityCredential`/`verifyHistoryAttestation` itself, or that
 * accepts a raw credential and verifies it inline: the ONLY way to
 * produce a `TrustDecision`/`HistoryTrustDecision` is to actually run
 * `lib/trust`'s `evaluateAuthorityCredentialTrust`/
 * `evaluateHistoryAttestationTrust`, which themselves can only be
 * produced by running M3's real verification chain first (see those
 * modules' own comments).
 *
 * That is true, and useful, ONLY for a caller who goes through `tsc` and
 * never casts. ADR 0004 itself says claims arrive as JSON, not
 * TypeScript — a value crossing a real serialization boundary (a queued
 * message, a replayed fixture, anything that was `any`/`unknown` a few
 * lines up the call stack) can reach this function *looking like* a
 * `TrustDecision` without being one, and a bare type annotation cannot
 * stop that. `decision-guards.ts`'s `checkAuthorityInput`/
 * `sanitizeHistoryInput` are the runtime boundary that makes the "cannot
 * accidentally hand this engine something unverified" property hold for
 * THOSE callers too: anything that isn't a well-formed
 * `TrustDecision`/`HistoryTrustDecision` is treated exactly as if it
 * were absent — fail closed, and always as a structured
 * `PolicyDecision`, never a thrown `TypeError` (see FINDING 1, L4 M5
 * review — this is the same class of defect that got M3 rejected: an
 * unhandled exception instead of a structured refusal).
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
import { computeFieldBound, type FieldBound } from "./permitted-scope.js";
import { checkAuthorityInput, sanitizeHistoryInput } from "./decision-guards.js";
import { readScopeField } from "./safe-scope-read.js";
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

/** `"over-scope"` for every bound source except a triggered history
 *  constraint, which always gets its own, more specific, refusal kind —
 *  see the existing over-scope/history-constraint split below. Shared by
 *  both the ordinary comparison branch and FINDING 4's
 *  omitted-bounded-field branch and FINDING 3/8's non-finite-bound
 *  branch, so all three name the refusal the same way. */
function boundRefusalKind(bound: FieldBound): Parameters<typeof refusedExplanation>[0] {
  return bound.source.kind === "history-constraint" ? "history-constraint" : "over-scope";
}

function describeBoundSource(bound: FieldBound): string {
  switch (bound.source.kind) {
    case "authority-credential":
      return "the credential's own scope";
    case "policy-rule":
      return `policy rule ${bound.rule.ruleId}`;
    case "history-constraint":
      return `history attestation from ${bound.source.attestationIssuer} (metric value ${bound.source.metricValue}) via rule "${bound.rule.ruleId}"`;
  }
}

export function evaluatePolicyRequest(input: EvaluatePolicyRequestInput): PolicyDecision {
  const policy: Policy = validatePolicy(input.policy);
  const { request } = input;

  // --- FINDING 1: `authority`/`history` are typed as trusted decisions,
  //     but a value crossing a real boundary (not `tsc`) can arrive
  //     looking like one without being one. Normalize BOTH before any
  //     property of either is ever read, so nothing below this line can
  //     throw a bare TypeError for a malformed decision — see
  //     `decision-guards.ts` and this module's own comment. -------------
  const history = sanitizeHistoryInput(input.history);
  const authorityCheck = checkAuthorityInput(input.authority);

  // --- Gate: an authority credential is always required -------------
  if (authorityCheck.kind !== "well-formed") {
    const narrative =
      authorityCheck.kind === "absent"
        ? `no authority credential was presented at all for action "${request.action}"; ${history.length} history attestation(s) were present but history alone can never grant authority (ADR 0002)`
        : `the "authority" input was not a well-formed trust decision (${authorityCheck.detail}); a malformed or unrecognised decision is treated exactly as if no authority credential had been presented at all for action "${request.action}" — fail closed, never a thrown error (FINDING 1)`;
    return refuse(
      "no-authority-credential",
      GATE_AUTHORITY_REQUIRED,
      fieldEvidence("authority", { requested: request.action, permitted: null, ...(authorityCheck.kind === "malformed" ? { note: authorityCheck.detail } : {}) }),
      narrative,
    );
  }
  const authority = authorityCheck.decision;

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

  // --- FINDING 4: evaluate every field that ANY source (the credential's
  //     own scope, the matching policy rule's ceiling, or a triggered
  //     history constraint) actually names a bound for — not merely the
  //     fields the REQUEST happens to mention. `computeFieldBound(field,
  //     ...)` only ever finds a bound for a field named by one of those
  //     three sources, so `boundedFields` below is exactly the set of
  //     fields this engine can, and must, check. Iterating
  //     `request.scope`'s own keys instead (as this loop used to) let a
  //     counterparty omit exactly the field it would be limited on and
  //     receive an unconditional permit, because a field the loop never
  //     visited was never checked at all — the credential's own granted
  //     ceiling was never even consulted. See ADR 0004 for why "omitted"
  //     is read as "unbounded, refuse" rather than "zero usage, permit". */
  const boundedFields = new Set<string>();
  for (const [field, value] of Object.entries(envelope.scope)) {
    if (typeof value === "number") boundedFields.add(field);
  }
  for (const field of Object.keys(matchingRule.maxScope)) {
    boundedFields.add(field);
  }
  for (const constraint of triggered) {
    boundedFields.add(constraint.rule.scopeField);
  }

  for (const field of boundedFields) {
    const bound = computeFieldBound(field, envelope, matchingRule, triggered);
    if (bound === null) {
      // Cannot actually happen — `boundedFields` is derived from exactly
      // the sources `computeFieldBound` consults — kept as a defensive
      // `continue` rather than a non-null assertion.
      continue;
    }

    // FIX (L4 M6 review, critical): `request.scope` is untrusted data
    // that never passes through `validatePolicy` (only `policy` does) —
    // unlike `envelope.scope`/`matchingRule.maxScope`, which are both
    // rebuilt from JSON-parsed/validated data and therefore cannot carry
    // a getter, a Proxy, or a throwing accessor. A hostile `scope` CAN.
    // `readScopeField` reads defensively so a throwing own/inherited
    // getter, or a Proxy trap that throws, resolves to `threw: true`
    // rather than propagating out of this function (and, through
    // `Supplier.evaluatePresentation`, out as an unhandled rejection —
    // the same defect class that got M3 rejected once already).
    const scopeRead = readScopeField(request.scope, field);
    const requestedRaw = scopeRead.value;
    if (typeof requestedRaw !== "number") {
      // FINDING 4: a field this engine knows a bound for, but the
      // request never supplied a numeric value for (omitted entirely, or
      // present with a non-numeric value). Treated as an UNBOUNDED,
      // unverifiable request for that dimension, refused fail-closed —
      // never silently read as "0 / not requested, therefore fine",
      // which is exactly the reading that let a counterparty bypass the
      // credential's own ceiling by simply not naming the field.
      return refuse(
        boundRefusalKind(bound),
        bound.rule,
        fieldEvidence(`scope.${field}`, {
          permitted: bound.value,
          note: scopeRead.threw
            ? "reading this field off the request threw (a hostile getter/Proxy trap) — treated as unreadable, exactly like an omitted field, never as an exception"
            : scopeRead.present
              ? "present in the request but not a number"
              : "omitted from the request entirely",
        }),
        `"${field}" is bounded to a maximum of ${bound.value} (source: ${describeBoundSource(bound)}), but the request did not supply a numeric value for it; an omitted-but-bounded field is refused, never treated as an implicit zero or as escaping the bound (FINDING 4)`,
      );
    }
    const requestedValue = requestedRaw;

    if (!Number.isFinite(requestedValue)) {
      // FINDING 8 (M5's defense of an M3 gap: M3 never validates that a
      // credential's own `scope` values are finite, so a hand-crafted
      // JWT can carry a real `Infinity`/`NaN`). A non-finite REQUESTED
      // value can never be verified as within any ceiling — refused,
      // never compared.
      return refuse(
        "over-scope",
        bound.rule,
        fieldEvidence(`scope.${field}`, { requested: requestedValue, permitted: bound.value, note: "requested value is not a finite number" }),
        `requested "${field}" = ${requestedValue} is not a finite number; a non-finite requested value is always refused, never compared against a ceiling (FINDING 8)`,
      );
    }
    // FIX (M7 exploratory attack suite finding, 2026-09-17): a negative
    // REQUESTED value was, before this fix, compared against the ceiling
    // exactly like any other value — `-500000 > 500` is `false`, so it
    // was PERMITTED, identically to a small in-range positive request.
    // That is a real authorization gap, not a curiosity: every bound
    // this engine understands (the credential's own scope value, an
    // `ActionScopeRule.maxScope` ceiling, a triggered
    // `HistoryNarrowRule.narrowedMax`) is a `maxX`-style CEILING —
    // `permitted-scope.ts`'s own module comment and ADR 0004 both frame
    // every one of them that way. None of them is a signed range or a
    // lower bound, and the semantics of "a negative request against a
    // maximum" are simply undefined by this policy language — reading
    // `-500000 <= 500` as "safely within scope" treats arithmetic
    // truth as if it were domain truth. For the domains this engine's
    // own examples model (a purchase, a transfer, a refund amount), a
    // negative value is not "a smaller version of the same request" —
    // it is a REVERSAL, the opposite direction from whatever the
    // ceiling was authored to bound. So "authority to spend up to 500"
    // must never silently double as "authority to move 500,000 in the
    // other direction" just because no rule happened to name a floor.
    // The universally-correct fix, GIVEN THE SHAPE OF EVERY BOUND THIS
    // ENGINE HAS, is: a requested numeric value must be non-negative,
    // full stop — checked BEFORE it is ever compared to a ceiling, the
    // same posture already taken one guard above for a non-finite
    // requested value (both are "a number this engine cannot safely
    // bound", just for a different reason: unmeasurable vs.
    // wrong-direction). This is deliberately the NARROW fix, not the
    // general one: a policy language able to express a genuine lower
    // bound (a `minScope` ceiling-from-below) or a true signed range
    // (e.g. "a refund between -1000 and 0 is fine, but nothing past
    // that") would be strictly more expressive, and is NOT built here —
    // seeing this as "the" answer rather than "a" answer would be the
    // same mistake, one level up, that this fix itself is closing. See
    // ADR 0004's amendment for the full record.
    //
    // Zero is explicitly EXCLUDED from this refusal: `0 < 0` is `false`,
    // so a request of exactly `0` for a bounded field is permitted, same
    // as before — a zero-usage request is harmless, and refusing it
    // would be over-reach this fix has no mandate for. `-0` also passes
    // (`-0 < 0` is `false` too) — a deliberate, not merely incidental,
    // decision: `-0` and `0` are the same real-world magnitude, and
    // treating them differently would be exactly the kind of sign-only
    // technicality this fix is trying to eliminate, not add.
    if (requestedValue < 0) {
      return refuse(
        "negative-scope-value",
        bound.rule,
        fieldEvidence(`scope.${field}`, { requested: requestedValue, permitted: bound.value, note: "requested value is negative" }),
        `requested "${field}" = ${requestedValue} is negative; the permitted ceiling for this field (source: ${describeBoundSource(bound)}, maximum ${bound.value}) is a maximum-style bound whose semantics are undefined for a negative request, so it is refused distinctly as "negative-scope-value" rather than compared against the ceiling as if it were merely a very small request (M7 exploratory attack suite finding)`,
      );
    }

    if (!Number.isFinite(bound.value)) {
      // FINDING 3 / FINDING 8: a non-finite BOUND — `NaN` from an
      // adversarial candidate (real `Math.min` poisons to `NaN` if ANY
      // candidate is non-finite — see `permitted-scope.ts`), or
      // `Infinity` smuggled through an authority credential's own
      // unvalidated scope value — must refuse, never permit.
      // `requested > NaN` and `requested > Infinity` (for any finite
      // requested value) both evaluate to `false`, which a naive
      // comparison would read as "never over scope" — i.e. an
      // unconditional permit. Checked explicitly, ahead of that
      // comparison, so a non-finite ceiling can never be mistaken for an
      // unbounded permit.
      return refuse(
        boundRefusalKind(bound),
        bound.rule,
        fieldEvidence(`scope.${field}`, { requested: requestedValue, permitted: bound.value, note: "the permitted ceiling itself is not a finite number" }),
        `the permitted ceiling for "${field}" (source: ${describeBoundSource(bound)}) is not a finite number (${String(bound.value)}); a non-finite ceiling always refuses rather than being treated as unbounded permission (FINDING 3 / FINDING 8)`,
      );
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
        `requested "${field}" = ${requestedValue} exceeds the permitted maximum of ${bound.value} (source: ${describeBoundSource(bound)})`,
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
