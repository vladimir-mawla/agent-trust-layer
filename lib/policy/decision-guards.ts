/**
 * Runtime shape validation for the `TrustDecision`/`HistoryTrustDecision`
 * values `evaluatePolicyRequest` receives as `authority`/`history` — the
 * counterpart, for THESE inputs, of what `validate.ts` already does for
 * `policy`.
 *
 * ## Why this exists (L4 M5 review, FINDING 1)
 *
 * `engine.ts`'s `authority`/`history` parameters are typed
 * `TrustDecision<AuthorityCredential> | null` and `readonly
 * HistoryTrustDecision[]` — but a TypeScript parameter type only binds a
 * caller that goes through `tsc`. ADR 0004 itself says "claims arrive as
 * JSON, not TypeScript"; anything that crosses a real serialization
 * boundary (a queued message, a replayed fixture, a value that was
 * `any`/`unknown` two lines up the call stack) can reach this function
 * *looking like* a `TrustDecision` without ever having been produced by
 * `evaluateAuthorityCredentialTrust`/`evaluateHistoryAttestationTrust`.
 * Before this fix, `engine.ts` and `history-constraints.ts` assumed the
 * discriminant shape unconditionally (checking only for literal `null`)
 * and threw a bare, unhandled `TypeError` for anything else malformed —
 * the exact class of defect ("unhandled exception instead of a
 * structured refusal") that got M3 rejected.
 *
 * ## Scope: validate what's actually read, not full VC re-verification
 *
 * Every check below validates ONLY the fields `engine.ts` /
 * `history-constraints.ts` / `envelope.ts` / `permitted-scope.ts` actually
 * dereference — the same "validate what you use" scope `validate.ts`
 * applies to `Policy`, not full W3C VC Data Model conformance (that
 * already happened for real, inside `verifyAuthorityCredential`/
 * `verifyHistoryAttestation` — this module cannot and does not
 * re-verify a signature; it only makes sure a malformed IMPOSTOR of the
 * result type fails closed instead of crashing).
 *
 * ## Fail closed, never a new refusal kind
 *
 * Anything that fails these checks is treated EXACTLY as if it were
 * absent — `null` for `authority`, filtered out of `history` — never as
 * its own distinct `RefusalKind`, and never by throwing. See `engine.ts`'s
 * `GATE_AUTHORITY_REQUIRED` refusal and its module comment.
 */
import type { AuthorityCredential, HistoryAttestation } from "../credentials/index.js";
import type { HistoryTrustDecision, TrustDecision } from "../trust/index.js";

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

/**
 * The `credentialVerification: VerificationSuccess<C>` shape shared by
 * BOTH an accepted `TrustDecision` and an accepted `HistoryTrustDecision`
 * — validated once, parameterised over which `credentialSubject` shape
 * the caller actually reads afterwards (`AuthorityClaim` vs.
 * `HistoryClaim` — see `vc-types.ts`).
 */
function hasWellFormedVerificationSuccess(value: unknown, isWellFormedSubject: (subject: Record<string, unknown>) => boolean): boolean {
  if (!isPlainObject(value)) return false;
  if (!isNonEmptyString(value["verifiedIssuer"])) return false;
  const credential = value["credential"];
  if (!isPlainObject(credential)) return false;
  const credentialSubject = credential["credentialSubject"];
  if (!isPlainObject(credentialSubject)) return false;
  return isWellFormedSubject(credentialSubject);
}

function isAuthorityClaimShape(subject: Record<string, unknown>): boolean {
  return typeof subject["action"] === "string" && isPlainObject(subject["scope"]);
}

function isHistoryClaimShape(subject: Record<string, unknown>): boolean {
  return typeof subject["observationType"] === "string" && isPlainObject(subject["metrics"]);
}

/**
 * Validate the `accepted: true` variant shared by `TrustDecision` and
 * `HistoryTrustDecision` — the only fields `envelope.ts` /
 * `history-constraints.ts` / `engine.ts` ever read for an accepted
 * decision: `reason`, `credentialVerification.{verifiedIssuer,
 * credential.credentialSubject}`, and `revocation.outcome` (+
 * `revocation.reason` when unchecked).
 */
function isWellFormedAcceptedShape(value: Record<string, unknown>, isWellFormedSubject: (subject: Record<string, unknown>) => boolean): boolean {
  if (!isNonEmptyString(value["reason"])) return false;
  if (!hasWellFormedVerificationSuccess(value["credentialVerification"], isWellFormedSubject)) return false;
  const revocation = value["revocation"];
  if (!isPlainObject(revocation)) return false;
  if (revocation["outcome"] === "not-checked") {
    return isNonEmptyString(revocation["reason"]);
  }
  if (revocation["outcome"] === "active") {
    return true;
  }
  return false;
}

/**
 * Validate an `authority` value as a well-formed
 * `TrustDecision<AuthorityCredential>`. Every branch mirrors one arm of
 * `engine.ts`'s own gate logic, so that if THIS returns `true`, none of
 * that logic's property accesses can throw.
 */
export function isWellFormedAuthorityTrustDecision(value: unknown): value is TrustDecision<AuthorityCredential> {
  if (!isPlainObject(value)) return false;
  const accepted = value["accepted"];

  if (accepted === true) {
    return isWellFormedAcceptedShape(value, isAuthorityClaimShape);
  }

  if (accepted === false) {
    if (!isNonEmptyString(value["reason"])) return false;
    const stage = value["stage"];
    if (stage === "credential-verification") {
      const credentialVerification = value["credentialVerification"];
      return isPlainObject(credentialVerification) && isNonEmptyString(credentialVerification["step"]) && isNonEmptyString(credentialVerification["reason"]);
    }
    if (stage === "issuer-trust") {
      const issuerTrust = value["issuerTrust"];
      if (!isPlainObject(issuerTrust) || issuerTrust["trusted"] !== false) return false;
      const reason = issuerTrust["reason"];
      return isPlainObject(reason) && isNonEmptyString(reason["kind"]);
    }
    if (stage === "revocation") {
      const revocation = value["revocation"];
      return isPlainObject(revocation) && (revocation["outcome"] === "revoked" || revocation["outcome"] === "indeterminate");
    }
    // Unrecognised `stage` — fail closed rather than assuming (as
    // `engine.ts` used to) that anything which isn't
    // "credential-verification"/"issuer-trust" must be "revocation".
    return false;
  }

  return false;
}

/**
 * Validate one `history` array entry as a well-formed
 * `HistoryTrustDecision`. The `accepted: false` variants are checked only
 * loosely: `history-constraints.ts` skips any `!decision.accepted` entry
 * outright (never dereferences its nested fields), so this only needs to
 * reject obvious garbage wearing an `accepted: false` costume.
 */
export function isWellFormedHistoryTrustDecision(value: unknown): value is HistoryTrustDecision {
  if (!isPlainObject(value)) return false;
  const accepted = value["accepted"];

  if (accepted === true) {
    return isWellFormedAcceptedShape(value, isHistoryClaimShape);
  }

  if (accepted === false) {
    return isNonEmptyString(value["reason"]) && (value["stage"] === "credential-verification" || value["stage"] === "revocation");
  }

  return false;
}

export type AuthorityInputCheck =
  | { readonly kind: "absent" }
  | { readonly kind: "malformed"; readonly detail: string }
  | { readonly kind: "well-formed"; readonly decision: TrustDecision<AuthorityCredential> };

/**
 * Normalize `evaluatePolicyRequest`'s raw `authority` input. `null` is
 * "absent" (a caller who genuinely has no authority credential to
 * present); anything else that isn't a well-formed `TrustDecision` is
 * "malformed" — worth naming distinctly in an explanation's evidence —
 * but `engine.ts` treats both identically for the purposes of the
 * accept/refuse decision: fail closed under `GATE_AUTHORITY_REQUIRED`.
 */
export function checkAuthorityInput(authority: unknown): AuthorityInputCheck {
  if (authority === null) {
    return { kind: "absent" };
  }
  if (isWellFormedAuthorityTrustDecision(authority)) {
    return { kind: "well-formed", decision: authority };
  }
  if (isPlainObject(authority)) {
    return {
      kind: "malformed",
      detail: `does not match any TrustDecision variant (accepted=${JSON.stringify(authority["accepted"])}, stage=${JSON.stringify(authority["stage"])})`,
    };
  }
  return { kind: "malformed", detail: `expected an object (or null), got ${Array.isArray(authority) ? "array" : typeof authority}` };
}

/**
 * Normalize `evaluatePolicyRequest`'s raw `history` input: a non-array
 * value is treated as "no history attestations were presented" (never a
 * thrown error), and any array entry that is not a well-formed
 * `HistoryTrustDecision` (`null` included) is silently dropped — exactly
 * the same "an unverifiable observation contributes no constraint"
 * posture `history-constraints.ts`'s own module comment already
 * documents for an entry that failed ITS OWN verification; garbage that
 * never was one is treated no differently.
 */
export function sanitizeHistoryInput(history: unknown): readonly HistoryTrustDecision[] {
  if (!Array.isArray(history)) {
    return [];
  }
  return history.filter(isWellFormedHistoryTrustDecision);
}
