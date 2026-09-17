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
 *
 * ## FIX 5(a) (L4 M5 RE-verification, non-blocking follow-up): a
 * throwing property read is malformed input too
 *
 * The checks below were themselves written as ordinary property
 * access (`value["accepted"]`, `credential["credentialSubject"]`, …),
 * on the reasoning that `authority`/`history` are JSON — and
 * `JSON.parse` cannot produce a getter, a `Proxy`, or any other
 * accessor that could make a plain property READ throw. That reasoning
 * is correct for a value that actually crossed a JSON boundary, but
 * this module's whole point is that nothing downstream can assume that
 * happened: an ADVERSARIAL IN-PROCESS CALLER (never a JSON parser) can
 * still construct an object with a throwing getter, or a `Proxy` whose
 * `get`/`ownKeys`/`getOwnPropertyDescriptor` traps throw, and hand it
 * to `evaluatePolicyRequest` directly. The re-verification judged this
 * non-blocking (exactly because it requires an in-process caller, not a
 * value that merely crossed JSON), but the fix is the same "never
 * throw for untrusted input" posture this whole module already
 * promises, just one property-read layer down. `isWellFormedAuthorityTrustDecision`/
 * `isWellFormedHistoryTrustDecision` now each wrap their entire body in
 * a `try`/`catch` that treats ANY thrown error — at any depth, own
 * property or inherited, from `value` itself or from a nested
 * `credential`/`credentialSubject`/`revocation`/`issuerTrust` object —
 * as "not well-formed", the same fail-closed outcome an ordinary
 * shape mismatch already produces. `sanitizeHistoryInput` additionally
 * guards its OWN array walk (`history.length`, `history[i]`) the same
 * way, since a `Proxy` wrapping a real array can make even INDEXING
 * into it throw, before the per-entry predicate is ever called.
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
 *
 * The entire body runs inside a `try`/`catch` (FIX 5(a)) — see this
 * module's own comment on why a plain property read here is not
 * guaranteed safe just because `authority` is "supposed to be" JSON.
 */
export function isWellFormedAuthorityTrustDecision(value: unknown): value is TrustDecision<AuthorityCredential> {
  try {
    return isWellFormedAuthorityTrustDecisionUnguarded(value);
  } catch {
    return false;
  }
}

function isWellFormedAuthorityTrustDecisionUnguarded(value: unknown): value is TrustDecision<AuthorityCredential> {
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
 *
 * The entire body runs inside a `try`/`catch` (FIX 5(a)) — same
 * reasoning as `isWellFormedAuthorityTrustDecision` above: this predicate
 * is also called from `sanitizeHistoryInput`'s array walk, where one
 * hostile entry must never take down the whole `history` array.
 */
export function isWellFormedHistoryTrustDecision(value: unknown): value is HistoryTrustDecision {
  try {
    return isWellFormedHistoryTrustDecisionUnguarded(value);
  } catch {
    return false;
  }
}

function isWellFormedHistoryTrustDecisionUnguarded(value: unknown): value is HistoryTrustDecision {
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
    // FIX 5(a): reading `accepted`/`stage` back out for the detail
    // message is itself a plain property read on untrusted `authority`
    // — guarded the same way as the shape checks above, so a hostile
    // getter/Proxy can make this diagnostic vaguer but never throw.
    try {
      return {
        kind: "malformed",
        detail: `does not match any TrustDecision variant (accepted=${JSON.stringify(authority["accepted"])}, stage=${JSON.stringify(authority["stage"])})`,
      };
    } catch {
      return {
        kind: "malformed",
        detail: "does not match any TrustDecision variant, and its own \"accepted\"/\"stage\" fields could not be read safely (a throwing accessor)",
      };
    }
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
  // FIX 5(a): guard the ARRAY WALK itself, not merely the per-entry
  // predicate. `Array.isArray` returns `true` for a `Proxy` wrapping a
  // real array too, and such a Proxy's `get` trap can make reading
  // `.length` or an individual index throw — before
  // `isWellFormedHistoryTrustDecision` (itself already guarded above)
  // is ever called for that entry. A plain `history.filter(...)` would
  // let that throw escape from `Array.prototype.filter`'s own internal
  // indexing, taking down the whole call.
  let length: number;
  try {
    length = history.length;
  } catch {
    return [];
  }
  const out: HistoryTrustDecision[] = [];
  for (let index = 0; index < length; index++) {
    let entry: unknown;
    try {
      entry = history[index];
    } catch {
      // This one index is unreadable — treated exactly like an entry
      // that failed shape validation: dropped, never fatal to the rest
      // of the walk.
      continue;
    }
    if (isWellFormedHistoryTrustDecision(entry)) {
      out.push(entry);
    }
  }
  return out;
}
