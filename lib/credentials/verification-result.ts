/**
 * Structured verification results. Every check in `verify.ts` returns one
 * of these — never a `boolean`, and never a bare parsed credential either.
 *
 * This is where the context graph's two invariants become concrete types
 * rather than prose:
 *
 *   - `every-decision-is-explainable`: a `VerificationFailure` always
 *     names `step` (which check failed) and `reason` (why); there is no
 *     code path that produces a failure with neither.
 *   - `no-unverified-claim-reaches-policy`: M5's policy engine (not built
 *     yet) is expected to accept only a `VerificationSuccess<C>` — a
 *     type that can only be produced by `verify.ts` actually running the
 *     full chain. There is no constructor for one anywhere else, and (as
 *     with `jws.ts`'s `SignatureVerified`) nothing about the shape lets a
 *     caller fabricate one by hand and have it pass a structural check —
 *     policy code that type-guards on `result.ok === true` before
 *     touching `result.credential` is, by construction, incapable of
 *     "accidentally" accepting a credential nothing verified.
 */
import type { Did } from "../identity/index.js";
import type { VerificationStep } from "./errors.js";
import type { AnyCredential } from "./vc-types.js";

export interface VerificationFailure {
  readonly ok: false;
  /** Which step of the chain rejected the credential — see
   *  `VerificationStep` in `errors.ts` for the full ordered list. */
  readonly step: VerificationStep;
  /** Human-readable reason, always naming the specific field or check
   *  involved (never just "invalid"). */
  readonly reason: string;
  /** The typed error this wraps, for callers that want `instanceof`. */
  readonly cause?: unknown;
}

/**
 * `ok: true` means the credential is internally consistent and
 * correctly signed — NOT that the issuer is trustworthy. Nothing in M3
 * vets who is allowed to issue what; `verifiedIssuer` below is exactly
 * who cryptographically signed the credential, which could be anyone
 * who can generate an Ed25519 keypair. Deciding whether that issuer
 * should be believed is M4's job (trust anchors / issuer vetting) — see
 * the module comment's `no-unverified-claim-reaches-policy` note, which
 * is about M5 trusting `verify.ts`'s output, not about `verify.ts`
 * itself vouching for the issuer's trustworthiness.
 */
export interface VerificationSuccess<C extends AnyCredential> {
  readonly ok: true;
  /** The verified credential. Safe to read every field of — reaching
   *  this point means signature, structure, temporal validity, subject
   *  binding, and issuer identity have ALL passed. */
  readonly credential: C;
  /** The issuer's DID, recovered from — and confirmed to match — the key
   *  that produced the signature (not merely copied from the credential's
   *  own `issuer` field: `verify.ts`'s issuer-identity step is exactly
   *  the check that these agree). This is proof the named issuer signed
   *  the credential, NOT that the named issuer is trusted or vetted —
   *  see this interface's own doc comment. */
  readonly verifiedIssuer: Did;
  /** The presenter's DID, established by `lib/identity`'s
   *  `verifyPossession` — i.e. cryptographically proven, not merely
   *  copied from `credentialSubject.id`. Equal to `credential.credentialSubject.id`
   *  by construction (that equality IS the subject-binding check). */
  readonly verifiedSubject: Did;
  readonly verifiedAt: number;
  /**
   * Named, deliberately-unimplemented seam for M4. This is always `false`
   * in M3 — typed as the literal `false`, not `boolean`, specifically so
   * that no code anywhere in this module can accidentally report a
   * credential as revocation-checked when nothing has actually consulted
   * a revocation list. M4 is expected to widen this to `boolean` (or a
   * richer status type) as part of actually implementing revocation —
   * that widening is itself the signal that the seam has been filled in,
   * rather than a silent behavior change hiding in an already-`boolean`
   * field.
   */
  readonly revocationChecked: false;
}

export type VerificationResult<C extends AnyCredential> = VerificationSuccess<C> | VerificationFailure;

/** Type guard for narrowing a `VerificationResult` to its success case. */
export function isVerified<C extends AnyCredential>(
  result: VerificationResult<C>,
): result is VerificationSuccess<C> {
  return result.ok;
}
