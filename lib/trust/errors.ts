/**
 * Typed error hierarchy for the trust module (M4), mirroring the pattern
 * `lib/identity/errors.ts` and `lib/credentials/errors.ts` established:
 * one distinct class per failure mode, never a bare `throw new
 * Error("...")`, so callers (and tests) can `instanceof`-check exactly
 * what went wrong.
 *
 * Every one of these is caught somewhere inside `lib/trust` and
 * re-packaged into a structured result (`RevocationStatus`,
 * `IssuerTrustResult`, `TrustDecision`) before it can reach a caller —
 * see each module's own comment for exactly where. None of these classes
 * is expected to ever propagate out of this package's public API as an
 * unhandled throw; if one does, that is the bug class M3 was rejected
 * for once (see ADR 0003), and every test in this module exists partly
 * to prove it doesn't happen here either.
 */

/** Ordered-ish grouping of revocation-check failure modes — not a single
 *  linear chain like `VerificationStep` (revocation has no fixed step
 *  order the way signature-then-structure-then-temporal does), but each
 *  value still names exactly one thing that can go wrong, for the same
 *  explainability reason. */
export type RevocationFailureKind =
  | "status-list-unavailable"
  | "status-list-malformed"
  | "status-list-signature-invalid"
  | "status-list-issuer-unresolvable"
  | "status-list-issuer-mismatch"
  | "status-list-stale"
  | "status-list-purpose-mismatch"
  | "bitstring-index-invalid";

/** The injected resolver threw or rejected, or returned something that
 *  isn't even a string. Per this module's fail-closed policy, this is
 *  treated identically to "revoked" by any caller that only wants an
 *  accept/refuse answer — but it is reported under its own kind so a
 *  caller that cares CAN tell "definitely revoked" apart from "could not
 *  check", which matters for triage even though both refuse the request. */
export class StatusListUnavailableError extends Error {
  override readonly name = "StatusListUnavailableError";
  readonly kind: RevocationFailureKind = "status-list-unavailable";

  constructor(
    readonly url: string,
    options?: { cause?: unknown },
  ) {
    super(`Status list unavailable at ${url}`, options);
  }
}

/** The resolved status list credential's JWS wire format, JSON payload,
 *  compressed bitstring, or VC shape (`@context`/`type`/`credentialSubject`)
 *  is not well-formed. Covers "malformed/garbage status list VC" from the
 *  M4 brief — never an unhandled `JSON.parse`/gunzip throw. */
export class StatusListMalformedError extends Error {
  override readonly name = "StatusListMalformedError";
  readonly kind: RevocationFailureKind = "status-list-malformed";

  constructor(
    readonly reason: string,
    options?: { cause?: unknown },
  ) {
    super(`Status list credential malformed: ${reason}`, options);
  }
}

/** The status list credential's signature does not verify against the
 *  public key recovered from its own claimed issuer. An unsigned or
 *  forged status list is worthless — see PART 1 of the M4 brief. */
export class StatusListSignatureInvalidError extends Error {
  override readonly name = "StatusListSignatureInvalidError";
  readonly kind: RevocationFailureKind = "status-list-signature-invalid";

  constructor(options?: { cause?: unknown }) {
    super("Status list credential signature verification failed", options);
  }
}

/**
 * The status list credential is internally self-consistent (its own
 * `issuer` claim matches the key that actually signed it — see
 * `StatusListMalformedError`'s sibling check in `status-list.ts`) but was
 * NOT issued by the identity the caller told `checkRevocation` to expect
 * — see that function's now-required `expectedIssuer` parameter. This is
 * precisely the vulnerability an L4 review found and required fixed: a
 * status list signed by ANY key (a throwaway, attacker-controlled
 * keypair included) previously passed every check as long as it was
 * self-consistent, because nothing tied it back to the credential whose
 * revocation it was supposed to speak for.
 */
export class StatusListIssuerMismatchError extends Error {
  override readonly name = "StatusListIssuerMismatchError";
  readonly kind: RevocationFailureKind = "status-list-issuer-mismatch";

  constructor(
    readonly expectedIssuer: string,
    readonly actualIssuer: string,
  ) {
    super(`Status list credential is issued by ${actualIssuer}, but the caller expected ${expectedIssuer} — refusing to accept a status list from an unexpected issuer`);
  }
}

/** The status list credential's `issuer` is not a well-formed `did:key`. */
export class StatusListIssuerUnresolvableError extends Error {
  override readonly name = "StatusListIssuerUnresolvableError";
  readonly kind: RevocationFailureKind = "status-list-issuer-unresolvable";

  constructor(
    readonly issuer: unknown,
    options?: { cause?: unknown },
  ) {
    super(`Status list credential "issuer" did not resolve to a usable did:key: ${JSON.stringify(issuer)}`, options);
  }
}

/**
 * The status list credential is older than the configured freshness
 * threshold (`maxStatusListAgeMs` — see `status-list.ts` for the default
 * and its reasoning). Revocation is a statement about *now*, and a stale
 * "everything looked fine a while ago" snapshot is not evidence about
 * now — see the module comment on the offline/network tension this
 * whole file exists to make explicit.
 */
export class StatusListStaleError extends Error {
  override readonly name = "StatusListStaleError";
  readonly kind: RevocationFailureKind = "status-list-stale";

  constructor(
    readonly issuedAtMs: number,
    readonly checkedAtMs: number,
    readonly maxAgeMs: number,
  ) {
    super(
      `Status list credential issued at ${new Date(issuedAtMs).toISOString()} is older than the ` +
        `${maxAgeMs}ms freshness threshold (checked at ${new Date(checkedAtMs).toISOString()})`,
    );
  }
}

/** The `credentialStatus` entry's `statusPurpose` does not match any
 *  `statusPurpose` the resolved status list credential actually carries
 *  (W3C Bitstring Status List v1.0 §8.1 step 3's matching requirement). */
export class StatusListPurposeMismatchError extends Error {
  override readonly name = "StatusListPurposeMismatchError";
  readonly kind: RevocationFailureKind = "status-list-purpose-mismatch";

  constructor(
    readonly expected: string,
    readonly actual: readonly string[],
  ) {
    super(`Expected statusPurpose "${expected}", status list declares [${actual.join(", ")}]`);
  }
}

/** `statusListIndex` (after multiplying by `statusSize`) is negative,
 *  non-integer, or beyond the decompressed bitstring's length. Always
 *  converted to a structured failure, never left to throw an unhandled
 *  `RangeError` out of an array index operation. */
export class BitstringIndexError extends Error {
  override readonly name = "BitstringIndexError";
  readonly kind: RevocationFailureKind = "bitstring-index-invalid";

  constructor(readonly reason: string) {
    super(`Invalid bitstring index: ${reason}`);
  }
}

/** Grouping type for anything a caller might want to `instanceof`-check
 *  across the whole "why couldn't revocation be confirmed" space. */
export type RevocationError =
  | StatusListUnavailableError
  | StatusListMalformedError
  | StatusListSignatureInvalidError
  | StatusListIssuerUnresolvableError
  | StatusListIssuerMismatchError
  | StatusListStaleError
  | StatusListPurposeMismatchError
  | BitstringIndexError;

// ---------------------------------------------------------------------
// Vouches (PART 3)
// ---------------------------------------------------------------------

export type VouchFailureKind = "vouch-malformed" | "vouch-signature-invalid" | "vouch-issuer-unresolvable" | "vouch-expired";

/** A vouch credential's wire format or VC shape is not well-formed. */
export class VouchMalformedError extends Error {
  override readonly name = "VouchMalformedError";
  readonly kind: VouchFailureKind = "vouch-malformed";

  constructor(
    readonly reason: string,
    options?: { cause?: unknown },
  ) {
    super(`Vouch malformed: ${reason}`, options);
  }
}

/** A vouch credential's signature does not verify against the public key
 *  recovered from its own claimed issuer (the would-be voucher). */
export class VouchSignatureInvalidError extends Error {
  override readonly name = "VouchSignatureInvalidError";
  readonly kind: VouchFailureKind = "vouch-signature-invalid";

  constructor(options?: { cause?: unknown }) {
    super("Vouch signature verification failed", options);
  }
}

/** A vouch's claimed issuer (the voucher) is not a well-formed `did:key`. */
export class VouchIssuerUnresolvableError extends Error {
  override readonly name = "VouchIssuerUnresolvableError";
  readonly kind: VouchFailureKind = "vouch-issuer-unresolvable";

  constructor(
    readonly issuer: unknown,
    options?: { cause?: unknown },
  ) {
    super(`Vouch "issuer" did not resolve to a usable did:key: ${JSON.stringify(issuer)}`, options);
  }
}

/** A vouch is being consulted after its `validUntil`. */
export class VouchExpiredError extends Error {
  override readonly name = "VouchExpiredError";
  readonly kind: VouchFailureKind = "vouch-expired";

  constructor(
    readonly validUntil: string,
    readonly checkedAt: number,
  ) {
    super(`Vouch expired at ${validUntil}, checked at ${new Date(checkedAt).toISOString()}`);
  }
}

// ---------------------------------------------------------------------
// Shared JWS-lite errors (see `jws-lite.ts`)
// ---------------------------------------------------------------------

/** Mirrors `lib/credentials/errors.ts`'s `AlgorithmNotAllowedError` for
 *  this module's own minimal JWS layer — see `jws-lite.ts`'s module
 *  comment for why this module has its own instead of importing that
 *  one directly. */
export class AlgorithmNotAllowedError extends Error {
  override readonly name = "AlgorithmNotAllowedError";

  constructor(readonly allegedAlg: unknown) {
    super(`Algorithm not allowed: expected "EdDSA", got ${JSON.stringify(allegedAlg)}`);
  }
}

/** Mirrors `lib/credentials/errors.ts`'s `SignatureVerificationFailedError`. */
export class SignatureVerificationFailedError extends Error {
  override readonly name = "SignatureVerificationFailedError";

  constructor() {
    super("JWS signature verification failed");
  }
}
