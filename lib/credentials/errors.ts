/**
 * Typed error hierarchy for the credentials module, mirroring the pattern
 * `lib/identity/errors.ts` established: one distinct class per failure
 * mode, never a bare `throw new Error("...")`, so callers (and tests) can
 * `instanceof`-check exactly what went wrong rather than parsing a string.
 *
 * The classes below are grouped by which step of the verification chain
 * (see `verify.ts`) throws them. That grouping IS `VerificationStep` —
 * every one of these errors is caught by `verify.ts` and re-packaged into
 * a `VerificationFailure` naming the step, so the structured result and
 * the thrown-error hierarchy always agree on vocabulary.
 */

/**
 * Ordered step names for the credential verification chain. `"parse"` and
 * `"signature"` both run before any credential content is trusted;
 * everything from `"structure"` onward runs only after the signature has
 * verified. `"revocation"` is deliberately NOT a member of this union —
 * see `verify.ts`'s `revocationChecked` field for why.
 */
export type VerificationStep =
  | "parse"
  | "signature"
  | "structure"
  | "temporal"
  | "subject-binding"
  | "issuer-identity";

/**
 * The JWT compact serialisation itself is malformed: wrong segment count,
 * an empty segment, a segment that isn't valid base64url, an oversized
 * token, or a header segment that isn't a well-formed JSON object. None
 * of this requires trusting anything the credential *claims* — it's
 * purely about whether the wire format can be parsed at all.
 */
export class MalformedJwsError extends Error {
  override readonly name = "MalformedJwsError";
  readonly step: VerificationStep = "parse";

  constructor(
    readonly reason: string,
    options?: { cause?: unknown },
  ) {
    super(`Malformed JWS: ${reason}`, options);
  }
}

/**
 * The JWS header named an algorithm this verifier does not accept — most
 * importantly `"none"`, or any non-`EdDSA` algorithm. Thrown even when a
 * signature-shaped value IS present, because the defense here is refusing
 * to let the token's own header pick which algorithm decides its fate
 * (the classic "alg confusion" family of attacks), not merely rejecting
 * `alg: "none"` as a special case.
 */
export class AlgorithmNotAllowedError extends Error {
  override readonly name = "AlgorithmNotAllowedError";
  readonly step: VerificationStep = "signature";

  constructor(readonly allegedAlg: unknown) {
    super(`Algorithm not allowed: expected "EdDSA", got ${JSON.stringify(allegedAlg)}`);
  }
}

/** The JWS header's `kid` did not resolve to a usable issuer `did:key`. */
export class UnresolvableSigningKeyError extends Error {
  override readonly name = "UnresolvableSigningKeyError";
  readonly step: VerificationStep = "signature";

  constructor(
    readonly kid: unknown,
    options?: { cause?: unknown },
  ) {
    super(`JWS "kid" did not resolve to a usable did:key: ${JSON.stringify(kid)}`, options);
  }
}

/**
 * The cryptographic signature check itself failed: the bytes over
 * `base64url(header).base64url(payload)` do not verify against the
 * public key recovered from `kid`. This is the one check that actually
 * proves the token wasn't forged or tampered with — everything else in
 * `"parse"`/`"signature"` is a cheap pre-check done before this expensive
 * one runs (same ordering rationale as M1's `ProofVerificationError`).
 */
export class SignatureVerificationFailedError extends Error {
  override readonly name = "SignatureVerificationFailedError";
  readonly step: VerificationStep = "signature";

  constructor() {
    super("JWS signature verification failed");
  }
}

/**
 * The (now signature-verified) payload does not conform to the W3C VC
 * Data Model 2.0 shape this project targets, or not to the specific
 * credential kind (`AuthorityCredential` / `HistoryAttestation`) the
 * caller asked to verify.
 */
export class CredentialStructureError extends Error {
  override readonly name = "CredentialStructureError";
  readonly step: VerificationStep = "structure";

  constructor(readonly reason: string) {
    super(`Credential structure invalid: ${reason}`);
  }
}

/** The credential is being used before its `validFrom`. */
export class CredentialNotYetValidError extends Error {
  override readonly name = "CredentialNotYetValidError";
  readonly step: VerificationStep = "temporal";

  constructor(
    readonly validFrom: string,
    readonly checkedAt: number,
  ) {
    super(`Credential not valid until ${validFrom}, checked at ${new Date(checkedAt).toISOString()}`);
  }
}

/** The credential is being used after its `validUntil`. */
export class CredentialExpiredError extends Error {
  override readonly name = "CredentialExpiredError";
  readonly step: VerificationStep = "temporal";

  constructor(
    readonly validUntil: string,
    readonly checkedAt: number,
  ) {
    super(`Credential expired at ${validUntil}, checked at ${new Date(checkedAt).toISOString()}`);
  }
}

/**
 * `credentialSubject.id` does not match the DID the presenter actually
 * proved possession of (via `lib/identity`'s `verifyPossession`). This is
 * the anti-replay check: it is what stops agent B presenting agent A's
 * otherwise-perfectly-valid credential, because B can only ever prove
 * possession of B's own key.
 */
export class SubjectBindingError extends Error {
  override readonly name = "SubjectBindingError";
  readonly step: VerificationStep = "subject-binding";

  constructor(
    readonly reason: string,
    options?: { cause?: unknown },
  ) {
    super(`Subject binding failed: ${reason}`, options);
  }
}

/**
 * The credential's claimed issuer (`issuer` / `iss`) does not match the
 * key that actually produced the signature. Passing the `"signature"`
 * step only proves "whoever `kid` named did sign this" — it proves
 * nothing about whether that signer is who the credential's own content
 * claims to be. This step is what catches "Acme" claimed as issuer while
 * someone else's key signed it.
 */
export class IssuerIdentityMismatchError extends Error {
  override readonly name = "IssuerIdentityMismatchError";
  readonly step: VerificationStep = "issuer-identity";

  constructor(readonly reason: string) {
    super(`Issuer identity mismatch: ${reason}`);
  }
}
