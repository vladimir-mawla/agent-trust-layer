/**
 * Typed error hierarchy for the identity module.
 *
 * Every failure mode below is a distinct class (not a shared "IdentityError"
 * with a string `code`, and never a bare `throw new Error("...")`) so that
 * callers — and tests — can `instanceof`-check exactly what went wrong.
 * The trust layer's fail-closed posture depends on this: a caller must be
 * able to tell "this DID is malformed" apart from "this proof expired"
 * apart from "this signature doesn't verify", because M4/M5 policy code
 * will eventually branch on which one happened.
 */

/** Why a `did:key` string failed to decode. */
export type MalformedDidReason =
  /** Does not start with the required `did:key:` method prefix. */
  | "BAD_PREFIX"
  /** The remainder is not valid multibase base58btc (must start with `z`
   *  and use the base58btc alphabet — see `did-key.ts`). */
  | "BAD_MULTIBASE"
  /** Decoded bytes don't start with the `0xed 0x01` multicodec varint that
   *  tags "this is an Ed25519 public key". */
  | "BAD_MULTICODEC"
  /** The bytes after the multicodec prefix aren't exactly 32 bytes. */
  | "BAD_KEY_LENGTH";

/**
 * A `did:key` string could not be decoded into a public key. Thrown instead
 * of returning `null`/`undefined` so callers can't accidentally treat a
 * malformed DID as "absent but fine" — decoding a DID is a security
 * boundary, not a parse convenience.
 */
export class MalformedDidError extends Error {
  override readonly name = "MalformedDidError";

  constructor(
    readonly reason: MalformedDidReason,
    readonly did: string,
    options?: { cause?: unknown },
  ) {
    super(`Malformed did:key (${reason}): ${did}`, options);
  }
}

/** A public key's raw bytes (or serialised form) are not a valid Ed25519 key. */
export class InvalidPublicKeyError extends Error {
  override readonly name = "InvalidPublicKeyError";

  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/**
 * A challenge's `expiresAt` has passed. Kept separate from
 * `ProofVerificationError` so callers (and tests) can prove that expiry is
 * enforced even when the signature is otherwise perfectly valid — an
 * expired-but-correctly-signed proof is exactly the "captured response
 * replayed later" attack this type exists to catch.
 */
export class ChallengeExpiredError extends Error {
  override readonly name = "ChallengeExpiredError";

  constructor(
    readonly expiresAt: number,
    readonly checkedAt: number,
  ) {
    super(
      `Challenge expired at ${new Date(expiresAt).toISOString()}, checked at ${new Date(checkedAt).toISOString()}`,
    );
  }
}

/**
 * A proof of possession failed cryptographic verification: the signature
 * does not verify against the public key recovered from the claimed DID.
 * This is the one check that actually proves key possession — everything
 * else (parsing, expiry) is a cheap pre-check done before this expensive
 * one runs.
 */
export class ProofVerificationError extends Error {
  override readonly name = "ProofVerificationError";

  constructor(
    readonly did: string,
    options?: { cause?: unknown },
  ) {
    super(`Signature verification failed for proof of possession of ${did}`, options);
  }
}
