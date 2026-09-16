/**
 * Proof of possession: a challenge-response that proves the presenter
 * actually holds the private key behind a claimed `did:key`.
 *
 * Identity and possession are deliberately separate concerns. A `did:key`
 * string is public — anyone who has ever seen it can copy and present it.
 * Holding the string proves nothing about who you are; only producing a
 * *fresh* signature over a challenge you could not have precomputed proves
 * you hold the private key. This module is the only place in M1 that
 * makes that proof, and everything downstream (M3's credential
 * presentations, M6's negotiation) is expected to challenge a
 * counterparty through this same mechanism before trusting its DID.
 *
 * The challenge carries two independent defenses against replay:
 *   - `nonce`: random per challenge, so a verifier who remembers nonces
 *     it has already seen can reject a repeat outright.
 *   - `expiresAt`: even without remembering anything, a signed response
 *     captured off the wire stops being acceptable after a short window.
 * Either one alone is weaker: a nonce with no expiry means a captured
 * response is valid forever until someone happens to notice the reused
 * nonce; an expiry with no nonce means any response is replayable for the
 * whole validity window. Together, a captured response is useless once
 * its short window closes, and unusable even within that window if reuse
 * is tracked.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { ChallengeExpiredError, ProofVerificationError } from "./errors.js";
import type { Did } from "./did-key.js";
import { decodeDidKey } from "./did-key.js";

/** Number of random bytes in a challenge nonce (128 bits). */
const NONCE_BYTE_LENGTH = 16;

/** Default challenge validity window: long enough for a real round trip
 *  over a network, short enough that a captured response is useless soon
 *  after. Callers with different needs pass their own `ttlMs`. */
const DEFAULT_TTL_MS = 5 * 60 * 1000;

/** A fresh challenge a verifier issues to whoever claims a given DID. */
export interface Challenge {
  /** Random hex nonce — defeats replay of a previously-seen response. */
  readonly nonce: string;
  /** When this challenge was issued, ms since epoch. */
  readonly issuedAt: number;
  /** When this challenge stops being acceptable, ms since epoch. */
  readonly expiresAt: number;
}

/** A signed response to a `Challenge`, claiming a specific DID. */
export interface ProofOfPossession {
  readonly did: Did;
  readonly challenge: Challenge;
  /** Hex-encoded Ed25519 signature over `encodeChallengeMessage(did, challenge)`. */
  readonly signature: string;
}

export interface CreateChallengeOptions {
  /** Override "now" for deterministic tests. Defaults to `Date.now()`. */
  readonly now?: number;
  /** Validity window in ms. Defaults to `DEFAULT_TTL_MS`. */
  readonly ttlMs?: number;
}

export interface VerifyPossessionOptions {
  /** Override "now" for deterministic tests. Defaults to `Date.now()`. */
  readonly now?: number;
}

/** Issue a fresh challenge. */
export function createChallenge(options: CreateChallengeOptions = {}): Challenge {
  const now = options.now ?? Date.now();
  const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
  if (ttlMs <= 0) {
    // A non-positive TTL would produce a challenge that is already
    // expired (or expires before it was issued) — refuse to construct
    // one rather than silently mint something already useless.
    throw new RangeError(`ttlMs must be positive, got ${ttlMs}`);
  }
  return {
    nonce: bytesToHex(randomBytes(NONCE_BYTE_LENGTH)),
    issuedAt: now,
    expiresAt: now + ttlMs,
  };
}

/**
 * Build the exact bytes a proof signs. The claimed DID is bound into the
 * message alongside every challenge field, so a signature only verifies
 * for the one DID it was produced for, and tampering with the nonce or
 * either timestamp after signing changes the message and invalidates the
 * signature.
 */
function encodeChallengeMessage(did: string, challenge: Challenge): Uint8Array {
  const canonical = `${did}|${challenge.nonce}|${challenge.issuedAt}|${challenge.expiresAt}`;
  return utf8ToBytes(canonical);
}

/** Sign a challenge with `privateKey`, producing a proof that claims `did`. */
export function provePossession(privateKey: Uint8Array, did: Did, challenge: Challenge): ProofOfPossession {
  const message = encodeChallengeMessage(did, challenge);
  const signature = ed25519.sign(message, privateKey);
  return { did, challenge, signature: bytesToHex(signature) };
}

/**
 * Verify a proof of possession. Fail-closed at every step:
 *   1. The claimed DID must decode to a real Ed25519 public key
 *      (`decodeDidKey` throws `MalformedDidError` otherwise).
 *   2. The challenge must not be expired — checked before the signature
 *      is verified, so an expired-but-validly-signed proof is still
 *      rejected (a captured response replayed after its window closes).
 *   3. The signature must verify against the public key recovered from
 *      the DID — this is the actual proof of possession. Verifying a
 *      correctly-signed challenge with the WRONG key's DID (or a
 *      differently-signed one against the right DID) must fail here.
 *
 * Returns the verified public key on success; throws otherwise.
 */
export function verifyPossession(
  proof: ProofOfPossession,
  options: VerifyPossessionOptions = {},
): Uint8Array {
  const now = options.now ?? Date.now();

  const publicKey = decodeDidKey(proof.did);

  if (now > proof.challenge.expiresAt) {
    throw new ChallengeExpiredError(proof.challenge.expiresAt, now);
  }

  const message = encodeChallengeMessage(proof.did, proof.challenge);

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = hexToBytes(proof.signature);
  } catch (cause) {
    throw new ProofVerificationError(proof.did, { cause });
  }

  let isValid: boolean;
  try {
    isValid = ed25519.verify(signatureBytes, message, publicKey);
  } catch {
    // Malformed signature bytes (wrong length, invalid curve point, etc.)
    // are a verification failure, not a crash — fail closed either way.
    isValid = false;
  }

  if (!isValid) {
    throw new ProofVerificationError(proof.did);
  }

  return publicKey;
}
