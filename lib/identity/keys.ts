/**
 * Ed25519 keypair generation and public-key serialisation.
 *
 * Ed25519 (not RSA/ECDSA) because keys and signatures are tiny (32 and 64
 * bytes), generation and verification are fast enough to do per-request,
 * and `@noble/curves` implements it in pure, audited, dependency-light
 * TypeScript that runs identically in Node and the browser — the same
 * verification code that runs here in M1 is the code that will run
 * client-side in M8's browser demo.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { InvalidPublicKeyError } from "./errors.js";

/**
 * `@noble/curves` types `lengths.*` as optional (`number | undefined`)
 * because not every curve family it supports defines every field — but
 * ed25519 always does. Assert that once, here, rather than threading
 * `| undefined` through every constant this module exports.
 */
function requireLength(value: number | undefined, field: string): number {
  if (value === undefined) {
    throw new Error(`@noble/curves ed25519 did not report a byte length for "${field}"`);
  }
  return value;
}

/** Raw Ed25519 public key length in bytes (a compressed curve point). */
export const ED25519_PUBLIC_KEY_LENGTH = requireLength(ed25519.lengths.publicKey, "publicKey");

/** Raw Ed25519 private (seed) key length in bytes. */
export const ED25519_PRIVATE_KEY_LENGTH = requireLength(ed25519.lengths.secretKey, "secretKey");

/** Raw Ed25519 signature length in bytes. */
export const ED25519_SIGNATURE_LENGTH = requireLength(ed25519.lengths.signature, "signature");

/** An Ed25519 keypair as raw bytes. Never serialise `privateKey` anywhere
 *  outside of this process's memory — see the repo's key-hygiene gate. */
export interface KeyPair {
  readonly publicKey: Uint8Array;
  readonly privateKey: Uint8Array;
}

/** Generate a fresh Ed25519 keypair using a CSPRNG. */
export function generateKeyPair(): KeyPair {
  const { secretKey, publicKey } = ed25519.keygen();
  return { publicKey, privateKey: secretKey };
}

/** Re-derive the public key from a private key. Useful for tests and for
 *  verifying that a stored keypair is internally consistent. */
export function derivePublicKey(privateKey: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(privateKey);
}

/**
 * Serialise a public key to lowercase hex. This is a plain byte<->hex
 * codec for storing/transmitting a raw key — distinct from `did:key`
 * encoding (`did-key.ts`), which additionally tags the bytes with a
 * multicodec and wraps them as a self-certifying identifier.
 */
export function encodePublicKeyHex(publicKey: Uint8Array): string {
  if (publicKey.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new InvalidPublicKeyError(
      `Public key must be ${ED25519_PUBLIC_KEY_LENGTH} bytes, got ${publicKey.length}`,
    );
  }
  return bytesToHex(publicKey);
}

/**
 * Deserialise a hex-encoded public key, rejecting anything that isn't
 * exactly 32 bytes of valid hex. Fail-closed: malformed input throws
 * rather than returning a truncated or padded key.
 */
export function decodePublicKeyHex(hex: string): Uint8Array {
  let bytes: Uint8Array;
  try {
    bytes = hexToBytes(hex);
  } catch (cause) {
    throw new InvalidPublicKeyError(`Public key is not valid hex: ${hex}`, { cause });
  }
  if (bytes.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new InvalidPublicKeyError(
      `Public key must be ${ED25519_PUBLIC_KEY_LENGTH} bytes, got ${bytes.length}`,
    );
  }
  return bytes;
}
