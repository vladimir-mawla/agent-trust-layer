/**
 * Public API of the identity module (M1): Ed25519 keypairs, `did:key`
 * encoding/decoding, and challenge-response proof of possession.
 *
 * Framework-free by design — nothing in `lib/identity` (or anywhere under
 * `lib/`) may import from Next.js. This module runs the same way in a
 * Node test, a Next.js API route (M2+), and eventually a browser (M8).
 */

export {
  type KeyPair,
  ED25519_PUBLIC_KEY_LENGTH,
  ED25519_PRIVATE_KEY_LENGTH,
  ED25519_SIGNATURE_LENGTH,
  generateKeyPair,
  derivePublicKey,
  encodePublicKeyHex,
  decodePublicKeyHex,
} from "./keys.js";

export { type Did, encodeDidKey, decodeDidKey } from "./did-key.js";

export {
  type Challenge,
  type ProofOfPossession,
  type CreateChallengeOptions,
  type VerifyPossessionOptions,
  createChallenge,
  provePossession,
  verifyPossession,
} from "./challenge.js";

export {
  type MalformedDidReason,
  MalformedDidError,
  InvalidPublicKeyError,
  ChallengeExpiredError,
  ProofVerificationError,
} from "./errors.js";
