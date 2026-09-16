/**
 * `did:key` encoding and decoding.
 *
 * A `did:key` identifier IS the public key: it is self-certifying and
 * resolvable with no network call and no registry — decoding the string
 * is the entire resolution process. That property is the whole point of
 * choosing `did:key` for this project (see ADR 0001): a verifier never
 * needs to trust, reach, or even know about a third party just to learn
 * "what public key does this identifier name".
 *
 * Format: `did:key:z` + base58btc( multicodec-prefix ++ raw public key ).
 * The multicodec prefix `0xed 0x01` is the varint encoding of multicodec
 * code 0xed ("ed25519-pub" in the multiformats table) — it tags the bytes
 * that follow as an Ed25519 public key so a decoder never has to *guess*
 * the key type from length alone, and can reject a same-length key of a
 * different type outright.
 */
import { base58btc } from "multiformats/bases/base58";
import { MalformedDidError } from "./errors.js";
import { ED25519_PUBLIC_KEY_LENGTH } from "./keys.js";

const DID_KEY_PREFIX = "did:key:";

/** Multicodec varint for "ed25519-pub" (code 0xed, one-byte varint 0xed 0x01). */
const ED25519_MULTICODEC_PREFIX = Uint8Array.of(0xed, 0x01);

/**
 * A `did:key` string. This is a *type-level* hint only — it documents
 * intent at call sites, but nothing in this module treats a value merely
 * typed `Did` as trustworthy. Any string, however typed, is re-validated
 * by `decodeDidKey` at runtime before its bytes are used for anything,
 * because the whole point of a trust boundary is that types don't cross
 * it for free.
 */
export type Did = `did:key:${string}`;

/**
 * Encode a raw Ed25519 public key as a `did:key` identifier.
 */
export function encodeDidKey(publicKey: Uint8Array): Did {
  if (publicKey.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new RangeError(
      `Public key must be ${ED25519_PUBLIC_KEY_LENGTH} bytes, got ${publicKey.length}`,
    );
  }
  const tagged = new Uint8Array(ED25519_MULTICODEC_PREFIX.length + publicKey.length);
  tagged.set(ED25519_MULTICODEC_PREFIX, 0);
  tagged.set(publicKey, ED25519_MULTICODEC_PREFIX.length);

  // base58btc.encode already prepends the "z" multibase prefix.
  const multibase = base58btc.encode(tagged);
  return `${DID_KEY_PREFIX}${multibase}`;
}

/**
 * Decode a `did:key` identifier back into its raw Ed25519 public key
 * bytes. Every failure mode is rejected with a typed `MalformedDidError`
 * naming exactly which structural check failed — never a silent fallback
 * and never an unhandled throw from the underlying base58 decoder.
 */
export function decodeDidKey(did: string): Uint8Array {
  if (!did.startsWith(DID_KEY_PREFIX)) {
    throw new MalformedDidError("BAD_PREFIX", did);
  }

  const multibase = did.slice(DID_KEY_PREFIX.length);

  let decoded: Uint8Array;
  try {
    // base58btc.decode itself requires the leading "z" and rejects
    // non-base58btc characters (e.g. 0/O/I/l), so both cases land here.
    decoded = base58btc.decode(multibase);
  } catch (cause) {
    throw new MalformedDidError("BAD_MULTIBASE", did, { cause });
  }

  if (decoded.length < 2 || decoded[0] !== ED25519_MULTICODEC_PREFIX[0] || decoded[1] !== ED25519_MULTICODEC_PREFIX[1]) {
    throw new MalformedDidError("BAD_MULTICODEC", did);
  }

  const publicKey = decoded.slice(2);
  if (publicKey.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new MalformedDidError("BAD_KEY_LENGTH", did);
  }

  return publicKey;
}
