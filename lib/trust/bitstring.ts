/**
 * The Bitstring Status List's actual bitstring: generation, GZIP
 * compression + multibase-base64url encoding, and single-bit lookup —
 * per W3C Bitstring Status List v1.0 (`https://www.w3.org/TR/vc-bitstring-status-list/`).
 *
 * Field/algorithm names below are traced directly to the spec, not
 * guessed:
 *   - §2.1 "Bitstring Encoding": "the bitstring MUST be encoded using
 *     the algorithm in Section 2.1... compress using GZIP [RFC1952]...
 *     and then base64url-encode (with no padding) that result, and
 *     prefix it with the multibase base64url header ('u')."
 *   - §2.1 also gives the bit-order convention this file implements:
 *     "the first index, with a value of zero (0), is located at the
 *     left-most bit in the bitstring, and the last index... is located
 *     at the right-most bit" — i.e. within a byte, bit 0 of the overall
 *     stream is the MOST significant bit, not the least.
 *   - §3 "Bitstring Generation Algorithm": bitstrings MUST be generated
 *     with a minimum size of 131,072 bits (16KB), specifically so a
 *     revocation check reveals nothing about which single credential a
 *     verifier actually cared about ("herd privacy" — see the module
 *     comment in `status-list.ts` for how that shapes this project's
 *     API, since fetching the whole list is the point).
 *   - §3 position formula: "the position of the bit... is calculated
 *     by multiplying the `statusListIndex` by the `statusSize`."
 *   - §4 "bit value 1 indicates that the referenced credential meets
 *     the status condition (e.g., is revoked); a bit value 0 indicates
 *     that the referenced credential does not meet the status condition."
 */
import { gunzipSync, gzipSync } from "node:zlib";
import { decodeBase64Url, encodeBase64Url } from "../credentials/index.js";
import { BitstringIndexError, StatusListMalformedError } from "./errors.js";

/** §3: minimum bitstring size, in bits, before compression — the
 *  privacy-motivated floor that makes "someone fetched the list" reveal
 *  nothing about which of the (at least) 131,072 credentials they meant. */
export const MINIMUM_BITSTRING_BITS = 131_072;

/** Multibase prefix for "base64url, no padding" (the `u` header —
 *  https://github.com/multiformats/multibase#multibase-table). This
 *  project uses only this one multibase prefix, the same way
 *  `lib/identity/did-key.ts` uses only `z` (base58btc) — both are
 *  narrow, hardcoded acceptance of one encoding, never a
 *  dispatch-on-whatever-prefix-shows-up. */
const MULTIBASE_BASE64URL_PREFIX = "u";

/** Build a bitstring of `sizeBits` bits (all zero / "unset"), GZIP it,
 *  and multibase-base64url-encode the result — the exact `encodedList`
 *  value a `BitstringStatusListCredential.credentialSubject` carries.
 *  `sizeBits` defaults to the spec's privacy-floor minimum; tests may
 *  override it smaller to keep fixtures fast to construct — a
 *  deliberate, documented trade of this codebase's own test speed
 *  against the spec's herd-privacy motivation, never done in the
 *  issuance HELPER's own default. */
export function createEmptyEncodedList(sizeBits: number = MINIMUM_BITSTRING_BITS): string {
  if (!Number.isInteger(sizeBits) || sizeBits <= 0 || sizeBits % 8 !== 0) {
    throw new RangeError(`sizeBits must be a positive multiple of 8, got ${sizeBits}`);
  }
  const bytes = new Uint8Array(sizeBits / 8);
  return encodeList(bytes);
}

/** Compress + multibase-base64url-encode raw bitstring bytes. */
export function encodeList(bytes: Uint8Array): string {
  const compressed = gzipSync(bytes);
  return `${MULTIBASE_BASE64URL_PREFIX}${encodeBase64Url(compressed)}`;
}

/**
 * Set (to "1"/revoked) the bit at `index` (after `index *= statusSize`
 * has already been applied by the caller — this function takes the
 * final bit position) within a bitstring previously produced by
 * `encodeList`/`createEmptyEncodedList`, returning a new encoded list.
 * Used only by test fixtures and any future issuance-side tooling —
 * `checkRevocation` (in `status-list.ts`) only ever reads, never writes.
 */
export function withBitSet(encodedList: string, bitIndex: number): string {
  const bytes = decodeEncodedList(encodedList);
  if (!Number.isInteger(bitIndex) || bitIndex < 0) {
    throw new BitstringIndexError(`bit index must be a non-negative integer, got ${JSON.stringify(bitIndex)}`);
  }
  const byteIndex = Math.floor(bitIndex / 8);
  if (byteIndex >= bytes.length) {
    throw new BitstringIndexError(`bit index ${bitIndex} is beyond the bitstring's ${bytes.length * 8}-bit length`);
  }
  const bitOffsetFromLeft = bitIndex % 8; // 0 = most-significant bit, per spec §2.1
  const mask = 0b1000_0000 >> bitOffsetFromLeft;
  const next = bytes.slice();
  next[byteIndex] = (next[byteIndex]! | mask) & 0xff;
  return encodeList(next);
}

/**
 * Multibase-decode + GZIP-decompress an `encodedList` value back to raw
 * bitstring bytes. Fails closed with a typed `StatusListMalformedError`
 * for every shape problem — wrong/missing multibase prefix, invalid
 * base64url, or bytes that don't gunzip — never an unhandled throw from
 * `node:zlib` or the base64url codec escaping this module. This is what
 * makes "malformed/garbage status list VC" (an M4 required test) a
 * typed failure rather than a crash.
 */
export function decodeEncodedList(encodedList: string): Uint8Array {
  if (typeof encodedList !== "string" || encodedList.length === 0) {
    throw new StatusListMalformedError('"encodedList" must be a non-empty string');
  }
  if (!encodedList.startsWith(MULTIBASE_BASE64URL_PREFIX)) {
    throw new StatusListMalformedError(`"encodedList" must use the multibase "${MULTIBASE_BASE64URL_PREFIX}" (base64url) prefix`);
  }
  let compressed: Uint8Array;
  try {
    compressed = decodeBase64Url(encodedList.slice(MULTIBASE_BASE64URL_PREFIX.length));
  } catch (cause) {
    throw new StatusListMalformedError('"encodedList" is not valid base64url after its multibase prefix', { cause });
  }
  try {
    return new Uint8Array(gunzipSync(compressed));
  } catch (cause) {
    throw new StatusListMalformedError('"encodedList" did not GZIP-decompress', { cause });
  }
}

/**
 * Read a single status bit at `index` from decompressed bitstring
 * `bytes`. `index` must already be `statusListIndex * statusSize` — see
 * `status-list.ts`'s `checkRevocation`, which is the only caller that
 * computes that multiplication.
 *
 * Fails closed with a typed `BitstringIndexError` — never an unhandled
 * throw or a silently-wrong `undefined`-read — for a negative index, a
 * non-integer index, or an index at/beyond the bitstring's bit length.
 * `noUncheckedIndexedAccess` (this repo's tsconfig) would otherwise make
 * `bytes[byteIndex]` type as `number | undefined`; the explicit range
 * check below is what lets this function assert it's defined rather
 * than silently coercing `undefined` through arithmetic into `NaN` and
 * a wrong (but not obviously wrong) answer.
 */
export function getStatusBit(bytes: Uint8Array, index: number): boolean {
  if (!Number.isInteger(index) || index < 0) {
    throw new BitstringIndexError(`index must be a non-negative integer, got ${JSON.stringify(index)}`);
  }
  const totalBits = bytes.length * 8;
  if (index >= totalBits) {
    throw new BitstringIndexError(`index ${index} is out of range for a ${totalBits}-bit bitstring`);
  }
  const byteIndex = Math.floor(index / 8);
  const byte = bytes[byteIndex];
  if (byte === undefined) {
    // Unreachable given the range check above, but kept as an explicit
    // typed guard rather than trusting that invariant silently forever
    // — same defensive posture as lib/credentials/base64url.ts.
    throw new BitstringIndexError(`index ${index} resolved to an undefined byte`);
  }
  const bitOffsetFromLeft = index % 8; // 0 = most-significant bit, per spec §2.1
  return ((byte >> (7 - bitOffsetFromLeft)) & 1) === 1;
}
