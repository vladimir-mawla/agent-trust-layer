/**
 * base64url codec (RFC 4648 §5), used by the compact JWS serialisation in
 * `jws.ts`. Hand-rolled rather than pulled from a dependency, and
 * deliberately NOT built on `atob`/`btoa`:
 *
 *   - `@noble/hashes/utils.js` (already a dependency, used throughout
 *     `lib/identity`) only exports hex codecs, not base64 — and JWS
 *     compact serialisation specifically requires the *unpadded*
 *     base64url alphabet (RFC 7515 §2), a small enough transform that a
 *     new dependency for it would cost more (another supply-chain
 *     surface, in a project whose entire premise is minimising trusted
 *     third parties) than it saves.
 *   - `Buffer` is Node-only, which would silently break this module
 *     running in a browser (M8) — same reasoning as `lib/identity/keys.ts`.
 *   - `atob`/`btoa`, while global in both Node and browsers at RUNTIME,
 *     are typed only via `lib.dom.d.ts` — `@types/node` merely re-exports
 *     them as `Buffer.atob`/`Buffer.btoa` assuming `globalThis.atob`
 *     already has a type, which it doesn't under this project's
 *     Node-focused `tsconfig.lib.json` (see that file's own comment on
 *     why it targets NodeNext resolution rather than the browser-shaped
 *     root `tsconfig.json`). Rather than pull in all of `lib.dom.d.ts`'s
 *     unrelated ambient types just to type two legacy functions, this
 *     codec is bit-manipulation over `Uint8Array`, which needs no
 *     environment-specific global at all.
 */

const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const DECODE_TABLE = new Map<string, number>();
for (let i = 0; i < BASE64URL_ALPHABET.length; i += 1) {
  DECODE_TABLE.set(BASE64URL_ALPHABET[i]!, i);
}

/** Encode raw bytes as unpadded base64url. */
export function encodeBase64Url(bytes: Uint8Array): string {
  let output = "";
  let i = 0;

  for (; i + 3 <= bytes.length; i += 3) {
    const chunk = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    output +=
      BASE64URL_ALPHABET[(chunk >> 18) & 0x3f]! +
      BASE64URL_ALPHABET[(chunk >> 12) & 0x3f]! +
      BASE64URL_ALPHABET[(chunk >> 6) & 0x3f]! +
      BASE64URL_ALPHABET[chunk & 0x3f]!;
  }

  const remaining = bytes.length - i;
  if (remaining === 1) {
    const chunk = bytes[i]! << 16;
    output += BASE64URL_ALPHABET[(chunk >> 18) & 0x3f]! + BASE64URL_ALPHABET[(chunk >> 12) & 0x3f]!;
  } else if (remaining === 2) {
    const chunk = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    output +=
      BASE64URL_ALPHABET[(chunk >> 18) & 0x3f]! +
      BASE64URL_ALPHABET[(chunk >> 12) & 0x3f]! +
      BASE64URL_ALPHABET[(chunk >> 6) & 0x3f]!;
  }

  return output;
}

/** RFC 4648 §5 base64url alphabet, plus an optional trailing `=` padding
 *  run — decoding is lenient about padding (accepts it, doesn't require
 *  it) even though `encodeBase64Url` never produces any, since some
 *  interop partners (this project's `jose` interop tests included) may
 *  emit either form. */
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*=*$/;

/**
 * Decode base64url (padded or not) back to raw bytes. Fails closed with
 * a `RangeError` for anything outside the base64url alphabet or with an
 * invalid length — never returns a truncated or garbage byte array for
 * malformed input.
 *
 * NOT CANONICAL: this decoder does not require the unused low bits of a
 * partial final character to be zero (RFC 4648 §3.5 says an encoder
 * SHOULD set them to zero but does not require a decoder to reject
 * nonzero ones). Consequently multiple distinct strings can decode to
 * the same bytes — e.g. 16 different 2-character inputs all decode to
 * the single byte `0x68`. This is NOT exploitable in this module's own
 * use (`jws.ts`'s compact JWS): a JWS signature covers the literal
 * base64url *string* that was transmitted, not the bytes it decodes to,
 * so a non-canonical payload segment just verifies (or fails to verify)
 * as the different string it actually is — there is no pair of distinct
 * encodings of the same underlying bytes that both validate as the same
 * signed token. Anyone reusing this decoder OUTSIDE that context —
 * anywhere a decoded byte value, not the encoded string, is what gets
 * compared, hashed, or looked up — must not assume distinct inputs
 * decode to distinct outputs.
 */
export function decodeBase64Url(value: string): Uint8Array {
  if (typeof value !== "string" || !BASE64URL_PATTERN.test(value)) {
    throw new RangeError(`not a valid base64url string: ${JSON.stringify(value)}`);
  }

  const clean = value.replace(/=+$/, "");
  if (clean.length % 4 === 1) {
    throw new RangeError(`invalid base64url length: ${JSON.stringify(value)}`);
  }

  const outputLength = Math.floor((clean.length * 6) / 8);
  const bytes = new Uint8Array(outputLength);

  let bitBuffer = 0;
  let bitCount = 0;
  let byteIndex = 0;
  for (let i = 0; i < clean.length; i += 1) {
    const char = clean[i]!;
    const bits = DECODE_TABLE.get(char);
    if (bits === undefined) {
      // Unreachable given BASE64URL_PATTERN already restricted the
      // alphabet, but kept as an explicit, typed guard rather than
      // trusting that invariant silently forever.
      throw new RangeError(`not a valid base64url character: ${JSON.stringify(char)}`);
    }
    bitBuffer = (bitBuffer << 6) | bits;
    bitCount += 6;
    if (bitCount >= 8) {
      bitCount -= 8;
      bytes[byteIndex] = (bitBuffer >> bitCount) & 0xff;
      byteIndex += 1;
    }
  }

  return bytes;
}
