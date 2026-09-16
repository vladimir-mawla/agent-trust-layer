/**
 * Minimal compact JWS (RFC 7515) sign/verify, EdDSA-only — used ONLY for
 * this trust module's own signed objects: Bitstring Status List
 * credentials (`status-list.ts`) and issuer vouches (`vouch.ts`).
 *
 * ## Why this isn't just `lib/credentials/jws.ts` reused
 *
 * `lib/credentials/jws.ts` exports `signCompactJws`, `verifySignature`,
 * and `decodeVerifiedPayload` — but `lib/credentials/index.ts` (that
 * module's own public barrel) deliberately does NOT re-export any of the
 * three. Its comment is explicit about why: "the trust-sensitive
 * ordering itself... lives entirely in jws.ts and verify.ts, not in
 * whatever imports these", and `verifySignature`'s `SignatureVerified`
 * result is a symbol-branded witness type that only `jws.ts` itself can
 * construct — by design, un-forgeable from outside that file. Reaching
 * past `index.ts` with a deep relative import
 * (`lib/credentials/jws.js`) would work today (TypeScript does not
 * enforce package-internal encapsulation the way a separate npm package
 * boundary would), but it would be exactly the kind of "the type system
 * says private, the import graph says otherwise" mismatch this project's
 * whole design argues against elsewhere (see `did-key.ts`'s and
 * `jws.ts`'s own comments on types not crossing trust boundaries for
 * free). `lib/trust` is architecturally a separate consumer of
 * `lib/credentials` — the same relationship `app/` or a future external
 * package would have — so it is held to the same public-API-only
 * contract this BUILD's task brief pointed at
 * (`lib/credentials/index.ts`).
 *
 * What IS reused, because it IS public: `parseCompactJws` (wire-format
 * parsing and header extraction), `encodeBase64Url`/`decodeBase64Url`
 * (the codec), and the `ALLOWED_ALG`/`VC_JWT_TYP`/`MAX_JWS_LENGTH`
 * constants, all re-exported from `lib/credentials/index.ts` specifically
 * "for... any future module that needs to inspect a compact JWS's shape
 * directly" — this module is exactly that future module. Only the two
 * pieces `index.ts` withholds (signing, and the signature-verify step)
 * are reimplemented here, and they are a handful of lines apiece,
 * independently tested (`jws-lite.test.ts`), against the exact same wire
 * format `lib/credentials/jws.ts` already proves conformant via its own
 * `jose` interop suite — not a fork of untested logic, a small,
 * obviously-necessary duplication with a documented reason.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import {
  ALLOWED_ALG,
  VC_JWT_TYP,
  decodeBase64Url,
  encodeBase64Url,
  parseCompactJws,
  type ParsedJws,
} from "../credentials/index.js";
import { AlgorithmNotAllowedError, SignatureVerificationFailedError } from "./errors.js";

function encodeJsonSegment(value: unknown): string {
  return encodeBase64Url(utf8ToBytes(JSON.stringify(value)));
}

function signingInputBytes(headerB64: string, payloadB64: string): Uint8Array {
  return utf8ToBytes(`${headerB64}.${payloadB64}`);
}

/** Sign `payload` as a compact EdDSA JWS. Header shape mirrors
 *  `lib/credentials/jws.ts`'s (`alg`, `kid`, `typ: "vc+jwt"`) for
 *  consistency — both modules produce and consume the same wire format,
 *  they just don't share the one function that emits it. */
export function signCompact(payload: unknown, kid: string, privateKey: Uint8Array): string {
  const header = { alg: ALLOWED_ALG, kid, typ: VC_JWT_TYP };
  const headerB64 = encodeJsonSegment(header);
  const payloadB64 = encodeJsonSegment(payload);
  const signature = ed25519.sign(signingInputBytes(headerB64, payloadB64), privateKey);
  return `${headerB64}.${payloadB64}.${encodeBase64Url(signature)}`;
}

/**
 * Parse a compact JWS, verify its signature against `publicKey`, and
 * only then decode the payload to JSON — the same ordering
 * `lib/credentials/verify.ts` depends on (signature before any content
 * is trusted), reproduced here because the witness-typed enforcement of
 * that ordering is exactly the private mechanism this module has
 * chosen not to reach into (see the module comment).
 *
 * `parseCompactJws` throws `MalformedJwsError` (a `lib/credentials`
 * error, re-exported publicly) for wire-format problems; that is
 * allowed to propagate to this function's caller, which — in both call
 * sites (`status-list.ts`, `vouch.ts`) — immediately wraps ANY failure
 * from this function into its own typed, module-specific error before
 * it can reach a public API boundary. Nothing below throws a bare
 * native `SyntaxError`/`RangeError`.
 */
export function verifyCompactAndDecode(jws: string, publicKey: Uint8Array): { readonly parsed: ParsedJws; readonly payload: unknown } {
  const parsed = parseCompactJws(jws);

  if (parsed.header.alg !== ALLOWED_ALG) {
    throw new AlgorithmNotAllowedError(parsed.header.alg);
  }

  const signatureBytes = decodeBase64Url(parsed.signatureB64);
  const message = signingInputBytes(parsed.headerB64, parsed.payloadB64);

  let isValid: boolean;
  try {
    isValid = ed25519.verify(signatureBytes, message, publicKey);
  } catch {
    // Malformed signature bytes (wrong length, invalid curve point) are
    // a verification failure, not a crash — same fail-closed posture as
    // lib/credentials/jws.ts's verifySignature and lib/identity's
    // verifyPossession.
    isValid = false;
  }
  if (!isValid) {
    throw new SignatureVerificationFailedError();
  }

  const payloadBytes = decodeBase64Url(parsed.payloadB64);
  let payload: unknown;
  try {
    payload = JSON.parse(new TextDecoder().decode(payloadBytes));
  } catch (cause) {
    // Same "real signature over non-JSON bytes" case lib/credentials was
    // once rejected (at L4) for letting escape unhandled — guarded here
    // from the start.
    throw new SyntaxErrorAsPayloadError(cause);
  }

  return { parsed, payload };
}

/** Thin wrapper so a `JSON.parse` failure carries a recognisable type
 *  instead of propagating a bare native `SyntaxError` — callers narrow
 *  on `instanceof SyntaxErrorAsPayloadError` if they need to distinguish
 *  "signature verified but payload isn't JSON" from other failures. */
export class SyntaxErrorAsPayloadError extends Error {
  override readonly name = "SyntaxErrorAsPayloadError";
  constructor(cause: unknown) {
    super("Verified JWS payload is not valid JSON", { cause });
  }
}
