/**
 * Compact JWS (RFC 7515) signing and verification, Ed25519-only.
 *
 * This module is the mechanical layer underneath the VC-JWT representation
 * (`credential.ts`/`verify.ts`): it knows nothing about verifiable
 * credentials, only about producing and checking
 * `base64url(header).base64url(payload).base64url(signature)`.
 *
 * The one property this module exists to guarantee, in the TYPE SYSTEM
 * and not merely in comment prose, is the ordering the whole verification
 * chain depends on: **the payload is never JSON-parsed before the
 * signature over it has been checked.** `parseCompactJws` only base64url-
 * decodes the payload segment to raw bytes (never `JSON.parse`s it).
 * `verifySignature` returns a `SignatureVerified` witness token — an
 * object of a type nothing outside this module can construct — and
 * `decodeVerifiedPayload` requires that token as an argument. There is
 * therefore no code path, anywhere that imports this module, that can
 * reach a parsed payload object without having first produced a witness
 * that the signature over its exact bytes was checked. This is the same
 * "a type doesn't cross a trust boundary for free" principle
 * `lib/identity/did-key.ts`'s `Did` type documents — applied here in the
 * opposite direction: instead of a type that must be re-validated before
 * it's trusted, this is a type that CANNOT be constructed except as
 * evidence that validation already happened.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { decodeBase64Url, encodeBase64Url } from "./base64url.js";
import {
  AlgorithmNotAllowedError,
  MalformedJwsError,
  SignatureVerificationFailedError,
} from "./errors.js";

/** The one algorithm this verifier will ever accept. Never read from the
 *  token's own header and used to pick a verification routine — see
 *  `parseCompactJws`. */
export const ALLOWED_ALG = "EdDSA" as const;

/** VC-JOSE-COSE (the W3C VC 2.0 securing spec this project targets — see
 *  `credential.ts`) says the `typ` header parameter SHOULD be `vc+jwt`. */
export const VC_JWT_TYP = "vc+jwt" as const;

/** JWS header shape this module produces and accepts. Nothing beyond
 *  `alg`/`kid`/`typ` is needed: there is no key-set indirection (`kid`
 *  resolves directly to a `did:key`, decodable with no network call) and
 *  no algorithm negotiation (there is exactly one algorithm). */
export interface JwsHeader {
  readonly alg: string;
  readonly kid: string;
  readonly typ?: string;
}

/** A JWS split into its three segments, with the header already decoded
 *  (decoding a header is inspecting JWS transport metadata, not reading a
 *  credential's claims — see the module comment). The payload is
 *  deliberately kept as an undecoded byte string here. */
export interface ParsedJws {
  readonly headerB64: string;
  readonly payloadB64: string;
  readonly signatureB64: string;
  readonly header: JwsHeader;
}

/**
 * Upper bound on a compact JWS's total length. Ed25519 VC-JWTs are a few
 * hundred bytes to a few KB; 64 KiB is generous headroom for a
 * legitimately large credential (many scope fields, a long history of
 * metrics) while still bounding the cost of base64url-decoding and
 * JSON-parsing an attacker-supplied "huge payload" to something that
 * fails fast instead of doing meaningful work on unbounded input.
 */
export const MAX_JWS_LENGTH = 64 * 1024;

function decodeJsonHeader(headerB64: string): JwsHeader {
  let headerBytes: Uint8Array;
  try {
    headerBytes = decodeBase64Url(headerB64);
  } catch (cause) {
    throw new MalformedJwsError("header is not valid base64url", { cause });
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(headerBytes));
  } catch (cause) {
    throw new MalformedJwsError("header is not valid JSON", { cause });
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new MalformedJwsError("header is not a JSON object");
  }
  const record = parsed as Record<string, unknown>;
  if (typeof record["alg"] !== "string") {
    throw new MalformedJwsError('header is missing a string "alg"');
  }
  if (typeof record["kid"] !== "string") {
    throw new MalformedJwsError('header is missing a string "kid"');
  }
  const typ = record["typ"];
  if (typ !== undefined && typeof typ !== "string") {
    throw new MalformedJwsError('header "typ" must be a string when present');
  }

  return typ === undefined ? { alg: record["alg"], kid: record["kid"] } : { alg: record["alg"], kid: record["kid"], typ };
}

/**
 * Parse a compact JWS string into its three segments and decoded header.
 * Fails closed with a typed `MalformedJwsError` for every shape problem —
 * wrong segment count, an empty segment, invalid base64url, an oversized
 * token, or a malformed header — never an unhandled throw from a native
 * `atob`/`JSON.parse` exception escaping this module.
 *
 * Does NOT verify the signature and does NOT decode the payload as JSON —
 * both happen later, and only for a payload whose signature has already
 * checked out (see `decodeVerifiedPayload`).
 */
export function parseCompactJws(jws: string): ParsedJws {
  if (typeof jws !== "string" || jws.length === 0) {
    throw new MalformedJwsError("token is empty");
  }
  if (jws.length > MAX_JWS_LENGTH) {
    throw new MalformedJwsError(`token exceeds maximum length of ${MAX_JWS_LENGTH} bytes`);
  }

  const segments = jws.split(".");
  if (segments.length !== 3) {
    throw new MalformedJwsError(`expected 3 dot-separated segments, got ${segments.length}`);
  }
  const [headerB64, payloadB64, signatureB64] = segments as [string, string, string];
  if (headerB64.length === 0 || payloadB64.length === 0 || signatureB64.length === 0) {
    throw new MalformedJwsError("a JWS segment is empty");
  }

  // Confirm the payload segment is at least *decodable* base64url — this
  // is a shape check on transport bytes, not an inspection of claims: the
  // decoded bytes are discarded here and never JSON.parsed.
  try {
    decodeBase64Url(payloadB64);
  } catch (cause) {
    throw new MalformedJwsError("payload is not valid base64url", { cause });
  }
  try {
    decodeBase64Url(signatureB64);
  } catch (cause) {
    throw new MalformedJwsError("signature is not valid base64url", { cause });
  }

  const header = decodeJsonHeader(headerB64);

  return { headerB64, payloadB64, signatureB64, header };
}

/**
 * Opaque witness that a `ParsedJws`'s signature has been checked against
 * a specific public key. Branded with a `unique symbol` that this module
 * never exports — not merely a `{ __brand: "..." }` string tag, which
 * *any* caller could fabricate with an ordinary object literal and
 * structural typing would accept. A symbol-keyed property can only be
 * produced by code that has a reference to that exact symbol value, and
 * the only such reference lives in this module's closure. There is
 * therefore no way, from outside this file, to construct a value of this
 * type except by calling `verifySignature` and having it succeed — see
 * the module comment for why this matters.
 */
const SIGNATURE_VERIFIED = Symbol("SignatureVerified");
export interface SignatureVerified {
  readonly [SIGNATURE_VERIFIED]: true;
}
const VERIFIED_TOKEN: SignatureVerified = Object.freeze({ [SIGNATURE_VERIFIED]: true as const });

/**
 * Serialise a value with `JSON.stringify` and base64url-encode the UTF-8
 * bytes. Used identically for both the header and the payload — JWS signs
 * the literal transmitted bytes of both segments, so there is no
 * canonicalisation step and therefore no canonicalisation-mismatch risk
 * against another JWS implementation: a verifier (ours or `jose`'s) never
 * re-serialises either segment, it only re-decodes the exact bytes that
 * were signed.
 */
function encodeJsonSegment(value: unknown): string {
  return encodeBase64Url(utf8ToBytes(JSON.stringify(value)));
}

/** Build the exact ASCII bytes a JWS signs: `base64url(header) + "." + base64url(payload)`. */
function signingInputBytes(headerB64: string, payloadB64: string): Uint8Array {
  return utf8ToBytes(`${headerB64}.${payloadB64}`);
}

/**
 * Sign `payload` as a compact JWS with `EdDSA` (Ed25519), asserting the
 * header names `kid` (the issuer's did:key verification method) so a
 * verifier can recover the correct public key from transport metadata
 * alone, before it ever parses the payload.
 */
export function signCompactJws(payload: unknown, kid: string, privateKey: Uint8Array): string {
  const header: JwsHeader = { alg: ALLOWED_ALG, kid, typ: VC_JWT_TYP };
  const headerB64 = encodeJsonSegment(header);
  const payloadB64 = encodeJsonSegment(payload);
  const signature = ed25519.sign(signingInputBytes(headerB64, payloadB64), privateKey);
  return `${headerB64}.${payloadB64}.${encodeBase64Url(signature)}`;
}

/**
 * Verify a parsed JWS's signature against `publicKey`. This is the ONLY
 * function in this module that reads `header.alg` — and it reads it to
 * REJECT anything but the one algorithm this verifier supports, never to
 * select which verification routine to run. That distinction is the
 * entire defense against algorithm-confusion attacks (including
 * `alg: "none"`): the set of algorithms this code is willing to execute
 * is a hardcoded constant (`ALLOWED_ALG`), not a value read from
 * attacker-controlled input.
 *
 * Returns a `SignatureVerified` witness on success. Throws
 * `AlgorithmNotAllowedError` or `SignatureVerificationFailedError`
 * otherwise — never returns a falsy witness, so a caller can't
 * accidentally treat "verification object present" as "verified".
 */
export function verifySignature(parsed: ParsedJws, publicKey: Uint8Array): SignatureVerified {
  if (parsed.header.alg !== ALLOWED_ALG) {
    throw new AlgorithmNotAllowedError(parsed.header.alg);
  }

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = decodeBase64Url(parsed.signatureB64);
  } catch {
    throw new SignatureVerificationFailedError();
  }

  const message = signingInputBytes(parsed.headerB64, parsed.payloadB64);

  let isValid: boolean;
  try {
    isValid = ed25519.verify(signatureBytes, message, publicKey);
  } catch {
    // Malformed signature bytes (wrong length, invalid curve point) are a
    // verification failure, not a crash — fail closed either way, same
    // posture as M1's `verifyPossession`.
    isValid = false;
  }

  if (!isValid) {
    throw new SignatureVerificationFailedError();
  }

  return VERIFIED_TOKEN;
}

/**
 * Decode a JWS payload to a JSON value. Requires a `SignatureVerified`
 * witness for the SAME parsed JWS, so this can only be called after
 * `verifySignature` has already succeeded for it — see the module
 * comment. Still fails closed with a typed error if the (now verified,
 * but not yet structurally validated) bytes aren't valid JSON.
 */
export function decodeVerifiedPayload(parsed: ParsedJws, _proof: SignatureVerified): unknown {
  let payloadBytes: Uint8Array;
  try {
    payloadBytes = decodeBase64Url(parsed.payloadB64);
  } catch (cause) {
    throw new MalformedJwsError("payload is not valid base64url", { cause });
  }
  try {
    return JSON.parse(new TextDecoder().decode(payloadBytes));
  } catch (cause) {
    throw new MalformedJwsError("payload is not valid JSON", { cause });
  }
}
