/**
 * FINDING 4 regression: `jws-lite.ts`'s own module comment claims it is
 * "independently tested (`jws-lite.test.ts`)" — before this file existed,
 * that claim was false; an L4 review ran this exact algorithm-confusion
 * battery manually and all cases passed, but nothing in the automated
 * suite covered them. This file makes the claim true.
 *
 * Every case below is a variant of "the token's header claims an
 * algorithm this verifier does not accept" (or isn't shaped like an
 * algorithm claim at all), and every one MUST be refused. The defense
 * these tests exist to prove is `verifyCompactAndDecode`'s (and
 * `lib/credentials/jws.ts`'s `verifySignature`'s, which it mirrors):
 * `header.alg` is read ONLY to reject anything but the hardcoded
 * `ALLOWED_ALG` ("EdDSA"), never to select which verification routine to
 * run — see `jws-lite.ts`'s and `lib/credentials/jws.ts`'s module
 * comments.
 */
import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { encodeDidKey, generateKeyPair, type Did } from "../identity/index.js";
import { MAX_JWS_LENGTH, MalformedJwsError, encodeBase64Url, verificationMethodId } from "../credentials/index.js";
import { AlgorithmNotAllowedError, SignatureVerificationFailedError } from "./errors.js";
import { SyntaxErrorAsPayloadError, signCompact, verifyCompactAndDecode } from "./jws-lite.js";

interface Identity {
  readonly publicKey: Uint8Array;
  readonly privateKey: Uint8Array;
  readonly did: Did;
}

function makeIdentity(): Identity {
  const { publicKey, privateKey } = generateKeyPair();
  return { publicKey, privateKey, did: encodeDidKey(publicKey) };
}

function b64Json(value: unknown): string {
  return encodeBase64Url(utf8ToBytes(JSON.stringify(value)));
}

/**
 * Build a raw compact JWS with an arbitrary (possibly malformed) header
 * value, an arbitrary payload, and an arbitrary raw signature segment —
 * bypassing `signCompact` entirely so a test can put something in the
 * `alg` slot that `signCompact`'s own typed header would never produce.
 */
function rawJws(header: unknown, payload: unknown, signatureB64: string): string {
  const headerB64 = b64Json(header);
  const payloadB64 = b64Json(payload);
  return `${headerB64}.${payloadB64}.${signatureB64}`;
}

/** A signature segment that is valid base64url (so `parseCompactJws`'s
 *  transport-shape check doesn't reject it before the `alg` check even
 *  runs) but is not a real Ed25519 signature over anything. Stands in for
 *  "whatever junk an attacker put in the signature slot" across every
 *  case where the point being proven is that `alg` alone gets a token
 *  refused, regardless of what the signature bytes are. */
const JUNK_SIGNATURE_B64 = encodeBase64Url(new Uint8Array(64));

const SAMPLE_PAYLOAD = { hello: "world" };

describe("jws-lite algorithm-confusion battery (FINDING 4) — every case must be refused", () => {
  it('refuses alg: "none" (the classic JWT algorithm-confusion attack)', () => {
    const signer = makeIdentity();
    const jws = rawJws({ alg: "none", kid: verificationMethodId(signer.did), typ: "vc+jwt" }, SAMPLE_PAYLOAD, JUNK_SIGNATURE_B64);

    expect(() => verifyCompactAndDecode(jws, signer.publicKey)).toThrow(AlgorithmNotAllowedError);
  });

  it('refuses alg: "HS256" even when "signed" with a valid HMAC using the issuer\'s PUBLIC KEY as the secret', () => {
    const signer = makeIdentity();
    const header = { alg: "HS256", kid: verificationMethodId(signer.did), typ: "vc+jwt" };
    const headerB64 = b64Json(header);
    const payloadB64 = b64Json(SAMPLE_PAYLOAD);
    // The classic RS256->HS256 (here EdDSA->HS256) downgrade: an attacker
    // who knows the verifier's PUBLIC key computes a genuine HMAC using
    // that public key as the shared secret, hoping a naive verifier that
    // dispatches on `alg` will "verify" it as HMAC and accept it. This
    // signature is a REAL, correctly-computed HMAC-SHA256 -- not garbage
    // -- so the only thing that can refuse it is the hardcoded alg check.
    const mac = createHmac("sha256", Buffer.from(signer.publicKey)).update(`${headerB64}.${payloadB64}`).digest();
    const jws = `${headerB64}.${payloadB64}.${encodeBase64Url(mac)}`;

    expect(() => verifyCompactAndDecode(jws, signer.publicKey)).toThrow(AlgorithmNotAllowedError);
  });

  it('refuses alg: "RS256"', () => {
    const signer = makeIdentity();
    const jws = rawJws({ alg: "RS256", kid: verificationMethodId(signer.did), typ: "vc+jwt" }, SAMPLE_PAYLOAD, JUNK_SIGNATURE_B64);

    expect(() => verifyCompactAndDecode(jws, signer.publicKey)).toThrow(AlgorithmNotAllowedError);
  });

  it('refuses alg: "EDDSA" (wrong case) even with a REAL, otherwise-valid Ed25519 signature', () => {
    const signer = makeIdentity();
    // A genuinely correct signature -- if the alg comparison were
    // case-insensitive, this token would incorrectly verify. It must not.
    const header = { alg: "EDDSA", kid: verificationMethodId(signer.did), typ: "vc+jwt" };
    const headerB64 = b64Json(header);
    const payloadB64 = b64Json(SAMPLE_PAYLOAD);
    const signature = ed25519.sign(utf8ToBytes(`${headerB64}.${payloadB64}`), signer.privateKey);
    const jws = `${headerB64}.${payloadB64}.${encodeBase64Url(signature)}`;

    expect(() => verifyCompactAndDecode(jws, signer.publicKey)).toThrow(AlgorithmNotAllowedError);
  });

  it('refuses alg: "eddsa" (wrong case) even with a REAL, otherwise-valid Ed25519 signature', () => {
    const signer = makeIdentity();
    const header = { alg: "eddsa", kid: verificationMethodId(signer.did), typ: "vc+jwt" };
    const headerB64 = b64Json(header);
    const payloadB64 = b64Json(SAMPLE_PAYLOAD);
    const signature = ed25519.sign(utf8ToBytes(`${headerB64}.${payloadB64}`), signer.privateKey);
    const jws = `${headerB64}.${payloadB64}.${encodeBase64Url(signature)}`;

    expect(() => verifyCompactAndDecode(jws, signer.publicKey)).toThrow(AlgorithmNotAllowedError);
  });

  it('refuses alg: "EdDSA " (trailing space) even with a REAL, otherwise-valid Ed25519 signature', () => {
    const signer = makeIdentity();
    // Same shape as the case-sensitivity cases: proves the comparison is
    // an exact string match, not a trimmed/normalized one.
    const header = { alg: "EdDSA ", kid: verificationMethodId(signer.did), typ: "vc+jwt" };
    const headerB64 = b64Json(header);
    const payloadB64 = b64Json(SAMPLE_PAYLOAD);
    const signature = ed25519.sign(utf8ToBytes(`${headerB64}.${payloadB64}`), signer.privateKey);
    const jws = `${headerB64}.${payloadB64}.${encodeBase64Url(signature)}`;

    expect(() => verifyCompactAndDecode(jws, signer.publicKey)).toThrow(AlgorithmNotAllowedError);
  });

  it("refuses a header with `alg` absent entirely", () => {
    const signer = makeIdentity();
    const jws = rawJws({ kid: verificationMethodId(signer.did), typ: "vc+jwt" }, SAMPLE_PAYLOAD, JUNK_SIGNATURE_B64);

    // `alg` absent fails `parseCompactJws`'s own header-shape check
    // (it requires a string `alg`) before `verifyCompactAndDecode`'s own
    // `alg !== ALLOWED_ALG` check ever runs -- still refused, just by a
    // different typed error (MalformedJwsError, re-exported from
    // lib/credentials) rather than AlgorithmNotAllowedError.
    expect(() => verifyCompactAndDecode(jws, signer.publicKey)).toThrow(MalformedJwsError);
  });

  it("refuses a header with `alg` as a number", () => {
    const signer = makeIdentity();
    const jws = rawJws({ alg: 256, kid: verificationMethodId(signer.did), typ: "vc+jwt" }, SAMPLE_PAYLOAD, JUNK_SIGNATURE_B64);

    expect(() => verifyCompactAndDecode(jws, signer.publicKey)).toThrow(MalformedJwsError);
  });

  it("refuses a header with `alg` as an array", () => {
    const signer = makeIdentity();
    const jws = rawJws({ alg: ["EdDSA"], kid: verificationMethodId(signer.did), typ: "vc+jwt" }, SAMPLE_PAYLOAD, JUNK_SIGNATURE_B64);

    expect(() => verifyCompactAndDecode(jws, signer.publicKey)).toThrow(MalformedJwsError);
  });
});

describe("jws-lite: size cap (FINDING 4)", () => {
  it("refuses a token exceeding MAX_JWS_LENGTH", () => {
    const signer = makeIdentity();
    const hugePayload = { filler: "x".repeat(MAX_JWS_LENGTH) };
    const jws = signCompact(hugePayload, verificationMethodId(signer.did), signer.privateKey);

    expect(jws.length).toBeGreaterThan(MAX_JWS_LENGTH);
    expect(() => verifyCompactAndDecode(jws, signer.publicKey)).toThrow(MalformedJwsError);
  });
});

describe("jws-lite: signature is checked BEFORE the payload is ever JSON.parsed (FINDING 4)", () => {
  it("an invalid signature over a non-JSON payload fails as a signature error, never a JSON parse error", () => {
    const signer = makeIdentity();
    const impostor = makeIdentity();
    // Real header naming `signer`, payload bytes that are not valid JSON
    // at all, but signed by a DIFFERENT key (`impostor`) than the one
    // verification will check against (`signer.publicKey`) -- so the
    // signature check must fail first. If the implementation ever
    // reordered this (parse-then-verify), this would instead surface as
    // a JSON-parse failure, which would be the exact bug class M3 was
    // once rejected for leaving unguarded, just inverted.
    const headerB64 = encodeBase64Url(utf8ToBytes(JSON.stringify({ alg: "EdDSA", kid: verificationMethodId(signer.did), typ: "vc+jwt" })));
    const payloadB64 = encodeBase64Url(utf8ToBytes("not json at all"));
    const signature = ed25519.sign(utf8ToBytes(`${headerB64}.${payloadB64}`), impostor.privateKey);
    const jws = `${headerB64}.${payloadB64}.${encodeBase64Url(signature)}`;

    expect(() => verifyCompactAndDecode(jws, signer.publicKey)).toThrow(SignatureVerificationFailedError);
  });

  it("a REAL signature over a non-JSON payload fails closed as SyntaxErrorAsPayloadError, only after the signature verified", () => {
    const signer = makeIdentity();
    const headerB64 = encodeBase64Url(utf8ToBytes(JSON.stringify({ alg: "EdDSA", kid: verificationMethodId(signer.did), typ: "vc+jwt" })));
    const payloadB64 = encodeBase64Url(utf8ToBytes("not json at all"));
    const signature = ed25519.sign(utf8ToBytes(`${headerB64}.${payloadB64}`), signer.privateKey);
    const jws = `${headerB64}.${payloadB64}.${encodeBase64Url(signature)}`;

    expect(() => verifyCompactAndDecode(jws, signer.publicKey)).toThrow(SyntaxErrorAsPayloadError);
  });
});

describe("jws-lite: happy path (sanity — signCompact/verifyCompactAndDecode round-trip)", () => {
  it("signs and verifies a real payload, decoding it back to an equal JSON value", () => {
    const signer = makeIdentity();
    const jws = signCompact(SAMPLE_PAYLOAD, verificationMethodId(signer.did), signer.privateKey);

    const { payload } = verifyCompactAndDecode(jws, signer.publicKey);

    expect(payload).toEqual(SAMPLE_PAYLOAD);
  });

  it("rejects a valid token verified against the WRONG public key", () => {
    const signer = makeIdentity();
    const notSigner = makeIdentity();
    const jws = signCompact(SAMPLE_PAYLOAD, verificationMethodId(signer.did), signer.privateKey);

    expect(() => verifyCompactAndDecode(jws, notSigner.publicKey)).toThrow(SignatureVerificationFailedError);
  });
});
