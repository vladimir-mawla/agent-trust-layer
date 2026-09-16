import { describe, expect, it } from "vitest";
import { generateKeyPair, encodeDidKey } from "../identity/index.js";
import { encodeBase64Url } from "./base64url.js";
import {
  AlgorithmNotAllowedError,
  MalformedJwsError,
  SignatureVerificationFailedError,
} from "./errors.js";
import {
  MAX_JWS_LENGTH,
  decodeVerifiedPayload,
  parseCompactJws,
  signCompactJws,
  verifySignature,
  type SignatureVerified,
} from "./jws.js";

function issuer() {
  const keyPair = generateKeyPair();
  return { ...keyPair, did: encodeDidKey(keyPair.publicKey) };
}

describe("signCompactJws / verifySignature / decodeVerifiedPayload round trip", () => {
  it("signs a payload and verifies it against the signer's own public key", () => {
    const alice = issuer();
    const jws = signCompactJws({ hello: "world" }, alice.did, alice.privateKey);

    const parsed = parseCompactJws(jws);
    expect(parsed.header.alg).toBe("EdDSA");
    expect(parsed.header.kid).toBe(alice.did);

    const token = verifySignature(parsed, alice.publicKey);
    expect(decodeVerifiedPayload(parsed, token)).toEqual({ hello: "world" });
  });

  it("HEADLINE: verifying against the WRONG public key fails", () => {
    const alice = issuer();
    const mallory = issuer();
    const jws = signCompactJws({ hello: "world" }, alice.did, alice.privateKey);
    const parsed = parseCompactJws(jws);

    expect(() => verifySignature(parsed, mallory.publicKey)).toThrow(SignatureVerificationFailedError);
  });
});

describe("tampering is detected", () => {
  it("rejects a payload with one byte changed after signing", () => {
    const alice = issuer();
    const jws = signCompactJws({ amount: 500 }, alice.did, alice.privateKey);
    const [headerB64, payloadB64, signatureB64] = jws.split(".");

    // Re-encode a claim with the amount bumped, keeping everything else
    // (including the signature) untouched — simulates an attacker
    // editing the decoded JSON and re-serialising it.
    const tamperedPayloadB64 = encodeBase64Url(new TextEncoder().encode('{"amount":50000}'));
    const tampered = `${headerB64}.${tamperedPayloadB64}.${signatureB64}`;

    const parsed = parseCompactJws(tampered);
    expect(() => verifySignature(parsed, alice.publicKey)).toThrow(SignatureVerificationFailedError);
    void payloadB64;
  });

  it("rejects a header with the alg switched after signing", () => {
    const alice = issuer();
    const jws = signCompactJws({ hello: "world" }, alice.did, alice.privateKey);
    const [, payloadB64, signatureB64] = jws.split(".");

    const tamperedHeaderB64 = encodeBase64Url(
      new TextEncoder().encode(JSON.stringify({ alg: "HS256", kid: alice.did })),
    );
    const tampered = `${tamperedHeaderB64}.${payloadB64}.${signatureB64}`;

    const parsed = parseCompactJws(tampered);
    expect(() => verifySignature(parsed, alice.publicKey)).toThrow(AlgorithmNotAllowedError);
  });
});

describe("algorithm confusion is rejected outright, not merely mismatched", () => {
  it('rejects alg: "none" even when the signature segment is empty-ish garbage', () => {
    const alice = issuer();
    const header = encodeBase64Url(new TextEncoder().encode(JSON.stringify({ alg: "none", kid: alice.did })));
    const payload = encodeBase64Url(new TextEncoder().encode(JSON.stringify({ hello: "world" })));
    // "none" algorithm attacks classically ship an empty-ish/junk
    // signature (there's nothing real to check). A single placeholder
    // byte keeps the segment non-empty (an empty segment would instead
    // be rejected at `parseCompactJws` for being malformed, which is a
    // different failure this test isn't about) while still being
    // nowhere near a real Ed25519 signature.
    const signature = encodeBase64Url(new Uint8Array([0]));
    const forged = `${header}.${payload}.${signature}`;

    const parsed = parseCompactJws(forged);
    expect(parsed.header.alg).toBe("none");
    expect(() => verifySignature(parsed, alice.publicKey)).toThrow(AlgorithmNotAllowedError);
  });

  it("never lets the header's own alg value select the verification routine", () => {
    // Even a syntactically-plausible OTHER algorithm name must fail the
    // same way "none" does — the allowlist is a hardcoded constant, not
    // a branch keyed on whatever the token claims.
    const alice = issuer();
    const jws = signCompactJws({ hello: "world" }, alice.did, alice.privateKey);
    const [, payloadB64, signatureB64] = jws.split(".");
    const rs256Header = encodeBase64Url(new TextEncoder().encode(JSON.stringify({ alg: "RS256", kid: alice.did })));
    const forged = `${rs256Header}.${payloadB64}.${signatureB64}`;

    expect(() => verifySignature(parseCompactJws(forged), alice.publicKey)).toThrow(AlgorithmNotAllowedError);
  });
});

describe("parseCompactJws rejects structurally malformed input with a typed error, never an unhandled throw", () => {
  it("rejects an empty string", () => {
    expect(() => parseCompactJws("")).toThrow(MalformedJwsError);
  });

  it("rejects a token with only two segments", () => {
    expect(() => parseCompactJws("abc.def")).toThrow(MalformedJwsError);
  });

  it("rejects a token with four segments", () => {
    expect(() => parseCompactJws("abc.def.ghi.jkl")).toThrow(MalformedJwsError);
  });

  it("rejects a token with an empty segment", () => {
    expect(() => parseCompactJws("abc..ghi")).toThrow(MalformedJwsError);
  });

  it("rejects garbage (non-base64url) characters in a segment", () => {
    expect(() => parseCompactJws("abc.not valid base64!.ghi")).toThrow(MalformedJwsError);
  });

  it("rejects a header that isn't valid JSON", () => {
    const notJson = encodeBase64Url(new TextEncoder().encode("not json"));
    const payload = encodeBase64Url(new TextEncoder().encode("{}"));
    expect(() => parseCompactJws(`${notJson}.${payload}.sig`)).toThrow(MalformedJwsError);
  });

  it('rejects a header missing "kid"', () => {
    const header = encodeBase64Url(new TextEncoder().encode(JSON.stringify({ alg: "EdDSA" })));
    const payload = encodeBase64Url(new TextEncoder().encode("{}"));
    expect(() => parseCompactJws(`${header}.${payload}.sig`)).toThrow(MalformedJwsError);
  });

  it("rejects a token exceeding the maximum length (huge payload)", () => {
    const huge = "a".repeat(MAX_JWS_LENGTH + 1);
    expect(() => parseCompactJws(huge)).toThrow(MalformedJwsError);
  });

  it("never JSON.parses the payload segment during parsing, even if it's garbage bytes", () => {
    // A payload segment that decodes to valid base64url bytes but is NOT
    // valid JSON must still parse fine at this stage — decoding to JSON
    // only happens after signature verification (decodeVerifiedPayload).
    const header = encodeBase64Url(new TextEncoder().encode(JSON.stringify({ alg: "EdDSA", kid: "did:key:zAbc" })));
    const notJsonPayload = encodeBase64Url(new TextEncoder().encode("this is not json at all {{{"));
    const signature = encodeBase64Url(new Uint8Array(8));
    expect(() => parseCompactJws(`${header}.${notJsonPayload}.${signature}`)).not.toThrow();
  });
});

describe("decodeVerifiedPayload requires proof the signature already verified", () => {
  it("cannot be called without a SignatureVerified witness (compile-time only — see below)", () => {
    // This test asserts the *documentation* of the invariant; the real
    // proof is that the following would fail `npm run typecheck`:
    //
    //   declare const parsed: ReturnType<typeof parseCompactJws>;
    //   // @ts-expect-error — no SignatureVerified witness available
    //   decodeVerifiedPayload(parsed, {});
    //
    // `{}` does not have the module-private symbol key `SignatureVerified`
    // requires, so no value constructible outside `jws.ts` satisfies the
    // second parameter's type.
    expect(typeof decodeVerifiedPayload).toBe("function");
  });

  it("type-level: an arbitrary object literal does not satisfy SignatureVerified", () => {
    function requiresWitness(_proof: SignatureVerified): void {
      void _proof;
    }
    function typeLevelProof() {
      // @ts-expect-error — {} lacks the module-private branding symbol;
      // if this stops erroring, decodeVerifiedPayload's trust-boundary
      // guarantee has been silently weakened.
      requiresWitness({});
    }
    void typeLevelProof;
    expect(typeof requiresWitness).toBe("function");
  });
});
