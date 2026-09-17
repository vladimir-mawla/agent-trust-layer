/**
 * M3_STEP_LABEL: proves `refineParseFailure` actually distinguishes the
 * two "parse"-step failures `lib/credentials/verify.ts` deliberately
 * reports identically — see that module's own comment, and
 * `verification-step-detail.ts`'s module comment for the full
 * reasoning. Pinned against a REAL fabricated JWS (a genuine Ed25519
 * signature over genuinely non-JSON bytes), the same fabrication
 * pattern `lib/trust/jws-lite.test.ts` uses, so this test fails loudly
 * if `lib/credentials`'s message ever changes instead of silently
 * losing the distinction.
 */
import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { createChallenge, encodeDidKey, generateKeyPair, provePossession } from "../identity/index.js";
import { encodeBase64Url, verificationMethodId, verifyAuthorityCredential } from "../credentials/index.js";
import { refineParseFailure } from "./verification-step-detail.js";

function encodeJsonSegment(value: unknown): string {
  return encodeBase64Url(utf8ToBytes(JSON.stringify(value)));
}

describe("refineParseFailure", () => {
  it("labels a real signature over non-JSON bytes as post-signature-payload-not-json", () => {
    const signer = generateKeyPair();
    const signerDid = encodeDidKey(signer.publicKey);

    const headerB64 = encodeJsonSegment({ alg: "EdDSA", kid: verificationMethodId(signerDid), typ: "vc+jwt" });
    const payloadB64 = encodeBase64Url(utf8ToBytes("not json at all {{{"));
    const signature = ed25519.sign(utf8ToBytes(`${headerB64}.${payloadB64}`), signer.privateKey);
    const jwt = `${headerB64}.${payloadB64}.${encodeBase64Url(signature)}`;

    const subject = generateKeyPair();
    const subjectDid = encodeDidKey(subject.publicKey);
    const challenge = createChallenge({ now: 0, ttlMs: 60_000 });
    const presenterProof = provePossession(subject.privateKey, subjectDid, challenge);

    const result = verifyAuthorityCredential(jwt, presenterProof, { now: 0 });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected verification failure");
    expect(result.step).toBe("parse");

    expect(refineParseFailure(result.step, result.reason)).toBe("post-signature-payload-not-json");
  });

  it("labels a pre-signature wire-format failure as pre-signature", () => {
    const subject = generateKeyPair();
    const subjectDid = encodeDidKey(subject.publicKey);
    const challenge = createChallenge({ now: 0, ttlMs: 60_000 });
    const presenterProof = provePossession(subject.privateKey, subjectDid, challenge);

    // Not even a well-formed 3-segment compact JWS — no signature was
    // ever checked, unlike the case above.
    const result = verifyAuthorityCredential("this-is-not-a-jws-at-all", presenterProof, { now: 0 });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected verification failure");
    expect(result.step).toBe("parse");

    expect(refineParseFailure(result.step, result.reason)).toBe("pre-signature");
  });

  it("returns not-applicable for any step other than parse", () => {
    expect(refineParseFailure("signature", "JWS signature verification failed")).toBe("not-applicable");
    expect(refineParseFailure("structure", 'expected credential type "AuthorityCredential"')).toBe("not-applicable");
  });
});
