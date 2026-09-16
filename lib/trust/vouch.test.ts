import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { encodeDidKey, generateKeyPair, type Did } from "../identity/index.js";
import { VC_CONTEXT_V2, encodeBase64Url, verificationMethodId } from "../credentials/index.js";
import { issueVouch, verifyVouch, VOUCH_TYPE, VOUCHED_CAPABILITY_IDENTITY } from "./vouch.js";
import { signCompact } from "./jws-lite.js";

interface Identity {
  readonly publicKey: Uint8Array;
  readonly privateKey: Uint8Array;
  readonly did: Did;
}

function makeIdentity(): Identity {
  const { publicKey, privateKey } = generateKeyPair();
  return { publicKey, privateKey, did: encodeDidKey(publicKey) };
}

/** Same forging helper as `status-list.test.ts` — see its comment. */
function forgeValidSignatureOverNonJsonPayload(signer: Identity, rawPayloadText: string): string {
  const headerB64 = encodeBase64Url(utf8ToBytes(JSON.stringify({ alg: "EdDSA", kid: verificationMethodId(signer.did), typ: "vc+jwt" })));
  const payloadB64 = encodeBase64Url(utf8ToBytes(rawPayloadText));
  const signingInput = utf8ToBytes(`${headerB64}.${payloadB64}`);
  const signatureB64 = encodeBase64Url(ed25519.sign(signingInput, signer.privateKey));
  return `${headerB64}.${payloadB64}.${signatureB64}`;
}

describe("issueVouch / verifyVouch — happy path", () => {
  it("verifies a genuine vouch and names the voucher", () => {
    const anchor = makeIdentity();
    const vouched = makeIdentity();
    const jwt = issueVouch({
      voucherPrivateKey: anchor.privateKey,
      voucherDid: anchor.did,
      vouchedIssuerDid: vouched.did,
      now: 0,
    });

    const result = verifyVouch(jwt, { now: 0 });
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected success");
    expect(result.voucher).toBe(anchor.did);
    expect(result.vouch.credentialSubject.id).toBe(vouched.did);
    expect(result.vouch.credentialSubject.vouchedCapability).toBe("identity");
  });
});

describe("a vouch whose own signature fails is refused", () => {
  it("rejects a vouch signed by a different key than its claimed issuer", () => {
    const anchor = makeIdentity();
    const mallory = makeIdentity();
    const vouched = makeIdentity();

    const payload = {
      "@context": [VC_CONTEXT_V2],
      type: ["VerifiableCredential", VOUCH_TYPE],
      issuer: anchor.did,
      iss: anchor.did,
      validFrom: new Date(0).toISOString(),
      credentialSubject: { id: vouched.did, vouchedCapability: VOUCHED_CAPABILITY_IDENTITY },
    };
    // Signed by Mallory but naming Anchor's kid in the header — forged.
    const forged = signCompact(payload, verificationMethodId(anchor.did), mallory.privateKey);

    const result = verifyVouch(forged, { now: 0 });
    expect(result.ok).toBe(false);
  });

  it("rejects a vouch whose bytes were tampered with after signing", () => {
    const anchor = makeIdentity();
    const vouched = makeIdentity();
    const other = makeIdentity();
    const jwt = issueVouch({
      voucherPrivateKey: anchor.privateKey,
      voucherDid: anchor.did,
      vouchedIssuerDid: vouched.did,
      now: 0,
    });
    const [header, , signature] = jwt.split(".");
    const tamperedPayload = encodeBase64Url(
      utf8ToBytes(
        JSON.stringify({
          "@context": [VC_CONTEXT_V2],
          type: ["VerifiableCredential", VOUCH_TYPE],
          issuer: anchor.did,
          iss: anchor.did,
          validFrom: new Date(0).toISOString(),
          credentialSubject: { id: other.did, vouchedCapability: VOUCHED_CAPABILITY_IDENTITY },
        }),
      ),
    );
    const tampered = `${header}.${tamperedPayload}.${signature}`;

    const result = verifyVouch(tampered, { now: 0 });
    expect(result.ok).toBe(false);
  });
});

describe("expiry", () => {
  it("rejects a vouch presented after its validUntil", () => {
    const anchor = makeIdentity();
    const vouched = makeIdentity();
    const jwt = issueVouch({
      voucherPrivateKey: anchor.privateKey,
      voucherDid: anchor.did,
      vouchedIssuerDid: vouched.did,
      validFrom: "2026-01-01T00:00:00Z",
      validUntil: "2026-06-01T00:00:00Z",
      now: Date.parse("2026-01-01T00:00:00Z"),
    });

    const result = verifyVouch(jwt, { now: Date.parse("2026-07-01T00:00:00Z") });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected failure");
    expect(result.reason).toMatch(/expired/i);
  });

  it("accepts a vouch with no validUntil at all", () => {
    const anchor = makeIdentity();
    const vouched = makeIdentity();
    const jwt = issueVouch({
      voucherPrivateKey: anchor.privateKey,
      voucherDid: anchor.did,
      vouchedIssuerDid: vouched.did,
      now: 0,
    });
    const result = verifyVouch(jwt, { now: 1_000_000_000_000 });
    expect(result.ok).toBe(true);
  });
});

describe("structural enforcement: a vouch can only ever claim identity, never authority", () => {
  it("rejects a forged vouch whose credentialSubject.vouchedCapability claims \"authority\"", () => {
    const anchor = makeIdentity();
    const vouched = makeIdentity();

    // issueVouch's own API has no parameter for `vouchedCapability` at
    // all — it is hardcoded to VOUCHED_CAPABILITY_IDENTITY — so proving
    // this rejection means hand-forging a payload that claims something
    // else, exactly the way verify.test.ts forges tampered credentials.
    const payload = {
      "@context": [VC_CONTEXT_V2],
      type: ["VerifiableCredential", VOUCH_TYPE],
      issuer: anchor.did,
      iss: anchor.did,
      validFrom: new Date(0).toISOString(),
      credentialSubject: { id: vouched.did, vouchedCapability: "authority" },
    };
    const forged = signCompact(payload, verificationMethodId(anchor.did), anchor.privateKey);

    const result = verifyVouch(forged, { now: 0 });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected failure");
    expect(result.reason).toMatch(/vouchedCapability/);
  });
});

describe("malformed vouches fail closed, never an unhandled throw", () => {
  it("rejects a non-JWS garbage string without throwing", () => {
    expect(() => verifyVouch("not-a-jws")).not.toThrow();
    expect(verifyVouch("not-a-jws").ok).toBe(false);
  });

  it("fails closed, never throws, for a REAL signature over a non-JSON payload (M3 finding-0 bug class)", () => {
    const anchor = makeIdentity();
    const forged = forgeValidSignatureOverNonJsonPayload(anchor, "not json at all");

    let result: ReturnType<typeof verifyVouch> | undefined;
    expect(() => {
      result = verifyVouch(forged, { now: 0 });
    }).not.toThrow();
    expect(result?.ok).toBe(false);
  });

  it("rejects a vouch of the wrong VC type", () => {
    const anchor = makeIdentity();
    const vouched = makeIdentity();
    const payload = {
      "@context": [VC_CONTEXT_V2],
      type: ["VerifiableCredential", "SomethingElse"],
      issuer: anchor.did,
      iss: anchor.did,
      validFrom: new Date(0).toISOString(),
      credentialSubject: { id: vouched.did, vouchedCapability: VOUCHED_CAPABILITY_IDENTITY },
    };
    const jwt = signCompact(payload, verificationMethodId(anchor.did), anchor.privateKey);
    const result = verifyVouch(jwt, { now: 0 });
    expect(result.ok).toBe(false);
  });
});
