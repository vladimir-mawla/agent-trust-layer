/**
 * Interoperability proof: our own code verifying our own credentials
 * only proves self-consistency (see M3's task brief). This file proves
 * standards conformance instead, using `jose` — an independent,
 * well-maintained JWS implementation, kept a devDependency only (see
 * `package.json`; it must never appear in `dependencies` or be imported
 * from anywhere under production `lib/` code) — as a genuinely separate
 * JWS engine that knows nothing about this project's did:key or VC
 * types.
 *
 * Both directions are tested:
 *   - credentials WE sign, verified by `jose` using a public key
 *     recovered INDEPENDENTLY from the did:key (via `decodeDidKey`, not
 *     via anything `jose` derives).
 *   - a JWT `jose` signs, accepted by OUR verifier (`jws.ts` directly,
 *     and the FULL `verifyAuthorityCredential` chain).
 *
 * If these disagreed on anything — base64url padding, JSON
 * canonicalisation, header fields, `crv`/`alg` naming — that would be a
 * real interop finding to report, not something to paper over by
 * loosening our verifier. They do not disagree; see the M3 report for
 * why (JWS signs literal transmitted bytes, so there is no
 * canonicalisation step for the two implementations to disagree about).
 */
import { describe, expect, it } from "vitest";
import * as jose from "jose";
import {
  createChallenge,
  decodeDidKey,
  encodeDidKey,
  generateKeyPair,
  provePossession,
  type Did,
} from "../identity/index.js";
import { encodeBase64Url } from "./base64url.js";
import { verificationMethodId } from "./credential.js";
import { issueAuthorityCredential } from "./authority.js";
import { decodeVerifiedPayload, parseCompactJws, signCompactJws, verifySignature } from "./jws.js";
import { verifyAuthorityCredential } from "./verify.js";
import { AUTHORITY_CREDENTIAL_TYPE, VC_BASE_TYPE, VC_CONTEXT_V2 } from "./vc-types.js";

interface Identity {
  readonly publicKey: Uint8Array;
  readonly privateKey: Uint8Array;
  readonly did: Did;
}

function makeIdentity(): Identity {
  const { publicKey, privateKey } = generateKeyPair();
  return { publicKey, privateKey, did: encodeDidKey(publicKey) };
}

/** A public JWK for `jose`, built from key bytes recovered independently
 *  from a did:key via THIS PROJECT's own `decodeDidKey` — not from
 *  anything `jose` itself parses or trusts. */
function publicJwkFromDid(did: Did) {
  const publicKey = decodeDidKey(did);
  return { kty: "OKP", crv: "Ed25519", x: encodeBase64Url(publicKey) } as const;
}

function privateJwkFrom(identity: Identity) {
  return {
    kty: "OKP",
    crv: "Ed25519",
    x: encodeBase64Url(identity.publicKey),
    d: encodeBase64Url(identity.privateKey),
  } as const;
}

describe("interop: jose verifies a raw JWS signed by our jws.ts", () => {
  it("accepts our signature and recovers the identical payload", async () => {
    const issuer = makeIdentity();
    const jwt = signCompactJws({ hello: "world" }, verificationMethodId(issuer.did), issuer.privateKey);

    const publicKey = await jose.importJWK(publicJwkFromDid(issuer.did), "EdDSA");
    const { payload, protectedHeader } = await jose.compactVerify(jwt, publicKey);

    expect(protectedHeader.alg).toBe("EdDSA");
    expect(protectedHeader.kid).toBe(verificationMethodId(issuer.did));
    expect(JSON.parse(new TextDecoder().decode(payload))).toEqual({ hello: "world" });
  });

  it("jose also rejects a byte-tampered payload signed by us", async () => {
    const issuer = makeIdentity();
    const jwt = signCompactJws({ amount: 500 }, verificationMethodId(issuer.did), issuer.privateKey);
    const [header, , signature] = jwt.split(".");
    const tamperedPayload = encodeBase64Url(new TextEncoder().encode(JSON.stringify({ amount: 50_000 })));
    const tampered = `${header}.${tamperedPayload}.${signature}`;

    const publicKey = await jose.importJWK(publicJwkFromDid(issuer.did), "EdDSA");
    await expect(jose.compactVerify(tampered, publicKey)).rejects.toThrow();
  });
});

describe("interop: our verifier accepts a raw JWS signed by jose", () => {
  it("verifies jose's signature and decodes the identical payload", async () => {
    const issuer = makeIdentity();
    const privateKey = await jose.importJWK(privateJwkFrom(issuer), "EdDSA");

    const payloadBytes = new TextEncoder().encode(JSON.stringify({ hello: "world" }));
    const jwtFromJose = await new jose.CompactSign(payloadBytes)
      .setProtectedHeader({ alg: "EdDSA", kid: verificationMethodId(issuer.did) })
      .sign(privateKey);

    const parsed = parseCompactJws(jwtFromJose);
    const token = verifySignature(parsed, issuer.publicKey);
    expect(decodeVerifiedPayload(parsed, token)).toEqual({ hello: "world" });
  });

  it("also rejects a jose-signed JWS if the payload is tampered afterwards", async () => {
    const issuer = makeIdentity();
    const privateKey = await jose.importJWK(privateJwkFrom(issuer), "EdDSA");
    const payloadBytes = new TextEncoder().encode(JSON.stringify({ amount: 500 }));
    const jwtFromJose = await new jose.CompactSign(payloadBytes)
      .setProtectedHeader({ alg: "EdDSA", kid: verificationMethodId(issuer.did) })
      .sign(privateKey);
    const [header, , signature] = jwtFromJose.split(".");
    const tamperedPayload = encodeBase64Url(new TextEncoder().encode(JSON.stringify({ amount: 50_000 })));
    const tampered = `${header}.${tamperedPayload}.${signature}`;

    const parsed = parseCompactJws(tampered);
    expect(() => verifySignature(parsed, issuer.publicKey)).toThrow();
  });
});

describe("interop: full VC-JWT round trip, not just raw JWS", () => {
  it("jose independently verifies a full AuthorityCredential VC-JWT issued by authority.ts", async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const jwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      action: "purchase",
      scope: { category: "office-supplies", maxAmount: 500 },
      validUntil: "2099-01-01T00:00:00Z",
      now: 0,
    });

    const publicKey = await jose.importJWK(publicJwkFromDid(issuer.did), "EdDSA");
    const { payload, protectedHeader } = await jose.compactVerify(jwt, publicKey);
    const credential = JSON.parse(new TextDecoder().decode(payload)) as Record<string, unknown>;

    expect(protectedHeader.typ).toBe("vc+jwt");
    expect(credential["issuer"]).toBe(issuer.did);
    expect(credential["type"]).toEqual(["VerifiableCredential", "AuthorityCredential"]);
  });

  it("our full verifyAuthorityCredential chain accepts a VC-JWT signed by jose, not by our own signCompactJws", async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const privateKey = await jose.importJWK(privateJwkFrom(issuer), "EdDSA");

    const credential = {
      "@context": [VC_CONTEXT_V2],
      type: [VC_BASE_TYPE, AUTHORITY_CREDENTIAL_TYPE],
      issuer: issuer.did,
      iss: issuer.did,
      validFrom: new Date(0).toISOString(),
      validUntil: "2099-01-01T00:00:00Z",
      credentialSubject: { id: subject.did, action: "purchase", scope: { maxAmount: 500 } },
    };
    const payloadBytes = new TextEncoder().encode(JSON.stringify(credential));
    const jwt = await new jose.CompactSign(payloadBytes)
      .setProtectedHeader({ alg: "EdDSA", kid: verificationMethodId(issuer.did), typ: "vc+jwt" })
      .sign(privateKey);

    const challenge = createChallenge({ now: 0, ttlMs: 60_000 });
    const proof = provePossession(subject.privateKey, subject.did, challenge);

    const result = verifyAuthorityCredential(jwt, proof, { now: 0 });
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(`expected success, got ${result.step}: ${result.reason}`);
    expect(result.verifiedIssuer).toBe(issuer.did);
    expect(result.verifiedSubject).toBe(subject.did);
  });
});
