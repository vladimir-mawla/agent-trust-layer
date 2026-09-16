import { describe, expect, it } from "vitest";
import { encodeDidKey, generateKeyPair } from "../identity/index.js";
import { issueAuthorityCredential } from "./authority.js";
import { parseCompactJws, verifySignature, decodeVerifiedPayload } from "./jws.js";
import { verificationMethodId } from "./credential.js";

describe("issueAuthorityCredential", () => {
  const issuer = generateKeyPair();
  const issuerDid = encodeDidKey(issuer.publicKey);
  const subjectDid = encodeDidKey(generateKeyPair().publicKey);

  it("produces a compact JWS whose header names the issuer's did:key as kid", () => {
    const jwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid,
      subjectDid,
      action: "purchase",
      scope: { category: "office-supplies", maxAmount: 500, currency: "USD" },
      validUntil: "2026-12-31T00:00:00Z",
      now: 0,
    });

    const parsed = parseCompactJws(jwt);
    expect(parsed.header.alg).toBe("EdDSA");
    expect(parsed.header.kid).toBe(verificationMethodId(issuerDid));

    const token = verifySignature(parsed, issuer.publicKey);
    const payload = decodeVerifiedPayload(parsed, token) as Record<string, unknown>;

    expect(payload["@context"]).toEqual(["https://www.w3.org/ns/credentials/v2"]);
    expect(payload["type"]).toEqual(["VerifiableCredential", "AuthorityCredential"]);
    expect(payload["issuer"]).toBe(issuerDid);
    expect(payload["iss"]).toBe(issuerDid);
    expect(payload["validFrom"]).toBe(new Date(0).toISOString());
    expect(payload["validUntil"]).toBe("2026-12-31T00:00:00Z");
    expect(payload["credentialSubject"]).toEqual({
      id: subjectDid,
      action: "purchase",
      scope: { category: "office-supplies", maxAmount: 500, currency: "USD" },
    });
  });

  it("never includes any private key material in the issued credential", () => {
    const jwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid,
      subjectDid,
      action: "purchase",
      scope: {},
      validUntil: "2026-12-31T00:00:00Z",
    });

    const privateKeyHex = Buffer.from(issuer.privateKey).toString("hex");
    expect(jwt).not.toContain(privateKeyHex);
    // Belt-and-suspenders: decode every segment and check none of them
    // contain the raw private key bytes either.
    for (const segment of jwt.split(".")) {
      expect(segment).not.toContain(privateKeyHex);
    }
  });

  it("defaults validFrom to now when omitted", () => {
    const jwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid,
      subjectDid,
      action: "purchase",
      scope: {},
      validUntil: "2099-01-01T00:00:00Z",
      now: 1_700_000_000_000,
    });
    const parsed = parseCompactJws(jwt);
    const token = verifySignature(parsed, issuer.publicKey);
    const payload = decodeVerifiedPayload(parsed, token) as Record<string, unknown>;
    expect(payload["validFrom"]).toBe(new Date(1_700_000_000_000).toISOString());
  });
});
