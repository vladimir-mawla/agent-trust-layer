import { describe, expect, it } from "vitest";
import { encodeDidKey, generateKeyPair } from "../identity/index.js";
import { issueHistoryAttestation } from "./history.js";
import { parseCompactJws, verifySignature, decodeVerifiedPayload } from "./jws.js";
import { verificationMethodId } from "./credential.js";

describe("issueHistoryAttestation", () => {
  const issuer = generateKeyPair();
  const issuerDid = encodeDidKey(issuer.publicKey);
  const subjectDid = encodeDidKey(generateKeyPair().publicKey);

  it("produces a compact JWS shaped as a HistoryAttestation, distinct from an authority credential", () => {
    const jwt = issueHistoryAttestation({
      issuerPrivateKey: issuer.privateKey,
      issuerDid,
      subjectDid,
      observationType: "transactions-completed",
      metrics: { count: 47, disputes: 0 },
      observationPeriod: { from: "2026-01-01T00:00:00Z", until: "2026-09-01T00:00:00Z" },
      now: 0,
    });

    const parsed = parseCompactJws(jwt);
    expect(parsed.header.kid).toBe(verificationMethodId(issuerDid));

    const token = verifySignature(parsed, issuer.publicKey);
    const payload = decodeVerifiedPayload(parsed, token) as Record<string, unknown>;

    expect(payload["type"]).toEqual(["VerifiableCredential", "HistoryAttestation"]);
    // No `action`/`scope` anywhere — a history attestation carries no
    // authority-shaped fields for a verifier to mistake for a grant.
    expect(payload).not.toHaveProperty("credentialSubject.action");
    expect(payload).not.toHaveProperty("credentialSubject.scope");
    expect(payload["credentialSubject"]).toEqual({
      id: subjectDid,
      observationType: "transactions-completed",
      metrics: { count: 47, disputes: 0 },
      observationPeriod: { from: "2026-01-01T00:00:00Z", until: "2026-09-01T00:00:00Z" },
    });
  });

  it("has no required validUntil, unlike AuthorityCredential", () => {
    const jwt = issueHistoryAttestation({
      issuerPrivateKey: issuer.privateKey,
      issuerDid,
      subjectDid,
      observationType: "transactions-completed",
      metrics: { count: 1 },
    });
    const parsed = parseCompactJws(jwt);
    const token = verifySignature(parsed, issuer.publicKey);
    const payload = decodeVerifiedPayload(parsed, token) as Record<string, unknown>;
    expect(payload).not.toHaveProperty("validUntil");
  });
});
