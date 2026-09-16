import { describe, expect, it } from "vitest";
import {
  createChallenge,
  encodeDidKey,
  generateKeyPair,
  provePossession,
  type Did,
  type ProofOfPossession,
} from "../identity/index.js";
import { issueAuthorityCredential } from "./authority.js";
import { issueHistoryAttestation } from "./history.js";
import { verificationMethodId } from "./credential.js";
import { encodeBase64Url } from "./base64url.js";
import { signCompactJws, MAX_JWS_LENGTH } from "./jws.js";
import { verifyAuthorityCredential, verifyHistoryAttestation } from "./verify.js";
import { VC_BASE_TYPE, VC_CONTEXT_V2, AUTHORITY_CREDENTIAL_TYPE, HISTORY_ATTESTATION_TYPE } from "./vc-types.js";

interface Identity {
  readonly publicKey: Uint8Array;
  readonly privateKey: Uint8Array;
  readonly did: Did;
}

function makeIdentity(): Identity {
  const { publicKey, privateKey } = generateKeyPair();
  return { publicKey, privateKey, did: encodeDidKey(publicKey) };
}

/** Build a real, cryptographically valid `ProofOfPossession` of `identity`'s
 *  own DID — the only kind `verifyPossession` (and so `verifyCredentialOfKind`)
 *  will ever accept. */
function proofOfPossessionFor(identity: Identity, now = 0, ttlMs = 60_000): ProofOfPossession {
  const challenge = createChallenge({ now, ttlMs });
  return provePossession(identity.privateKey, identity.did, challenge);
}

describe("verifyAuthorityCredential / verifyHistoryAttestation — happy path", () => {
  it("verifies a genuine authority credential and reports what it verified", () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const jwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      action: "purchase",
      scope: { category: "office-supplies", maxAmount: 500 },
      validFrom: "2026-01-01T00:00:00Z",
      validUntil: "2026-12-31T00:00:00Z",
      now: Date.parse("2026-06-01T00:00:00Z"),
    });

    const result = verifyAuthorityCredential(jwt, proofOfPossessionFor(subject, Date.parse("2026-06-01T00:00:00Z")), {
      now: Date.parse("2026-06-01T00:00:00Z"),
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected success");
    expect(result.verifiedIssuer).toBe(issuer.did);
    expect(result.verifiedSubject).toBe(subject.did);
    expect(result.revocationChecked).toBe(false);
    expect(result.credential.credentialSubject.action).toBe("purchase");
    expect(result.credential.credentialSubject.scope).toEqual({ category: "office-supplies", maxAmount: 500 });
  });

  it("verifies a genuine history attestation and reports what it verified", () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const jwt = issueHistoryAttestation({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      observationType: "transactions-completed",
      metrics: { count: 47, disputes: 0 },
      now: 1_700_000_000_000,
    });

    const result = verifyHistoryAttestation(jwt, proofOfPossessionFor(subject, 1_700_000_000_000), {
      now: 1_700_000_000_000,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected success");
    expect(result.credential.credentialSubject.metrics).toEqual({ count: 47, disputes: 0 });
    expect(result.revocationChecked).toBe(false);
  });
});

describe("tampering fails at the signature step", () => {
  it("a tampered claim value fails on signature, before structure is even considered", () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const jwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      action: "purchase",
      scope: { maxAmount: 500 },
      validUntil: "2099-01-01T00:00:00Z",
      now: 0,
    });
    const [headerB64, , signatureB64] = jwt.split(".");
    const tamperedPayload = encodeBase64Url(
      new TextEncoder().encode(
        JSON.stringify({
          "@context": [VC_CONTEXT_V2],
          type: [VC_BASE_TYPE, AUTHORITY_CREDENTIAL_TYPE],
          issuer: issuer.did,
          iss: issuer.did,
          validFrom: new Date(0).toISOString(),
          validUntil: "2099-01-01T00:00:00Z",
          credentialSubject: { id: subject.did, action: "purchase", scope: { maxAmount: 500_000_000 } },
        }),
      ),
    );
    const tampered = `${headerB64}.${tamperedPayload}.${signatureB64}`;

    const result = verifyAuthorityCredential(tampered, proofOfPossessionFor(subject, 0), { now: 0 });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected failure");
    expect(result.step).toBe("signature");
  });

  it('rejects alg: "none" outright', () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const header = encodeBase64Url(
      new TextEncoder().encode(JSON.stringify({ alg: "none", kid: verificationMethodId(issuer.did) })),
    );
    const payload = encodeBase64Url(
      new TextEncoder().encode(
        JSON.stringify({
          "@context": [VC_CONTEXT_V2],
          type: [VC_BASE_TYPE, AUTHORITY_CREDENTIAL_TYPE],
          issuer: issuer.did,
          iss: issuer.did,
          validFrom: new Date(0).toISOString(),
          validUntil: "2099-01-01T00:00:00Z",
          credentialSubject: { id: subject.did, action: "purchase", scope: {} },
        }),
      ),
    );
    const forged = `${header}.${payload}.${encodeBase64Url(new Uint8Array([0]))}`;

    const result = verifyAuthorityCredential(forged, proofOfPossessionFor(subject, 0), { now: 0 });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected failure");
    expect(result.step).toBe("signature");
    expect(result.reason).toMatch(/EdDSA/);
  });
});

describe("issuer identity: signed by a different key than the stated issuer", () => {
  it('fails on "issuer-identity", not "signature" — the signature IS valid, just for the wrong claimed issuer', () => {
    const acme = makeIdentity(); // the claimed issuer
    const mallory = makeIdentity(); // who actually signed it
    const subject = makeIdentity();

    // Craft a payload that claims Acme as issuer, but sign it (and set
    // kid) with Mallory's key — a credential impersonating Acme.
    const payload = {
      "@context": [VC_CONTEXT_V2],
      type: [VC_BASE_TYPE, AUTHORITY_CREDENTIAL_TYPE],
      issuer: acme.did,
      iss: acme.did,
      validFrom: new Date(0).toISOString(),
      validUntil: "2099-01-01T00:00:00Z",
      credentialSubject: { id: subject.did, action: "purchase", scope: {} },
    };
    const forged = signCompactJws(payload, verificationMethodId(mallory.did), mallory.privateKey);

    const result = verifyAuthorityCredential(forged, proofOfPossessionFor(subject, 0), { now: 0 });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected failure");
    expect(result.step).toBe("issuer-identity");
    expect(result.reason).toContain(acme.did);
    expect(result.reason).toContain(mallory.did);
  });
});

describe("temporal validity", () => {
  it("rejects an expired credential", () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const jwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      action: "purchase",
      scope: {},
      validFrom: "2020-01-01T00:00:00Z",
      validUntil: "2020-06-01T00:00:00Z",
    });

    const now = Date.parse("2026-01-01T00:00:00Z");
    const result = verifyAuthorityCredential(jwt, proofOfPossessionFor(subject, now), { now });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected failure");
    expect(result.step).toBe("temporal");
  });

  it("rejects a credential used before its validFrom", () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const jwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      action: "purchase",
      scope: {},
      validFrom: "2030-01-01T00:00:00Z",
      validUntil: "2031-01-01T00:00:00Z",
    });

    const now = Date.parse("2026-01-01T00:00:00Z");
    const result = verifyAuthorityCredential(jwt, proofOfPossessionFor(subject, now), { now });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected failure");
    expect(result.step).toBe("temporal");
  });

  it("explicit clock skew: accepts a credential presented slightly before validFrom, within the skew window", () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const validFrom = "2026-06-01T00:00:30.000Z"; // 30s after `now` below
    const jwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      action: "purchase",
      scope: {},
      validFrom,
      validUntil: "2027-01-01T00:00:00Z",
    });
    const now = Date.parse("2026-06-01T00:00:00.000Z");

    const result = verifyAuthorityCredential(jwt, proofOfPossessionFor(subject, now), { now, clockSkewMs: 60_000 });
    expect(result.ok).toBe(true);
  });

  it("explicit clock skew: still rejects a credential presented well before validFrom, outside the skew window", () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const jwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      action: "purchase",
      scope: {},
      validFrom: "2026-06-01T01:00:00.000Z", // one hour after `now`
      validUntil: "2027-01-01T00:00:00Z",
    });
    const now = Date.parse("2026-06-01T00:00:00.000Z");

    const result = verifyAuthorityCredential(jwt, proofOfPossessionFor(subject, now), { now, clockSkewMs: 60_000 });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected failure");
    expect(result.step).toBe("temporal");
  });
});

describe("HEADLINE: subject binding stops a replayed credential cold", () => {
  it("agent B presenting agent A's valid, unexpired, correctly-signed credential is REFUSED", () => {
    const issuer = makeIdentity();
    const agentA = makeIdentity();
    const agentB = makeIdentity(); // the attacker

    const jwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: agentA.did, // credential is bound to A
      action: "purchase",
      scope: { maxAmount: 500 },
      validUntil: "2099-01-01T00:00:00Z",
      now: 0,
    });

    // B can only ever prove possession of B's OWN key — B never had A's
    // private key, so this is the strongest proof B can honestly produce.
    const bsOwnProof = proofOfPossessionFor(agentB, 0);

    const result = verifyAuthorityCredential(jwt, bsOwnProof, { now: 0 });

    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected refusal");
    expect(result.step).toBe("subject-binding");
    expect(result.reason).toContain(agentA.did);
    expect(result.reason).toContain(agentB.did);
  });

  it("agent B cannot forge a proof of possession claiming agent A's DID either", () => {
    const issuer = makeIdentity();
    const agentA = makeIdentity();
    const agentB = makeIdentity();

    const jwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: agentA.did,
      action: "purchase",
      scope: {},
      validUntil: "2099-01-01T00:00:00Z",
      now: 0,
    });

    // B signs the challenge with B's OWN private key but LIES about
    // which DID it's proving — M1's verifyPossession must catch this
    // (it's the exact attack `challenge.test.ts` calls its own headline
    // test), and our subject-binding step must surface that failure.
    const challenge = createChallenge({ now: 0, ttlMs: 60_000 });
    const forgedProof: ProofOfPossession = provePossession(agentB.privateKey, agentA.did, challenge);

    const result = verifyAuthorityCredential(jwt, forgedProof, { now: 0 });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected refusal");
    expect(result.step).toBe("subject-binding");
  });

  it("the legitimate subject, presenting their OWN credential, is accepted", () => {
    const issuer = makeIdentity();
    const agentA = makeIdentity();
    const jwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: agentA.did,
      action: "purchase",
      scope: {},
      validUntil: "2099-01-01T00:00:00Z",
      now: 0,
    });

    const result = verifyAuthorityCredential(jwt, proofOfPossessionFor(agentA, 0), { now: 0 });
    expect(result.ok).toBe(true);
  });
});

describe("structurally malformed JWTs fail closed with a typed result, never an unhandled throw", () => {
  const subject = makeIdentity();

  it("two segments", () => {
    const result = verifyAuthorityCredential("abc.def", proofOfPossessionFor(subject));
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected failure");
    expect(result.step).toBe("parse");
  });

  it("empty string", () => {
    const result = verifyAuthorityCredential("", proofOfPossessionFor(subject));
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected failure");
    expect(result.step).toBe("parse");
  });

  it("garbage base64", () => {
    const result = verifyAuthorityCredential("not base64!.also not.nope!!", proofOfPossessionFor(subject));
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected failure");
    expect(result.step).toBe("parse");
  });

  it("huge payload", () => {
    const huge = `${"a".repeat(MAX_JWS_LENGTH)}.b.c`;
    const result = verifyAuthorityCredential(huge, proofOfPossessionFor(subject));
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected failure");
    expect(result.step).toBe("parse");
  });

  it("never throws, for any of the above", () => {
    for (const bogus of ["abc.def", "", "not base64!.also not.nope!!", `${"a".repeat(MAX_JWS_LENGTH)}.b.c`]) {
      expect(() => verifyAuthorityCredential(bogus, proofOfPossessionFor(subject))).not.toThrow();
    }
  });
});

describe("a history attestation cannot be used where authority is required, and vice versa", () => {
  it("verifyAuthorityCredential rejects a JWT that is actually a signed HistoryAttestation", () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const historyJwt = issueHistoryAttestation({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      observationType: "transactions-completed",
      metrics: { count: 47, disputes: 0 },
    });

    const result = verifyAuthorityCredential(historyJwt, proofOfPossessionFor(subject));
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected refusal — history is not authority");
    expect(result.step).toBe("structure");
    expect(result.reason).toContain(HISTORY_ATTESTATION_TYPE);
  });

  it("verifyHistoryAttestation rejects a JWT that is actually a signed AuthorityCredential", () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const authorityJwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      action: "purchase",
      scope: {},
      validUntil: "2099-01-01T00:00:00Z",
    });

    const result = verifyHistoryAttestation(authorityJwt, proofOfPossessionFor(subject));
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected refusal");
    expect(result.step).toBe("structure");
    expect(result.reason).toContain(AUTHORITY_CREDENTIAL_TYPE);
  });
});
