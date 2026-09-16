import { describe, expect, it } from "vitest";
import { createChallenge, encodeDidKey, generateKeyPair, provePossession, type Did, type ProofOfPossession } from "../identity/index.js";
import { issueAuthorityCredential } from "../credentials/index.js";
import { TrustAnchorSet } from "./anchors.js";
import { issueStatusListCredential } from "./status-list.js";
import { issueVouch } from "./vouch.js";
import { evaluateAuthorityCredentialTrust } from "./trust-decision.js";

interface Identity {
  readonly publicKey: Uint8Array;
  readonly privateKey: Uint8Array;
  readonly did: Did;
}

function makeIdentity(): Identity {
  const { publicKey, privateKey } = generateKeyPair();
  return { publicKey, privateKey, did: encodeDidKey(publicKey) };
}

function proofOfPossessionFor(identity: Identity, now = 0): ProofOfPossession {
  const challenge = createChallenge({ now, ttlMs: 60_000 });
  return provePossession(identity.privateKey, identity.did, challenge);
}

const STATUS_LIST_URL = "https://issuer.example/status/1";

describe("evaluateAuthorityCredentialTrust — full accept path", () => {
  it("accepts a credential from a direct anchor with a clean, checked revocation status", async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const anchors = new TrustAnchorSet([issuer.did]);

    const jwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      action: "purchase",
      scope: { maxAmount: 500 },
      validUntil: "2099-01-01T00:00:00Z",
      now: 0,
    });

    const statusListJwt = issueStatusListCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      statusPurpose: "revocation",
      sizeBits: 128,
      now: 0,
    });

    const decision = await evaluateAuthorityCredentialTrust({
      jwt,
      presenterProof: proofOfPossessionFor(subject, 0),
      anchors,
      credentialStatus: { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: 3, statusListCredential: STATUS_LIST_URL },
      statusListResolver: async () => statusListJwt,
      now: 0,
    });

    expect(decision.accepted).toBe(true);
    if (!decision.accepted) throw new Error("expected acceptance");
    expect(decision.issuerTrust.reason.kind).toBe("direct-anchor");
    expect(decision.revocation.outcome).toBe("active");
  });

  it("accepts a credential from a vouched issuer, and the decision names the voucher", async () => {
    const anchor = makeIdentity();
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const anchors = new TrustAnchorSet([anchor.did]);
    const vouchJwt = issueVouch({ voucherPrivateKey: anchor.privateKey, voucherDid: anchor.did, vouchedIssuerDid: issuer.did, now: 0 });

    const jwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      action: "purchase",
      scope: { maxAmount: 500 },
      validUntil: "2099-01-01T00:00:00Z",
      now: 0,
    });

    const decision = await evaluateAuthorityCredentialTrust({
      jwt,
      presenterProof: proofOfPossessionFor(subject, 0),
      anchors,
      vouches: [vouchJwt],
      now: 0,
    });

    expect(decision.accepted).toBe(true);
    if (!decision.accepted) throw new Error("expected acceptance");
    expect(decision.issuerTrust.reason.kind).toBe("vouched");
    if (decision.issuerTrust.reason.kind !== "vouched") throw new Error("expected vouched");
    expect(decision.issuerTrust.reason.voucher).toBe(anchor.did);
    // No credentialStatus/resolver supplied -> honestly reported as not-checked, never assumed clean.
    expect(decision.revocation.outcome).toBe("not-checked");
  });
});

describe("evaluateAuthorityCredentialTrust — self-issued authority (headline)", () => {
  it("refuses an agent's own self-signed 'I may spend $1,000,000' credential, naming self-issued as the reason", async () => {
    const attacker = makeIdentity();
    const anchors = new TrustAnchorSet([makeIdentity().did]); // some unrelated anchor exists, attacker is not it

    const jwt = issueAuthorityCredential({
      issuerPrivateKey: attacker.privateKey,
      issuerDid: attacker.did,
      subjectDid: attacker.did, // self-issued: issuer === subject
      action: "purchase",
      scope: { maxAmount: 1_000_000 },
      validUntil: "2099-01-01T00:00:00Z",
      now: 0,
    });

    const decision = await evaluateAuthorityCredentialTrust({
      jwt,
      presenterProof: proofOfPossessionFor(attacker, 0),
      anchors,
      now: 0,
    });

    expect(decision.accepted).toBe(false);
    if (decision.accepted) throw new Error("expected refusal");
    if (decision.stage !== "issuer-trust") throw new Error(`expected issuer-trust stage, got ${decision.stage}`);
    expect(decision.issuerTrust.reason.kind).toBe("self-issued");
  });
});

describe("evaluateAuthorityCredentialTrust — revocation refusals", () => {
  it("refuses a revoked credential even though the issuer is a trusted anchor", async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const anchors = new TrustAnchorSet([issuer.did]);

    const jwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      action: "purchase",
      scope: { maxAmount: 500 },
      validUntil: "2099-01-01T00:00:00Z",
      now: 0,
    });

    const statusListJwt = issueStatusListCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      statusPurpose: "revocation",
      sizeBits: 128,
      revokedIndices: [3],
      now: 0,
    });

    const decision = await evaluateAuthorityCredentialTrust({
      jwt,
      presenterProof: proofOfPossessionFor(subject, 0),
      anchors,
      credentialStatus: { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: 3, statusListCredential: STATUS_LIST_URL },
      statusListResolver: async () => statusListJwt,
      now: 0,
    });

    expect(decision.accepted).toBe(false);
    if (decision.accepted) throw new Error("expected refusal");
    if (decision.stage !== "revocation") throw new Error(`expected revocation stage, got ${decision.stage}`);
    expect(decision.revocation.outcome).toBe("revoked");
  });

  it("fails closed (refuses) when the status list resolver is unavailable", async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const anchors = new TrustAnchorSet([issuer.did]);

    const jwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      action: "purchase",
      scope: { maxAmount: 500 },
      validUntil: "2099-01-01T00:00:00Z",
      now: 0,
    });

    const decision = await evaluateAuthorityCredentialTrust({
      jwt,
      presenterProof: proofOfPossessionFor(subject, 0),
      anchors,
      credentialStatus: { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: 3, statusListCredential: STATUS_LIST_URL },
      statusListResolver: async () => {
        throw new Error("network unreachable");
      },
      now: 0,
    });

    expect(decision.accepted).toBe(false);
    if (decision.accepted) throw new Error("expected refusal");
    if (decision.stage !== "revocation") throw new Error(`expected revocation stage, got ${decision.stage}`);
    expect(decision.revocation.outcome).toBe("indeterminate");
  });
});

describe("evaluateAuthorityCredentialTrust — M3 verification failures still surface as refusals", () => {
  it("refuses when the underlying credential itself fails M3 verification (e.g. expired)", async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const anchors = new TrustAnchorSet([issuer.did]);

    const jwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      action: "purchase",
      scope: { maxAmount: 500 },
      validFrom: "2020-01-01T00:00:00Z",
      validUntil: "2020-06-01T00:00:00Z",
      now: Date.parse("2020-01-01T00:00:00Z"),
    });

    const decision = await evaluateAuthorityCredentialTrust({
      jwt,
      presenterProof: proofOfPossessionFor(subject, Date.parse("2026-01-01T00:00:00Z")),
      anchors,
      now: Date.parse("2026-01-01T00:00:00Z"),
    });

    expect(decision.accepted).toBe(false);
    if (decision.accepted) throw new Error("expected refusal");
    if (decision.stage !== "credential-verification") throw new Error(`expected credential-verification stage, got ${decision.stage}`);
    expect(decision.credentialVerification.step).toBe("temporal");
  });
});
