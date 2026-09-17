/**
 * FINDING 6 (L4 M5 review): the mandatory revocation gate
 * (`GATE_REVOCATION_UNCHECKED` in `engine.ts`) is checked ONLY for the
 * `authority` decision — `computeHistoryConstraints` never inspects
 * `HistoryTrustDecision.revocation.outcome` at all, so an
 * unchecked-revocation history attestation narrows a ceiling exactly
 * like a checked-and-clean one. This is deliberate (see
 * `history-constraints.ts`'s module comment for the full reasoning: an
 * unverifiable NARROWING can only ever produce a false negative — a
 * request wrongly refused — never a false positive/grant, so extending
 * the mandatory-checked gate to history would make the engine MORE
 * permissive, not more cautious). This test makes that choice explicit
 * and regression-proof rather than merely documented.
 */
import { describe, expect, it } from "vitest";
import { createChallenge, encodeDidKey, generateKeyPair, provePossession, type Did, type ProofOfPossession } from "../identity/index.js";
import { issueAuthorityCredential, issueHistoryAttestation } from "../credentials/index.js";
import { TrustAnchorSet } from "../trust/anchors.js";
import { issueStatusListCredential } from "../trust/status-list.js";
import { evaluateAuthorityCredentialTrust, evaluateHistoryAttestationTrust } from "../trust/index.js";
import { evaluatePolicyRequest } from "./engine.js";
import { ACTION_SCOPE_RULE_KIND, HISTORY_NARROW_RULE_KIND, type Policy } from "./policy-types.js";

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

function narrowingPolicy(): Policy {
  return {
    id: "policy-history-revocation-fixture",
    version: "1.0.0",
    revocationHandling: { requireChecked: true },
    rules: [
      { kind: ACTION_SCOPE_RULE_KIND, id: "R-purchase", description: "purchase ceiling", action: "purchase", maxScope: { maxAmount: 500 } },
      {
        kind: HISTORY_NARROW_RULE_KIND,
        id: "R-dispute-narrow",
        description: "3+ observed disputes narrow the purchase ceiling to 100",
        action: "purchase",
        observationType: "disputes-observed",
        metric: "disputeCount",
        operator: "gte",
        threshold: 3,
        scopeField: "maxAmount",
        narrowedMax: 100,
      },
    ],
  };
}

describe("computeHistoryConstraints (via evaluatePolicyRequest) — unchecked-revocation history narrows identically to checked-clean history (FINDING 6)", () => {
  it("an accepted history attestation whose revocation was NEVER checked still triggers the narrowing rule", async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const anchors = new TrustAnchorSet([issuer.did]);

    const authorityJwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      action: "purchase",
      scope: { maxAmount: 500 },
      validUntil: "2099-01-01T00:00:00Z",
      now: 0,
    });
    const statusListJwt = issueStatusListCredential({ issuerPrivateKey: issuer.privateKey, issuerDid: issuer.did, statusPurpose: "revocation", sizeBits: 128, now: 0 });
    const authority = await evaluateAuthorityCredentialTrust({
      jwt: authorityJwt,
      presenterProof: proofOfPossessionFor(subject, 0),
      anchors,
      credentialStatus: { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: 1, statusListCredential: "https://issuer.example/status/1" },
      statusListResolver: async () => statusListJwt,
      now: 0,
    });
    expect(authority.accepted).toBe(true);

    const historyJwt = issueHistoryAttestation({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      observationType: "disputes-observed",
      metrics: { disputeCount: 3 },
      now: 0,
    });

    // NO credentialStatus/statusListResolver supplied for the history
    // attestation — its revocation is honestly reported "not-checked".
    const uncheckedHistory = await evaluateHistoryAttestationTrust({ jwt: historyJwt, presenterProof: proofOfPossessionFor(subject, 0), now: 0 });
    expect(uncheckedHistory.accepted).toBe(true);
    if (!uncheckedHistory.accepted) throw new Error("expected acceptance");
    expect(uncheckedHistory.revocation.outcome).toBe("not-checked");

    const decisionWithUnchecked = evaluatePolicyRequest({
      policy: narrowingPolicy(),
      request: { action: "purchase", scope: { maxAmount: 200 } },
      authority,
      history: [uncheckedHistory],
    });

    // The unchecked history attestation still narrows the ceiling to 100
    // — refused, exactly as a checked-and-clean one would be (see the
    // sibling test below), even though the POLICY's own
    // `revocationHandling: { requireChecked: true }` is the strict,
    // mandatory default for the AUTHORITY credential. That gate simply
    // does not apply to history — see `history-constraints.ts`'s module
    // comment for why this is deliberate and safe.
    expect(decisionWithUnchecked.permitted).toBe(false);
    if (decisionWithUnchecked.permitted) throw new Error("expected refusal");
    expect(decisionWithUnchecked.explanation.refusalKind).toBe("history-constraint");
    expect(decisionWithUnchecked.explanation.field.permitted).toBe(100);

    // Now the SAME history claim, but with revocation actually checked
    // and clean — the outcome is identical: still narrowed to 100.
    const historyStatusListJwt = issueStatusListCredential({ issuerPrivateKey: issuer.privateKey, issuerDid: issuer.did, statusPurpose: "revocation", sizeBits: 128, now: 0 });
    const checkedHistory = await evaluateHistoryAttestationTrust({
      jwt: historyJwt,
      presenterProof: proofOfPossessionFor(subject, 0),
      credentialStatus: { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: 1, statusListCredential: "https://issuer.example/status/2" },
      statusListResolver: async () => historyStatusListJwt,
      now: 0,
    });
    expect(checkedHistory.accepted).toBe(true);
    if (!checkedHistory.accepted) throw new Error("expected acceptance");
    expect(checkedHistory.revocation.outcome).toBe("active");

    const decisionWithChecked = evaluatePolicyRequest({
      policy: narrowingPolicy(),
      request: { action: "purchase", scope: { maxAmount: 200 } },
      authority,
      history: [checkedHistory],
    });

    expect(decisionWithChecked.permitted).toBe(false);
    if (decisionWithChecked.permitted) throw new Error("expected refusal");
    expect(decisionWithChecked.explanation.refusalKind).toBe("history-constraint");
    expect(decisionWithChecked.explanation.field.permitted).toBe(100);

    // Same effective outcome (both refuse, at the same narrowed ceiling)
    // regardless of whether the history attestation's own revocation was
    // ever checked — the asymmetry with the mandatory AUTHORITY gate is
    // real, deliberate, and — because history can only ever narrow —
    // never a path to an unearned permit.
    expect(decisionWithUnchecked.explanation.field.permitted).toBe(decisionWithChecked.explanation.field.permitted);
  });
});
