/**
 * ATTACK 8 — DID impersonation: the impostor copies a DID string it
 * cannot sign for (Agent A's real, public `did:key`) and attempts to
 * answer the Supplier's challenge claiming to BE A, signing with its OWN
 * (different) private key instead.
 *
 * Mechanism asserted: proof of possession (`lib/identity/challenge.ts`'s
 * `verifyPossession`, wired in as `lib/negotiation/supplier.ts`'s FIRST
 * gate after session-binding) — the signature verification fails
 * against the public key recovered from the CLAIMED DID (A's), because
 * it was produced with the impostor's own, different key.
 *
 * This is checked in `Supplier.evaluatePresentation` BEFORE
 * `presentation.credentials` is read even once — proved here
 * structurally, not just by the decision's own labelled stage, with an
 * injected resolver spy that must never be called. DONE.html's own
 * Definition of Done names this gate explicitly: "A spoofed agent
 * presenting a copied DID is rejected at proof-of-possession, before any
 * credential is even examined."
 */
import { describe, expect, it, vi } from "vitest";
import { createChallenge, verifyPossession } from "../../../lib/identity/index.js";
import { Supplier, buildFourBeatFixture } from "../../../lib/negotiation/index.js";
import type { Presentation, NegotiationRequest } from "../../../lib/negotiation/index.js";
import type { StatusListResolver } from "../../../lib/trust/index.js";

describe("attack 8 — DID impersonation", () => {
  it("[mechanism, direct] verifyPossession throws ProofVerificationError when the claimed DID's key does not match the signing key", () => {
    const fixture = buildFourBeatFixture();
    const challenge = createChallenge({ now: fixture.now });
    // The attacker signs with ITS OWN key while claiming the Buyer's DID.
    const spoofedProof = fixture.attacker.attemptProofOfPossessionFor(fixture.buyer.did, challenge);

    expect(() => verifyPossession(spoofedProof, { now: fixture.now })).toThrow();
    try {
      verifyPossession(spoofedProof, { now: fixture.now });
      expect.fail("expected verifyPossession to throw");
    } catch (error) {
      expect((error as Error).name).toBe("ProofVerificationError");
    }
  });

  it("[end-to-end, structural] the Supplier refuses at proof-of-possession and NEVER invokes the status-list resolver — the credential is never examined at all", async () => {
    const fixture = buildFourBeatFixture();
    const resolverSpy = vi.fn<StatusListResolver>(() => {
      throw new Error("resolver must never be called — the credential must never be examined for a spoofed DID");
    });
    const supplier = new Supplier({ policy: fixture.policy, anchors: fixture.anchors, statusListResolver: resolverSpy, now: fixture.now });

    const challenge = supplier.issueChallenge();
    const spoofedProof = fixture.attacker.attemptProofOfPossessionFor(fixture.buyer.did, challenge);
    const presentation: Presentation = {
      proof: spoofedProof,
      credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
    };
    const request: NegotiationRequest = { action: "purchase-office-supplies", scope: { amount: 1 } };

    const decision = await supplier.evaluatePresentation(challenge, presentation, request);

    expect(decision.stage).toBe("proof-of-possession");
    expect(decision.permitted).toBe(false);
    if (decision.stage === "proof-of-possession") {
      expect(decision.rule.ruleId).toBe("gate:proof-of-possession");
      expect(decision.claimedDid).toBe(fixture.buyer.did);
    }
    // Structural proof, not just a labelled stage: the credential's own
    // revocation status was never even looked up.
    expect(resolverSpy).not.toHaveBeenCalled();
  });

  it("[end-to-end] the identical valid credential is permitted for the true holder and refused for the impostor claiming the same DID — only the signing key differs", async () => {
    const fixture = buildFourBeatFixture();
    const request: NegotiationRequest = { action: "purchase-office-supplies", scope: { amount: 100 } };

    const honestChallenge = fixture.supplier.issueChallenge();
    const honestDecision = await fixture.supplier.evaluatePresentation(
      honestChallenge,
      { proof: fixture.buyer.provePossession(honestChallenge), credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
      request,
    );
    expect(honestDecision.stage).toBe("policy");
    expect(honestDecision.permitted).toBe(true);

    const hostileChallenge = fixture.supplier.issueChallenge();
    const hostileDecision = await fixture.supplier.evaluatePresentation(
      hostileChallenge,
      {
        proof: fixture.attacker.attemptProofOfPossessionFor(fixture.buyer.did, hostileChallenge),
        credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
      },
      request,
    );
    expect(hostileDecision.stage).toBe("proof-of-possession");
    expect(hostileDecision.permitted).toBe(false);
  });
});
