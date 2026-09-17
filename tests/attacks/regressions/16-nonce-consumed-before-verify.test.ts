/**
 * REGRESSION 16 — consuming a nonce before verifying let anyone burn a
 * legitimate agent's challenge. REAL HISTORICAL DEFECT (M6, MEDIUM DoS —
 * FIX B of the SECOND L4 M6 review): the first fix round's single-use
 * bookkeeping marked a challenge nonce "consumed" the INSTANT a
 * presentation merely CITED it — before its signature was ever checked.
 * A challenge nonce travels on the wire in plain sight (only private
 * keys are secret — see ADR 0001), so anyone who intercepted or simply
 * guessed a live nonce could submit a presentation with a GARBAGE
 * signature citing it, and the legitimate holder's one real shot at that
 * challenge would already be spent — a pure denial-of-service requiring
 * no private key at all.
 *
 * Fixed by reordering to check-already-consumed -> verify possession ->
 * consume ONLY on success, still entirely before credential/policy
 * evaluation. This test proves BOTH properties hold together, since one
 * without the other is a regression in a different direction:
 *   1. a garbage-signed presentation citing a real challenge, followed
 *      by the legitimate holder's genuinely valid presentation for the
 *      SAME challenge, now PERMITS the legitimate one (it was never
 *      burned); and
 *   2. a genuinely valid presentation, once it HAS succeeded, still
 *      cannot be replayed — single-use must still hold for a real
 *      presentation, or fixing (1) would have reopened attack 4.
 */
import { describe, expect, it } from "vitest";
import { buildFourBeatFixture, Supplier } from "../../../lib/negotiation/index.js";
import type { Presentation, NegotiationRequest } from "../../../lib/negotiation/index.js";

const ACTION = "purchase-office-supplies";

describe("regression 16 — a nonce is consumed only after possession is genuinely proven (real M6 MEDIUM DoS defect)", () => {
  it("an attacker's garbage-signed presentation citing a live nonce, followed by the legitimate holder's genuine presentation for the SAME nonce: the legitimate one is PERMITTED", async () => {
    const fixture = buildFourBeatFixture();
    const supplier = new Supplier({ policy: fixture.policy, anchors: fixture.anchors, statusListResolver: fixture.resolver, now: fixture.now });
    const challenge = supplier.issueChallenge();
    const request: NegotiationRequest = { action: ACTION, scope: { amount: 1 } };
    const credentials = { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus };

    // The attacker never held any private key — it merely knows the
    // challenge nonce (public the instant it's on the wire) and submits
    // a signature that cannot possibly verify.
    const garbageProof: Presentation["proof"] = { did: fixture.buyer.did, challenge, signature: "00".repeat(64) };
    const garbageDecision = await supplier.evaluatePresentation(challenge, { proof: garbageProof, credentials }, request);
    expect(garbageDecision.stage).toBe("proof-of-possession");
    expect(garbageDecision.permitted).toBe(false);
    if (garbageDecision.stage === "proof-of-possession") {
      expect(garbageDecision.rule.ruleId).toBe("gate:proof-of-possession");
      // Explicitly NOT single-use — the nonce must not be considered
      // "spent" by a signature that never verified.
      expect(garbageDecision.rule.ruleId).not.toBe("gate:challenge-single-use");
    }

    // The REAL Buyer now genuinely answers the SAME, still-live challenge.
    const legitProof = fixture.buyer.provePossession(challenge);
    const legitDecision = await supplier.evaluatePresentation(challenge, { proof: legitProof, credentials }, request);
    expect(legitDecision.stage).toBe("policy");
    expect(legitDecision.permitted).toBe(true);
  });

  it("[both properties together] many garbage attempts against the same nonce still never burn it, AND the eventual legitimate success still cannot itself be replayed afterwards", async () => {
    const fixture = buildFourBeatFixture();
    const supplier = new Supplier({ policy: fixture.policy, anchors: fixture.anchors, statusListResolver: fixture.resolver, now: fixture.now });
    const challenge = supplier.issueChallenge();
    const request: NegotiationRequest = { action: ACTION, scope: { amount: 1 } };
    const credentials = { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus };

    for (let i = 0; i < 5; i += 1) {
      const garbageProof: Presentation["proof"] = { did: fixture.buyer.did, challenge, signature: (i % 10).toString().repeat(128).slice(0, 128) };
      const decision = await supplier.evaluatePresentation(challenge, { proof: garbageProof, credentials }, request);
      expect(decision.stage).toBe("proof-of-possession");
      expect(decision.permitted).toBe(false);
    }

    const legitProof = fixture.buyer.provePossession(challenge);
    const legitDecision = await supplier.evaluatePresentation(challenge, { proof: legitProof, credentials }, request);
    expect(legitDecision.stage).toBe("policy");
    expect(legitDecision.permitted).toBe(true);

    // Property 2: the legitimate success itself is still single-use.
    const replay = await supplier.evaluatePresentation(challenge, { proof: legitProof, credentials }, request);
    expect(replay.stage).toBe("proof-of-possession");
    expect(replay.permitted).toBe(false);
    if (replay.stage === "proof-of-possession") {
      expect(replay.rule.ruleId).toBe("gate:challenge-single-use");
    }
  });
});
