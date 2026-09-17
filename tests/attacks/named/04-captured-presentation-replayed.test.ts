/**
 * ATTACK 4 — a captured presentation replayed later: an attacker
 * intercepts a fully valid, honestly-signed `Presentation` (proof +
 * credentials) on the wire and re-submits the IDENTICAL bytes to the
 * SAME session later, hoping the Supplier will grant the request a
 * second time.
 *
 * Mechanism asserted: `lib/negotiation/supplier.ts`'s single-use nonce
 * tracking (`#consumedChallengeNonces`), refused at
 * `GATE_CHALLENGE_ALREADY_CONSUMED` (`gate:challenge-single-use`) —
 * distinct from BOTH `GATE_SESSION_CHALLENGE` (a nonce this session
 * never issued at all) and `GATE_PROOF_OF_POSSESSION` (a cryptographic
 * failure): here the nonce genuinely belongs to this session, and the
 * proof is genuinely, cryptographically valid — it has simply already
 * been spent.
 */
import { describe, expect, it } from "vitest";
import { buildFourBeatFixture } from "../../../lib/negotiation/index.js";
import type { Presentation, NegotiationRequest } from "../../../lib/negotiation/index.js";

describe("attack 4 — captured presentation replayed later", () => {
  it("[mechanism] the first presentation is permitted; the IDENTICAL captured presentation replayed against the same challenge is refused at gate:challenge-single-use", async () => {
    const fixture = buildFourBeatFixture();
    const challenge = fixture.supplier.issueChallenge();
    const presentation: Presentation = {
      proof: fixture.buyer.provePossession(challenge),
      credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
    };
    const request: NegotiationRequest = { action: "purchase-office-supplies", scope: { amount: 100 } };

    const first = await fixture.supplier.evaluatePresentation(challenge, presentation, request);
    expect(first.stage).toBe("policy");
    expect(first.permitted).toBe(true);

    // The attacker replays the EXACT same (challenge, presentation) pair
    // captured off the wire — nothing about it is forged or altered.
    const replay = await fixture.supplier.evaluatePresentation(challenge, presentation, request);

    expect(replay.stage).toBe("proof-of-possession");
    expect(replay.permitted).toBe(false);
    if (replay.stage === "proof-of-possession") {
      expect(replay.rule.ruleId).toBe("gate:challenge-single-use");
      // Explicitly the RIGHT gate, not the two neighboring ones a
      // superficial "just refused" check would miss confusing this with.
      expect(replay.rule.ruleId).not.toBe("gate:session-challenge");
      expect(replay.rule.ruleId).not.toBe("gate:proof-of-possession");
    }
  });

  it("[mechanism] replaying a captured presentation that was refused for an unrelated reason the first time is STILL refused on replay (the nonce is spent regardless of the first outcome)", async () => {
    const fixture = buildFourBeatFixture();
    const challenge = fixture.supplier.issueChallenge();
    const presentation: Presentation = {
      proof: fixture.buyer.provePossession(challenge),
      credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
    };
    // A request that will be refused as over-scope the first time.
    const overScopeRequest: NegotiationRequest = { action: "purchase-office-supplies", scope: { amount: 999_999 } };
    const first = await fixture.supplier.evaluatePresentation(challenge, presentation, overScopeRequest);
    expect(first.stage).toBe("policy");
    expect(first.permitted).toBe(false);

    // Replaying the SAME captured presentation with a request that WOULD
    // otherwise have been permitted still fails — at single-use, not at
    // over-scope again.
    const wouldPermitRequest: NegotiationRequest = { action: "purchase-office-supplies", scope: { amount: 1 } };
    const replay = await fixture.supplier.evaluatePresentation(challenge, presentation, wouldPermitRequest);
    expect(replay.stage).toBe("proof-of-possession");
    expect(replay.permitted).toBe(false);
    if (replay.stage === "proof-of-possession") {
      expect(replay.rule.ruleId).toBe("gate:challenge-single-use");
    }
  });
});
