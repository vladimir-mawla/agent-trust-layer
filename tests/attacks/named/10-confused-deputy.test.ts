/**
 * ATTACK 10 — confused deputy: a fully valid, trusted, unrevoked
 * authority credential is presented honestly by its rightful holder, in
 * scope — but invoked for a DIFFERENT action/purpose than the one it was
 * actually granted for. The classic confused-deputy shape: the Supplier
 * (the "deputy") holds real authority on the Buyer's behalf for one
 * purpose, and the Buyer attempts to redirect that same, genuine
 * authority toward a purpose it was never granted for.
 *
 * Mechanism asserted: `lib/policy/engine.ts`'s `GATE_ACTION_MATCH` —
 * `request.action !== envelope.action` (`envelope.action` comes from the
 * credential's OWN granted `credentialSubject.action`, established by
 * M3's verification, never from anything the request merely claims) —
 * `refusalKind: "wrong-action"`. This check runs BEFORE any policy rule
 * lookup or scope comparison, so it fires even for a policy that has no
 * rule at all governing the mismatched action, and even when the
 * requested numeric scope would otherwise have been well within any
 * plausible ceiling.
 *
 * Distinguished from attack 9 (over-scope): the numeric scope requested
 * here is deliberately small and well within what the credential grants
 * FOR ITS OWN action — only the action itself is wrong.
 */
import { describe, expect, it } from "vitest";
import { buildFourBeatFixture } from "../../../lib/negotiation/index.js";
import type { Presentation, NegotiationRequest } from "../../../lib/negotiation/index.js";

describe("attack 10 — confused deputy (credential used for a different purpose than granted)", () => {
  it("[end-to-end] a credential granted for \"purchase-office-supplies\" is refused when invoked for a different action (\"wire-transfer\"), naming both actions", async () => {
    const fixture = buildFourBeatFixture();
    const challenge = fixture.supplier.issueChallenge();
    const presentation: Presentation = {
      proof: fixture.buyer.provePossession(challenge),
      credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
    };
    // A small, otherwise-plausible amount for a DIFFERENT action than
    // what was actually granted.
    const request: NegotiationRequest = { action: "wire-transfer", scope: { amount: 10 } };

    const decision = await fixture.supplier.evaluatePresentation(challenge, presentation, request);

    expect(decision.stage).toBe("policy");
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("wrong-action");
      expect(decision.explanation.field.requested).toBe("wire-transfer");
      expect(decision.explanation.field.permitted).toBe("purchase-office-supplies");
      // Not confused with the scope ceiling, and not with "this policy
      // simply never wrote a rule for this action" — the credential's
      // OWN granted action is what disagrees with the request, checked
      // before any rule lookup even happens.
      expect(decision.explanation.refusalKind).not.toBe("over-scope");
      expect(decision.explanation.refusalKind).not.toBe("no-matching-rule");
    }
  });

  it("[mechanism] the wrong-action gate fires even when the policy has NO rule at all for the mismatched action — it never reaches rule lookup", async () => {
    const fixture = buildFourBeatFixture();
    // Confirm structurally: fixture.policy's only rule governs
    // "purchase-office-supplies" — there is no rule for "wire-transfer"
    // at all, yet the refusal is still "wrong-action", not
    // "no-matching-rule", proving the action-match gate runs first.
    const ruleActions = fixture.policy.rules.map((rule) => rule.action);
    expect(ruleActions).not.toContain("wire-transfer");

    const challenge = fixture.supplier.issueChallenge();
    const decision = await fixture.supplier.evaluatePresentation(
      challenge,
      { proof: fixture.buyer.provePossession(challenge), credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
      { action: "wire-transfer", scope: { amount: 1 } },
    );
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("wrong-action");
    } else {
      expect.fail("expected a policy-stage refusal");
    }
  });
});
