/**
 * ATTACK 9 — over-scope request: a fully valid, trusted, unrevoked
 * authority credential, presented honestly by its rightful holder, for
 * the RIGHT action — but asking for more than the credential (and the
 * policy's own ceiling) actually grants.
 *
 * Mechanism asserted: `lib/policy/engine.ts`'s scope-bound comparison
 * (`computeFieldBound`, `Math.min` across every source that names a
 * bound), `refusalKind: "over-scope"`, carrying BOTH the requested and
 * permitted numeric values in `field.requested`/`field.permitted` — not
 * a bare "insufficient authority" string. Distinguished from attack 10
 * (confused deputy): the ACTION here is exactly what was granted; only
 * the numeric scope is out of bounds.
 */
import { describe, expect, it } from "vitest";
import { buildFourBeatFixture, GRANTED_MAX_AMOUNT } from "../../../lib/negotiation/index.js";
import type { Presentation, NegotiationRequest } from "../../../lib/negotiation/index.js";

describe("attack 9 — over-scope request", () => {
  it("[end-to-end] a request for far more than the granted ceiling is refused as over-scope, carrying both the requested and permitted values", async () => {
    const fixture = buildFourBeatFixture();
    const challenge = fixture.supplier.issueChallenge();
    const presentation: Presentation = {
      proof: fixture.buyer.provePossession(challenge),
      credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
    };
    const requestedAmount = GRANTED_MAX_AMOUNT * 10;
    const request: NegotiationRequest = { action: "purchase-office-supplies", scope: { amount: requestedAmount } };

    const decision = await fixture.supplier.evaluatePresentation(challenge, presentation, request);

    expect(decision.stage).toBe("policy");
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("over-scope");
      expect(decision.explanation.field.requested).toBe(requestedAmount);
      expect(decision.explanation.field.permitted).toBe(GRANTED_MAX_AMOUNT);
      // The right-side-of-the-boundary distinctions: not confused with
      // a wrong action or an unauthored rule.
      expect(decision.explanation.refusalKind).not.toBe("wrong-action");
      expect(decision.explanation.refusalKind).not.toBe("no-matching-rule");
    }
  });

  it("[boundary] exactly at the ceiling is permitted; one unit over is refused — the comparison is a strict `>`, not `>=`", async () => {
    const fixture = buildFourBeatFixture();

    const atCeilingChallenge = fixture.supplier.issueChallenge();
    const atCeiling = await fixture.supplier.evaluatePresentation(
      atCeilingChallenge,
      { proof: fixture.buyer.provePossession(atCeilingChallenge), credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
      { action: "purchase-office-supplies", scope: { amount: GRANTED_MAX_AMOUNT } },
    );
    expect(atCeiling.permitted).toBe(true);

    const overChallenge = fixture.supplier.issueChallenge();
    const over = await fixture.supplier.evaluatePresentation(
      overChallenge,
      { proof: fixture.buyer.provePossession(overChallenge), credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
      { action: "purchase-office-supplies", scope: { amount: GRANTED_MAX_AMOUNT + 1 } },
    );
    expect(over.permitted).toBe(false);
    if (over.stage === "policy" && !over.permitted) {
      expect(over.explanation.refusalKind).toBe("over-scope");
    }
  });
});
