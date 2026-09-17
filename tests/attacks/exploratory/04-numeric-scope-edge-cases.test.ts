/**
 * PART 3 EXPLORATORY — idea 7: "integer overflow or precision loss in a
 * scope amount (Number.MAX_SAFE_INTEGER, 1e308, -0)".
 *
 * Most of this held (JS's IEEE-754 doubles compare correctly even at
 * extreme magnitudes, and `-0` behaves as plain zero with no special
 * bypass). ONE genuine gap was found and is flagged clearly below,
 * without being fixed — see the final report's ANY_NEW_DEFECT section.
 */
import { describe, expect, it } from "vitest";
import { buildFourBeatFixture, GRANTED_MAX_AMOUNT } from "../../../lib/negotiation/index.js";
import type { Presentation, NegotiationRequest } from "../../../lib/negotiation/index.js";

const ACTION = "purchase-office-supplies";

describe("exploratory 7 — extreme/edge numeric scope values", () => {
  it("HELD: Number.MAX_SAFE_INTEGER as a requested amount is correctly refused as over-scope (no precision-loss bypass)", async () => {
    const fixture = buildFourBeatFixture();
    const challenge = fixture.supplier.issueChallenge();
    const decision = await fixture.supplier.evaluatePresentation(
      challenge,
      { proof: fixture.buyer.provePossession(challenge), credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
      { action: ACTION, scope: { amount: Number.MAX_SAFE_INTEGER } },
    );
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("over-scope");
    }
  });

  it("HELD: 1e308 (a huge but still finite double, close to Number.MAX_VALUE) is correctly refused as over-scope, not mistaken for Infinity or NaN", async () => {
    const fixture = buildFourBeatFixture();
    expect(Number.isFinite(1e308)).toBe(true);
    const challenge = fixture.supplier.issueChallenge();
    const decision = await fixture.supplier.evaluatePresentation(
      challenge,
      { proof: fixture.buyer.provePossession(challenge), credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
      { action: ACTION, scope: { amount: 1e308 } },
    );
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("over-scope");
    }
  });

  it("HELD: -0 behaves as plain zero — within scope, no special bypass or crash (Number.isFinite(-0) is true, -0 <= any positive ceiling)", async () => {
    const fixture = buildFourBeatFixture();
    const challenge = fixture.supplier.issueChallenge();
    const decision = await fixture.supplier.evaluatePresentation(
      challenge,
      { proof: fixture.buyer.provePossession(challenge), credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
      { action: ACTION, scope: { amount: -0 } },
    );
    expect(decision.permitted).toBe(true);
  });

  /**
   * ============================================================
   * NEW FINDING (Part 3) — NOT a hypothetical, discovered by direct
   * code reading of `lib/policy/engine.ts` and `permitted-scope.ts`,
   * then confirmed empirically below.
   *
   * The policy engine's scope-bound arithmetic (`computeFieldBound`,
   * `Math.min` across every source that names a bound, then
   * `requestedValue > bound.value` in `engine.ts`) enforces ONLY an
   * upper ceiling. There is no lower bound (e.g. "amount must be >= 0")
   * anywhere in `lib/policy` or `lib/credentials`'s scope model. A
   * NEGATIVE numeric scope value is therefore treated exactly like any
   * other in-range value: `-500000 > 500` is `false`, so it is
   * PERMITTED, identically to a small positive request.
   *
   * Whether this is exploitable depends entirely on what a downstream
   * consumer does with a permitted "amount: -500000" (e.g. a refund
   * system where a negative purchase amount might mean something very
   * different from "no purchase") — that consumer is out of scope for
   * `lib/`, which only decides "is this within the credential's/
   * policy's numeric envelope". But the envelope itself has a real,
   * demonstrable gap: nothing here treats a numeric scope dimension as
   * implicitly non-negative, even though every scope example in this
   * codebase (amounts, item counts) is domain-conventionally
   * non-negative.
   *
   * NOT FIXED HERE per the M7 brief ("if you find a real defect, STOP
   * and report it — do not fix library code"): this is reported as a
   * candidate defect for its own review cycle, not patched. This test
   * documents CURRENT, OBSERVED behavior — it is deliberately NOT
   * phrased as a spec requirement, and flipping it later (if a fix adds
   * a lower-bound check) would be the CORRECT reason for this exact
   * test to start failing.
   * ============================================================
   */
  it("[FINDING — flagged, not fixed] a NEGATIVE requested amount is currently PERMITTED: the policy engine enforces only an upper ceiling, never a lower bound", async () => {
    const fixture = buildFourBeatFixture();
    const challenge = fixture.supplier.issueChallenge();
    const decision = await fixture.supplier.evaluatePresentation(
      challenge,
      { proof: fixture.buyer.provePossession(challenge), credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
      { action: ACTION, scope: { amount: -GRANTED_MAX_AMOUNT * 1000 } }, // e.g. amount: -500000
    );
    // OBSERVED, CURRENT behavior (see the finding above) — a negative
    // amount, however large in magnitude, is permitted because it never
    // exceeds the (positive) ceiling.
    expect(decision.permitted).toBe(true);
  });
});
