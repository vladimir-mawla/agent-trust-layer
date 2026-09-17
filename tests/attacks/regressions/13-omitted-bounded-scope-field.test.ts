/**
 * REGRESSION 13 — omitting a bounded scope field escaped every ceiling.
 * REAL HISTORICAL DEFECT (M5, HIGH — an authorization bypass that shipped
 * behind 31 passing tests, per ADR 0004's own "FINDING 4" amendment):
 * `evaluatePolicyRequest` used to iterate only the fields
 * `PolicyRequest.scope` itself happened to mention. A request shaped
 * `{ action, scope: {} }` against a credential granting
 * `{ amount: 500 }` and a matching `ActionScopeRule.maxScope: { amount:
 * 500 }` returned an UNCONDITIONAL PERMIT — the credential's own ceiling
 * was never even consulted, because the loop never visited the
 * `amount` field at all.
 *
 * Fixed by evaluating the UNION of every field named by the authority
 * credential's own scope, the matching `ActionScopeRule.maxScope`, and
 * any triggered `HistoryNarrowRule.scopeField` — never merely the fields
 * the request happens to mention (`lib/policy/engine.ts`'s
 * `boundedFields` set). A field this engine knows a bound for, that the
 * request does not supply a numeric value for, is now treated as an
 * UNBOUNDED, unverifiable request for that dimension and refused
 * (never silently read as "0 usage, therefore fine").
 */
import { describe, expect, it } from "vitest";
import { buildFourBeatFixture, GRANTED_MAX_AMOUNT } from "../../../lib/negotiation/index.js";
import type { Presentation, NegotiationRequest } from "../../../lib/negotiation/index.js";

describe("regression 13 — an omitted-but-bounded scope field no longer escapes the ceiling (real M5 HIGH defect)", () => {
  it("`scope: {}` (the exact historical bypass shape) is refused, never permitted", async () => {
    const fixture = buildFourBeatFixture();
    const challenge = fixture.supplier.issueChallenge();
    const presentation: Presentation = {
      proof: fixture.buyer.provePossession(challenge),
      credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
    };
    // The exact historical bypass request: the bounded field ("amount")
    // is simply never mentioned.
    const request: NegotiationRequest = { action: "purchase-office-supplies", scope: {} };

    const decision = await fixture.supplier.evaluatePresentation(challenge, presentation, request);

    expect(decision.stage).toBe("policy");
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      // "over-scope" is the refusal kind an omitted-but-bounded field
      // produces (see engine.ts) — never an unconditional permit.
      expect(decision.explanation.refusalKind).toBe("over-scope");
      expect(decision.explanation.field.permitted).toBe(GRANTED_MAX_AMOUNT);
      expect(decision.explanation.field.note).toContain("omitted");
    }
  });

  it("`scope: { unrelatedField: 1 }` (the bounded field still never mentioned) is likewise refused, never permitted", async () => {
    const fixture = buildFourBeatFixture();
    const challenge = fixture.supplier.issueChallenge();
    const presentation: Presentation = {
      proof: fixture.buyer.provePossession(challenge),
      credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
    };
    const request: NegotiationRequest = { action: "purchase-office-supplies", scope: { unrelatedField: 1 } };

    const decision = await fixture.supplier.evaluatePresentation(challenge, presentation, request);

    expect(decision.stage).toBe("policy");
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("over-scope");
      expect(decision.explanation.field.path).toBe("scope.amount");
    }
  });

  it("[sanity] the identical credential and policy DO permit when the bounded field is actually supplied within the ceiling — the fix isn't just refusing everything", async () => {
    const fixture = buildFourBeatFixture();
    const challenge = fixture.supplier.issueChallenge();
    const presentation: Presentation = {
      proof: fixture.buyer.provePossession(challenge),
      credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
    };
    const request: NegotiationRequest = { action: "purchase-office-supplies", scope: { amount: 10 } };

    const decision = await fixture.supplier.evaluatePresentation(challenge, presentation, request);
    expect(decision.permitted).toBe(true);
  });
});
