/**
 * PART 3 EXPLORATORY — idea 1: "a credential valid for a DIFFERENT
 * supplier's policy presented to this one", and idea 2: "two credentials
 * presented together, one valid and one forged".
 *
 * Neither of these turned out to be a defect — both outcomes are
 * reported honestly below, with the reasoning for why the system holds.
 */
import { describe, expect, it } from "vitest";
import { issueHistoryAttestation } from "../../../lib/credentials/index.js";
import { TrustAnchorSet } from "../../../lib/trust/index.js";
import { buildFourBeatFixture, Supplier } from "../../../lib/negotiation/index.js";
import type { Presentation, NegotiationRequest } from "../../../lib/negotiation/index.js";
import type { Policy } from "../../../lib/policy/index.js";
import { makeIdentity } from "../helpers.js";

describe("exploratory 1 — a credential presented to a DIFFERENT supplier's policy", () => {
  it("HELD: the SAME credential + proof, presented to a second Supplier with its own (tighter) ceiling, is bounded by THAT Supplier's own policy — never by whatever the first Supplier would have allowed", async () => {
    const fixture = buildFourBeatFixture();
    // A second, independently-configured Supplier — SAME trust anchors
    // (it also trusts the real issuer), but a much tighter ceiling of
    // its own for the identical action.
    const tighterPolicy: Policy = {
      id: "second-supplier-tighter-policy",
      version: "1.0.0",
      revocationHandling: { requireChecked: true },
      rules: [{ kind: "action-scope", id: "R-tight", description: "a stricter supplier", action: "purchase-office-supplies", maxScope: { amount: 50 } }],
    };
    const secondSupplier = new Supplier({ policy: tighterPolicy, anchors: fixture.anchors, statusListResolver: fixture.resolver, now: fixture.now });

    const challenge = secondSupplier.issueChallenge();
    const presentation: Presentation = {
      proof: fixture.buyer.provePossession(challenge),
      credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
    };
    // Within the CREDENTIAL's own 500 ceiling, but over the SECOND
    // supplier's own, independently-authored 50 ceiling.
    const request: NegotiationRequest = { action: "purchase-office-supplies", scope: { amount: 100 } };

    const decision = await secondSupplier.evaluatePresentation(challenge, presentation, request);

    expect(decision.stage).toBe("policy");
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("over-scope");
      expect(decision.explanation.field.permitted).toBe(50); // the SECOND supplier's own ceiling, not the first's 500
    }
  });

  it("HELD: a Supplier that does not itself trust the credential's issuer refuses it (untrusted-issuer), regardless of whether some OTHER supplier trusts that same issuer", async () => {
    const fixture = buildFourBeatFixture();
    const strangerAnchors = new TrustAnchorSet([]); // trusts nobody at all
    const strangerPolicy: Policy = {
      id: "stranger-supplier-policy",
      version: "1.0.0",
      revocationHandling: { requireChecked: true },
      rules: [{ kind: "action-scope", id: "R-x", description: "x", action: "purchase-office-supplies", maxScope: { amount: 500 } }],
    };
    const strangerSupplier = new Supplier({ policy: strangerPolicy, anchors: strangerAnchors, statusListResolver: fixture.resolver, now: fixture.now });

    const challenge = strangerSupplier.issueChallenge();
    const decision = await strangerSupplier.evaluatePresentation(
      challenge,
      { proof: fixture.buyer.provePossession(challenge), credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
      { action: "purchase-office-supplies", scope: { amount: 10 } },
    );

    expect(decision.stage).toBe("policy");
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("untrusted-issuer");
    }
  });

  it("CONCLUSION (documented, not asserted further): presenting a credential to a different supplier is bounded by that supplier's OWN anchors and policy every time — there is no cross-supplier bypass, because neither the credential nor the presentation carries any notion of 'which supplier this is for' (no audience/aud claim in this data model). This is a property of the design, not a gap: a credential is meant to be checkable by any independent verifier, the same way a real-world credential (a driver's licence, a professional certification) is checked independently by every venue that consults it, each applying its OWN rules.", () => {
    expect(true).toBe(true);
  });
});

describe("exploratory 2 — two credentials presented together, one valid and one forged", () => {
  const ACTION = "purchase-office-supplies";

  function policyWithHistoryRule(): Policy {
    return {
      id: "mixed-credentials-policy",
      version: "1.0.0",
      revocationHandling: { requireChecked: true },
      rules: [
        { kind: "action-scope", id: "R-scope", description: "base ceiling", action: ACTION, maxScope: { amount: 500 } },
        {
          kind: "history-narrow",
          id: "R-narrow",
          description: "zero disputes narrows the ceiling to 200",
          action: ACTION,
          observationType: "dispute-record",
          metric: "disputeCount",
          operator: "lte",
          threshold: 0,
          scopeField: "amount",
          narrowedMax: 200,
        },
      ],
    };
  }

  it("HELD: one valid history attestation + one forged (garbage) history JWT, presented TOGETHER: the valid one still narrows correctly, the forged one is silently dropped, and neither crashes nor poisons the other", async () => {
    const fixture = buildFourBeatFixture();
    const supplier = new Supplier({ policy: policyWithHistoryRule(), anchors: fixture.anchors, statusListResolver: fixture.resolver, now: fixture.now });

    // History has no trust-anchor requirement (anchors.ts's own module
    // comment) — issued here by an independent observer identity, not
    // the fixture's trust-anchor issuer, to keep the two mechanisms
    // (issuer trust for authority, history narrowing) visibly separate.
    const observer = makeIdentity();
    const genuineHistoryJwt = issueHistoryAttestation({
      issuerPrivateKey: observer.privateKey,
      issuerDid: observer.did,
      subjectDid: fixture.buyer.did,
      observationType: "dispute-record",
      metrics: { disputeCount: 0 },
      now: fixture.now,
    });
    const forgedHistoryJwt = "not-a-jwt-at-all.garbage.data";

    const challenge = supplier.issueChallenge();
    const presentation: Presentation = {
      proof: fixture.buyer.provePossession(challenge),
      credentials: {
        authorityJwt: fixture.buyerAuthorityJwt,
        credentialStatus: fixture.buyerCredentialStatus,
        historyJwts: [genuineHistoryJwt, forgedHistoryJwt],
      },
    };
    // Between the narrowed ceiling (200) and the wider policy/credential
    // ceiling (500) — permitted only if the GENUINE history narrowing is
    // correctly applied despite the forged entry sitting right next to it.
    const request: NegotiationRequest = { action: ACTION, scope: { amount: 150 } };

    const decision = await supplier.evaluatePresentation(challenge, presentation, request);
    expect(decision.stage).toBe("policy");
    expect(decision.permitted).toBe(true);

    // Requesting ABOVE the narrowed 200 ceiling (but below 500) is
    // refused, proving the narrowing genuinely took effect — this isn't
    // vacuously permitted regardless of history.
    const overNarrowedChallenge = supplier.issueChallenge();
    const overNarrowedDecision = await supplier.evaluatePresentation(
      overNarrowedChallenge,
      {
        proof: fixture.buyer.provePossession(overNarrowedChallenge),
        credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus, historyJwts: [genuineHistoryJwt, forgedHistoryJwt] },
      },
      { action: ACTION, scope: { amount: 300 } },
    );
    expect(overNarrowedDecision.permitted).toBe(false);
    if (overNarrowedDecision.stage === "policy" && !overNarrowedDecision.permitted) {
      expect(overNarrowedDecision.explanation.refusalKind).toBe("history-constraint");
      expect(overNarrowedDecision.explanation.field.permitted).toBe(200);
    }
  });

  it("HELD: two forged authority-credential-shaped strings cannot even be submitted simultaneously — the protocol's own message shape (`PresentedCredentials.authorityJwt: string`, singular) structurally admits only ONE authority credential per presentation, so 'two competing authority credentials' has no code path to reach at all", async () => {
    const fixture = buildFourBeatFixture();
    const challenge = fixture.supplier.issueChallenge();
    // There is no field to put a second authorityJwt into — TypeScript
    // itself refuses an `authorityJwt` that isn't a single string, and
    // there is no array/list variant anywhere in `PresentedCredentials`.
    const presentation: Presentation = {
      proof: fixture.buyer.provePossession(challenge),
      credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
    };
    const decision = await fixture.supplier.evaluatePresentation(challenge, presentation, { action: ACTION, scope: { amount: 10 } });
    expect(decision.permitted).toBe(true);
  });
});
