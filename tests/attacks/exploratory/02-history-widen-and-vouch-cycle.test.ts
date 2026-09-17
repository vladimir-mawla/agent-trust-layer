/**
 * PART 3 EXPLORATORY — idea 3: "a history attestation crafted to widen
 * rather than narrow", and idea 4: "a vouch chain that loops back on
 * itself".
 *
 * Both held. Reported honestly below.
 */
import { describe, expect, it } from "vitest";
import { issueHistoryAttestation } from "../../../lib/credentials/index.js";
import { evaluateIssuerTrust, issueVouch, TrustAnchorSet } from "../../../lib/trust/index.js";
import { buildFourBeatFixture, Supplier } from "../../../lib/negotiation/index.js";
import type { Presentation, NegotiationRequest } from "../../../lib/negotiation/index.js";
import type { Policy } from "../../../lib/policy/index.js";
import { makeIdentity } from "../helpers.js";

const ACTION = "purchase-office-supplies";

describe("exploratory 3 — a history attestation crafted to widen rather than narrow", () => {
  it("HELD: an UNTRUSTED, attacker-controlled observer can still issue a favorable history attestation (history has no anchor gate, by design), but even a policy author's absurdly high narrowedMax (10,000,000) has ZERO effect beyond the credential/policy's own tighter ceiling (500) — Math.min, not Math.max, always wins", async () => {
    const fixture = buildFourBeatFixture();
    const policyWithGenerousNarrowRule: Policy = {
      id: "widen-attempt-policy",
      version: "1.0.0",
      revocationHandling: { requireChecked: true },
      rules: [
        { kind: "action-scope", id: "R-scope", description: "base ceiling", action: ACTION, maxScope: { amount: 500 } },
        {
          kind: "history-narrow",
          id: "R-careless-author",
          description: "a careless policy author wrote an absurdly high narrowedMax, hoping favorable history would grant MORE than the credential allows",
          action: ACTION,
          observationType: "dispute-record",
          metric: "disputeCount",
          operator: "lte",
          threshold: 0,
          scopeField: "amount",
          narrowedMax: 10_000_000, // intentionally absurd
        },
      ],
    };
    const supplier = new Supplier({ policy: policyWithGenerousNarrowRule, anchors: fixture.anchors, statusListResolver: fixture.resolver, now: fixture.now });

    // The attacker itself (untrusted for AUTHORITY purposes, but history
    // has no anchor requirement at all) issues a maximally favorable
    // history attestation about the Buyer.
    const attackerObserver = makeIdentity();
    const attackerCraftedHistoryJwt = issueHistoryAttestation({
      issuerPrivateKey: attackerObserver.privateKey,
      issuerDid: attackerObserver.did,
      subjectDid: fixture.buyer.did,
      observationType: "dispute-record",
      metrics: { disputeCount: 0 },
      now: fixture.now,
    });

    const challenge = supplier.issueChallenge();
    const presentation: Presentation = {
      proof: fixture.buyer.provePossession(challenge),
      credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus, historyJwts: [attackerCraftedHistoryJwt] },
    };
    // Requests an amount that WOULD be permitted if the absurd
    // narrowedMax (10,000,000) had actually taken effect as a widening,
    // but is over the credential's/policy's own real ceiling (500).
    const request: NegotiationRequest = { action: ACTION, scope: { amount: 5_000 } };

    const decision = await supplier.evaluatePresentation(challenge, presentation, request);

    expect(decision.stage).toBe("policy");
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("over-scope");
      // The effective ceiling is still 500 — never 10,000,000.
      expect(decision.explanation.field.permitted).toBe(500);
    }
  });
});

describe("exploratory 4 — a vouch chain that loops back on itself (A vouches B, B vouches C, C vouches A)", () => {
  it("HELD: the cycle has ZERO effect — VOUCH_DEPTH_LIMIT=1 means only a vouch whose OWN issuer is a direct anchor is ever consulted; nothing walks the chain, so there is no cycle to fall into, and the credential is refused as untrusted-issuer, quickly (no hang)", () => {
    const anchor = makeIdentity(); // the only configured trust anchor
    const b = makeIdentity();
    const c = makeIdentity();
    const anchors = new TrustAnchorSet([anchor.did]);

    const anchorVouchesB = issueVouch({ voucherPrivateKey: anchor.privateKey, voucherDid: anchor.did, vouchedIssuerDid: b.did });
    const bVouchesC = issueVouch({ voucherPrivateKey: b.privateKey, voucherDid: b.did, vouchedIssuerDid: c.did });
    // Closes the loop: C vouches for the ANCHOR itself.
    const cVouchesAnchor = issueVouch({ voucherPrivateKey: c.privateKey, voucherDid: c.did, vouchedIssuerDid: anchor.did });

    const startedAt = Date.now();
    // Evaluate trust for C — an attacker might hope the engine "walks"
    // the cycle (anchor -> B -> C -> anchor) and concludes the anchor
    // transitively vouches for C.
    const result = evaluateIssuerTrust(c.did, { subject: b.did, anchors, vouches: [anchorVouchesB, bVouchesC, cVouchesAnchor] });
    const elapsedMs = Date.now() - startedAt;

    expect(result.trusted).toBe(false);
    if (!result.trusted) {
      expect(result.reason.kind).toBe("untrusted-issuer");
    }
    // Structural guarantee, not just an outcome: this must be fast —
    // there is no recursive chain-walk to hang on, cyclical or not.
    expect(elapsedMs).toBeLessThan(2_000);
  });

  it("HELD: a self-referential vouch (an entity vouching for itself) that also participates in a cycle changes nothing — self-vouching is not self-issuance (a different check entirely) but still never establishes trust on its own", () => {
    const anchor = makeIdentity();
    const attacker = makeIdentity();
    const anchors = new TrustAnchorSet([anchor.did]);

    // The attacker vouches for itself, hoping a vouch is treated as
    // sufficient on its own regardless of who signed it.
    const selfVouch = issueVouch({ voucherPrivateKey: attacker.privateKey, voucherDid: attacker.did, vouchedIssuerDid: attacker.did });

    const result = evaluateIssuerTrust(attacker.did, { subject: makeIdentity().did, anchors, vouches: [selfVouch] });
    expect(result.trusted).toBe(false);
    if (!result.trusted) {
      // The voucher (attacker) is not a direct anchor, so this vouch is
      // never even consulted — refused as untrusted-issuer, not treated
      // as a self-issuance special case (that check is about the
      // CREDENTIAL's issuer === subject, an orthogonal concern).
      expect(result.reason.kind).toBe("untrusted-issuer");
    }
  });
});
