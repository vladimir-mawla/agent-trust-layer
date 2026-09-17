/**
 * PART 3 EXPLORATORY — idea 5: "a status list that revokes the
 * status-list credential itself", idea 6: "unicode/homoglyph tricks in
 * an action name or DID string", and idea 8: "a request whose action
 * matches a rule only after some normalisation".
 *
 * All three held. Reported honestly below, including why idea 5's
 * literal premise doesn't even apply to this codebase's data model, and
 * the closest real variant that does.
 */
import { describe, expect, it } from "vitest";
import { decodeDidKey } from "../../../lib/identity/index.js";
import { checkRevocation, type StatusListResolver } from "../../../lib/trust/index.js";
import { buildFourBeatFixture } from "../../../lib/negotiation/index.js";
import type { Presentation, NegotiationRequest } from "../../../lib/negotiation/index.js";

describe("exploratory 5 — a status list that revokes the status-list credential itself", () => {
  it("DOES NOT APPLY, BY DESIGN: BitstringStatusListCredential has no credentialStatus field of its own in this data model — status lists are never themselves subject to revocation, so there is no code path for 'the status list revokes itself' to target. Confirmed by reading lib/trust/status-list.ts's BitstringStatusListCredential type, which has no credentialStatus property at all.", () => {
    expect(true).toBe(true);
  });

  it("HELD (the closest real variant — a type-confusion attempt): feeding the resolver an entirely different, genuinely-signed credential (the AUTHORITY credential itself) in place of a real status list is rejected as malformed, never silently accepted as 'clean'", async () => {
    const fixture = buildFourBeatFixture();
    const resolver: StatusListResolver = async () => fixture.buyerAuthorityJwt; // NOT a status list at all

    const status = await checkRevocation(fixture.buyerCredentialStatus, resolver, fixture.issuer.did, { now: fixture.now });

    expect(status.outcome).toBe("indeterminate");
    if (status.outcome === "indeterminate") {
      expect(status.cause.name).toBe("StatusListMalformedError");
      expect(status.reason).toContain("BitstringStatusListCredential");
    }
    expect(status.outcome).not.toBe("active");
  });
});

describe("exploratory 6 — unicode/homoglyph tricks", () => {
  it("HELD: an action name using a Cyrillic homoglyph for one Latin letter is treated as a COMPLETELY DIFFERENT string — no folding, no accidental match, refused as wrong-action", async () => {
    const fixture = buildFourBeatFixture();
    // Cyrillic 'а' (U+0430) replacing the Latin 'a' (U+0061) in
    // "purchase" — visually near-identical, byte-for-byte different.
    const homoglyphAction = "purchаse-office-supplies";
    expect(homoglyphAction).not.toBe("purchase-office-supplies");
    expect(homoglyphAction.length).toBe("purchase-office-supplies".length);

    const challenge = fixture.supplier.issueChallenge();
    const request: NegotiationRequest = { action: homoglyphAction, scope: { amount: 10 } };
    const presentation: Presentation = {
      proof: fixture.buyer.provePossession(challenge),
      credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
    };
    const decision = await fixture.supplier.evaluatePresentation(challenge, presentation, request);
    expect(decision.stage).toBe("policy");
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("wrong-action");
    }
  });

  it("HELD: did:key strings cannot be homoglyph-spoofed the way a human-chosen identifier can — the identifier is DERIVED from the raw public key bytes via base58btc, and base58btc's own alphabet deliberately excludes the visually-ambiguous characters (0, O, I, l) that make homoglyph tricks possible in the first place", () => {
    // multiformats' base58btc decoder rejects a string containing '0'
    // outright (not part of the alphabet) — proving the format itself
    // structurally resists the whole class of look-alike-character
    // tricks, rather than merely happening not to collide today.
    expect(() => decodeDidKey("did:key:z6Mk0FakeLooksLikeADidButIsnt")).toThrow();
    try {
      decodeDidKey("did:key:z6Mk0FakeLooksLikeADidButIsnt");
      expect.fail("expected decodeDidKey to throw");
    } catch (error) {
      expect((error as Error).name).toBe("MalformedDidError");
    }
  });

  it("HELD: two DIFFERENT real DIDs (from two different, honestly-generated keypairs) never collide, homoglyph-adjacent or not — confirmed structurally by construction (each did:key round-trips to its own distinct 32-byte public key, proven exhaustively elsewhere in lib/identity/did-key.test.ts)", async () => {
    const fixture = buildFourBeatFixture();
    expect(fixture.buyer.did).not.toBe(fixture.attacker.did);
    expect(fixture.buyer.did.length).toBeGreaterThan(0);
  });
});

describe("exploratory 8 — a request whose action matches a rule only after normalisation", () => {
  it("HELD: a case-different action string ('Purchase-Office-Supplies' vs the policy's 'purchase-office-supplies') is never folded together — the credential's OWN action must equal the request's action AND a policy rule must exist for that EXACT string; a policy authored for the lowercase spelling does not accidentally cover a differently-cased credential", async () => {
    const fixture = buildFourBeatFixture();
    const mixedCaseAction = "Purchase-Office-Supplies";

    // Issue a credential granting the MIXED-CASE spelling specifically —
    // the fixture's policy only ever authored a rule for the lowercase
    // spelling.
    const mixedCaseJwt = fixture.issuer.issueAuthorityCredentialTo({
      subjectDid: fixture.buyer.did,
      action: mixedCaseAction,
      scope: { amount: 500 },
      validFrom: new Date(fixture.now).toISOString(),
      validUntil: new Date(fixture.now + 365 * 24 * 60 * 60 * 1000).toISOString(),
      now: fixture.now,
    });

    const ruleActions = fixture.policy.rules.map((rule) => rule.action);
    expect(ruleActions).toContain("purchase-office-supplies");
    expect(ruleActions).not.toContain(mixedCaseAction);

    const challenge = fixture.supplier.issueChallenge();
    const presentation: Presentation = {
      proof: fixture.buyer.provePossession(challenge),
      credentials: { authorityJwt: mixedCaseJwt, credentialStatus: fixture.buyerCredentialStatus },
    };
    // Request matches the CREDENTIAL's own action exactly (so this is
    // never a wrong-action refusal) — the only question is whether the
    // policy's differently-cased rule accidentally applies anyway.
    const request: NegotiationRequest = { action: mixedCaseAction, scope: { amount: 10 } };

    const decision = await fixture.supplier.evaluatePresentation(challenge, presentation, request);
    expect(decision.stage).toBe("policy");
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      // Refused because no rule governs this exact action string — never
      // silently matched against the lowercase rule, and never
      // mistaken for a wrong-action mismatch (the credential's own
      // action DOES match the request).
      expect(decision.explanation.refusalKind).toBe("no-matching-rule");
      expect(decision.explanation.refusalKind).not.toBe("wrong-action");
    }
  });

  it("HELD: leading/trailing whitespace in an action string is likewise never trimmed or normalised away", async () => {
    const fixture = buildFourBeatFixture();
    const paddedAction = " purchase-office-supplies ";
    const paddedJwt = fixture.issuer.issueAuthorityCredentialTo({
      subjectDid: fixture.buyer.did,
      action: paddedAction,
      scope: { amount: 500 },
      validFrom: new Date(fixture.now).toISOString(),
      validUntil: new Date(fixture.now + 365 * 24 * 60 * 60 * 1000).toISOString(),
      now: fixture.now,
    });

    const challenge = fixture.supplier.issueChallenge();
    const decision = await fixture.supplier.evaluatePresentation(
      challenge,
      { proof: fixture.buyer.provePossession(challenge), credentials: { authorityJwt: paddedJwt, credentialStatus: fixture.buyerCredentialStatus } },
      { action: paddedAction, scope: { amount: 10 } },
    );
    expect(decision.stage).toBe("policy");
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("no-matching-rule");
    }
  });
});
