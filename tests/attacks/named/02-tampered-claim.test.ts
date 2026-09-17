/**
 * ATTACK 2 — tampered claim: a byte changed in the payload AFTER
 * signing (e.g. a captured-in-transit credential whose `scope.amount`
 * is bumped from 500 to 500000, or whose subject is swapped).
 *
 * Mechanism asserted: identical underlying check to attack 1
 * (`lib/credentials/verify.ts` step 2, `SignatureVerificationFailedError`)
 * — the whole point of a JWS is that the signature covers the payload
 * bytes verbatim, so ANY post-signing mutation, however small, makes the
 * existing signature fail to verify over the new bytes. This test is
 * kept distinct from attack 1 because it exercises the OTHER real-world
 * scenario named in the M3 success criterion ("the suite proves a
 * tampered claim fails verification and an untampered one passes"): here
 * the attacker never had ANY key at all, honest or forged — they merely
 * intercepted a legitimately-issued credential and edited its claims.
 */
import { describe, expect, it } from "vitest";
import { createChallenge } from "../../../lib/identity/index.js";
import { verifyAuthorityCredential } from "../../../lib/credentials/index.js";
import { buildFourBeatFixture } from "../../../lib/negotiation/index.js";
import type { Presentation, NegotiationRequest } from "../../../lib/negotiation/index.js";
import { tamperPayload } from "../helpers.js";

describe("attack 2 — tampered claim", () => {
  it("[mechanism] widening scope.amount after signing fails at step \"signature\" — the untampered original still verifies fine", () => {
    const fixture = buildFourBeatFixture();
    const challenge = createChallenge({ now: fixture.now });
    const proof = fixture.buyer.provePossession(challenge);

    // Sanity: the untampered credential verifies cleanly first.
    const genuine = verifyAuthorityCredential(fixture.buyerAuthorityJwt, proof, { now: fixture.now });
    expect(genuine.ok).toBe(true);

    const tampered = tamperPayload(fixture.buyerAuthorityJwt, (payload) => {
      const subject = payload["credentialSubject"] as Record<string, unknown>;
      return {
        ...payload,
        credentialSubject: { ...subject, scope: { amount: 500_000 } },
      };
    });
    expect(tampered).not.toBe(fixture.buyerAuthorityJwt);

    const result = verifyAuthorityCredential(tampered, proof, { now: fixture.now });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.step).toBe("signature");
      expect((result.cause as Error).name).toBe("SignatureVerificationFailedError");
      // Never mistaken for a structural or temporal problem — the JSON
      // is perfectly well-shaped, it just isn't what was signed.
      expect(result.step).not.toBe("structure");
      expect(result.step).not.toBe("temporal");
    }
  });

  it("[mechanism] tampering the subject id (an attempted subject-swap) also fails at \"signature\", never reaching subject-binding", () => {
    const fixture = buildFourBeatFixture();
    const challenge = createChallenge({ now: fixture.now });
    const proof = fixture.buyer.provePossession(challenge);

    const tampered = tamperPayload(fixture.buyerAuthorityJwt, (payload) => {
      const subject = payload["credentialSubject"] as Record<string, unknown>;
      return { ...payload, credentialSubject: { ...subject, id: fixture.attacker.did } };
    });

    const result = verifyAuthorityCredential(tampered, proof, { now: fixture.now });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      // The signature check runs BEFORE subject-binding — a tampered
      // subject never even reaches the check it might seem to target.
      expect(result.step).toBe("signature");
      expect(result.step).not.toBe("subject-binding");
    }
  });

  it("[end-to-end] the Supplier refuses a tampered credential the same way it refuses a forged one: credential-verification-failed at the signature step", async () => {
    const fixture = buildFourBeatFixture();
    const tamperedJwt = tamperPayload(fixture.buyerAuthorityJwt, (payload) => {
      const subject = payload["credentialSubject"] as Record<string, unknown>;
      return { ...payload, credentialSubject: { ...subject, scope: { amount: 999_999 } } };
    });

    const challenge = fixture.supplier.issueChallenge();
    const presentation: Presentation = {
      proof: fixture.buyer.provePossession(challenge),
      credentials: { authorityJwt: tamperedJwt, credentialStatus: fixture.buyerCredentialStatus },
    };
    const request: NegotiationRequest = { action: "purchase-office-supplies", scope: { amount: 100 } };

    const decision = await fixture.supplier.evaluatePresentation(challenge, presentation, request);

    expect(decision.stage).toBe("policy");
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("credential-verification-failed");
      expect(decision.explanation.field.path).toBe("credentialVerification.step:signature");
      // Critically: NOT "over-scope" — the tampered, huge amount never
      // gets far enough to be compared against any ceiling at all.
      expect(decision.explanation.refusalKind).not.toBe("over-scope");
    }
  });
});
