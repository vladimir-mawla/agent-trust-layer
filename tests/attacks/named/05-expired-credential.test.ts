/**
 * ATTACK 5 — expired credential: a genuinely valid, correctly-signed
 * authority credential is presented after its own `validUntil`.
 *
 * Mechanism asserted: `lib/credentials/verify.ts` step 4 ("temporal"),
 * `CredentialExpiredError` — explicit clock-skew-tolerant comparison
 * against `validUntil`. Distinguished explicitly from attack 6 (revoked
 * credential): expiry is an M3, offline, signature-adjacent check with
 * no network dependency at all, whereas revocation (attack 6) is an M4
 * check that requires resolving a status list. A credential can be
 * expired-but-never-revoked, or revoked-but-not-yet-expired — this test
 * pins the FIRST one specifically and asserts it is never confused with
 * the second.
 */
import { describe, expect, it } from "vitest";
import { createChallenge } from "../../../lib/identity/index.js";
import { verifyAuthorityCredential } from "../../../lib/credentials/index.js";
import { Supplier, buildFourBeatFixture } from "../../../lib/negotiation/index.js";
import type { Presentation, NegotiationRequest } from "../../../lib/negotiation/index.js";
import { ONE_YEAR_MS } from "../helpers.js";

describe("attack 5 — expired credential", () => {
  it("[mechanism] verifyAuthorityCredential fails at step \"temporal\" via CredentialExpiredError once now is past validUntil (+ clock skew)", () => {
    const fixture = buildFourBeatFixture();
    const issuedAt = fixture.now;
    const validUntil = issuedAt + 60_000; // expires one minute after issuance
    const expiredJwt = fixture.issuer.issueAuthorityCredentialTo({
      subjectDid: fixture.buyer.did,
      action: "purchase-office-supplies",
      scope: { amount: 500 },
      validFrom: new Date(issuedAt).toISOString(),
      validUntil: new Date(validUntil).toISOString(),
      now: issuedAt,
    });

    // Well past validUntil, well past any reasonable clock-skew window.
    const checkedAt = validUntil + 10 * 60_000;
    const challenge = createChallenge({ now: checkedAt });
    const proof = fixture.buyer.provePossession(challenge);

    const result = verifyAuthorityCredential(expiredJwt, proof, { now: checkedAt });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.step).toBe("temporal");
      expect((result.cause as Error).name).toBe("CredentialExpiredError");
      expect(result.step).not.toBe("signature");
    }
  });

  it("[sanity] the SAME credential verifies fine one second before it expires", () => {
    const fixture = buildFourBeatFixture();
    const issuedAt = fixture.now;
    const validUntil = issuedAt + 60_000;
    const jwt = fixture.issuer.issueAuthorityCredentialTo({
      subjectDid: fixture.buyer.did,
      action: "purchase-office-supplies",
      scope: { amount: 500 },
      validFrom: new Date(issuedAt).toISOString(),
      validUntil: new Date(validUntil).toISOString(),
      now: issuedAt,
    });
    const checkedAt = validUntil - 1_000;
    const challenge = createChallenge({ now: checkedAt });
    const proof = fixture.buyer.provePossession(challenge);
    const result = verifyAuthorityCredential(jwt, proof, { now: checkedAt });
    expect(result.ok).toBe(true);
  });

  it("[end-to-end] the Supplier refuses an expired credential as credential-verification-failed at the temporal step, never as revoked", async () => {
    const fixture = buildFourBeatFixture();
    const issuedAt = fixture.now;
    const validUntil = issuedAt + 60_000;
    const expiredJwt = fixture.issuer.issueAuthorityCredentialTo({
      subjectDid: fixture.buyer.did,
      action: "purchase-office-supplies",
      scope: { amount: 500 },
      validFrom: new Date(issuedAt).toISOString(),
      validUntil: new Date(validUntil).toISOString(),
      now: issuedAt,
    });

    const checkedAt = validUntil + 10 * 60_000;
    const supplier = new Supplier({
      policy: fixture.policy,
      anchors: fixture.anchors,
      statusListResolver: fixture.resolver,
      now: checkedAt,
    });
    const challenge = supplier.issueChallenge();
    const presentation: Presentation = {
      proof: fixture.buyer.provePossession(challenge),
      credentials: { authorityJwt: expiredJwt, credentialStatus: fixture.buyerCredentialStatus },
    };
    const request: NegotiationRequest = { action: "purchase-office-supplies", scope: { amount: 100 } };

    const decision = await supplier.evaluatePresentation(challenge, presentation, request);

    expect(decision.stage).toBe("policy");
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("credential-verification-failed");
      expect(decision.explanation.field.path).toBe("credentialVerification.step:temporal");
      expect(decision.explanation.refusalKind).not.toBe("revoked");
    }
  });
});
