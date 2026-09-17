/**
 * ATTACK 3 — a stolen credential replayed by a different subject: Agent
 * B (the attacker) captures Agent A's (the Buyer's) real, validly-issued,
 * unexpired `AuthorityCredential` — DIDs and credentials are public,
 * copyable data (see ADR 0001) — and presents it as ITS OWN evidence,
 * while HONESTLY proving possession of ITS OWN key (not spoofing A's
 * DID; that is attack 8 / M6 Beat 3, a structurally different failure).
 *
 * Mechanism asserted: `lib/credentials/verify.ts` step 5
 * ("subject-binding"), `SubjectBindingError` — `credentialSubject.id`
 * (the Buyer's DID) does not equal the DID the presenter actually,
 * cryptographically proved possession of (the Attacker's own DID). This
 * is the anti-replay gate named explicitly in DONE.html's own Definition
 * of Done ("A presentation that replays another agent's credential is
 * rejected on subject binding").
 *
 * Distinguished from attack 8 (DID impersonation): here proof-of-
 * possession SUCCEEDS (the attacker really does control the key behind
 * the DID it claims — its own), so the Supplier reaches the "policy"
 * stage and M3's verification chain, and is refused there, at
 * subject-binding — never at the proof-of-possession gate.
 */
import { describe, expect, it } from "vitest";
import { createChallenge } from "../../../lib/identity/index.js";
import { verifyAuthorityCredential } from "../../../lib/credentials/index.js";
import { buildFourBeatFixture } from "../../../lib/negotiation/index.js";
import type { Presentation, NegotiationRequest } from "../../../lib/negotiation/index.js";

describe("attack 3 — stolen credential replayed by a different subject", () => {
  it("[mechanism] verifyAuthorityCredential fails at step \"subject-binding\" via SubjectBindingError when the presenter honestly proves a DIFFERENT DID than the credential's subject", () => {
    const fixture = buildFourBeatFixture();
    const challenge = createChallenge({ now: fixture.now });

    // The Attacker proves possession of its OWN key, honestly — this is
    // a real, valid proof, just for the wrong identity to use this
    // particular (stolen) credential.
    const attackerHonestProof = fixture.attacker.provePossession(challenge);

    const result = verifyAuthorityCredential(fixture.buyerAuthorityJwt, attackerHonestProof, { now: fixture.now });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.step).toBe("subject-binding");
      expect((result.cause as Error).name).toBe("SubjectBindingError");
      expect(result.reason).toContain(fixture.buyer.did);
      expect(result.reason).toContain(fixture.attacker.did);
    }
  });

  it("[end-to-end] the Supplier reaches the policy stage (proof of possession succeeded) and refuses there, at subject-binding — never at proof-of-possession", async () => {
    const fixture = buildFourBeatFixture();
    const challenge = fixture.supplier.issueChallenge();
    const presentation: Presentation = {
      proof: fixture.attacker.provePossession(challenge), // honest, own key
      credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
    };
    const request: NegotiationRequest = { action: "purchase-office-supplies", scope: { amount: 100 } };

    const decision = await fixture.supplier.evaluatePresentation(challenge, presentation, request);

    // Proof of possession succeeded — this is NOT a proof-of-possession
    // stage refusal, which is exactly what distinguishes this attack
    // from DID impersonation (attack 8).
    expect(decision.stage).toBe("policy");
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("credential-verification-failed");
      expect(decision.explanation.field.path).toBe("credentialVerification.step:subject-binding");
      expect(decision.explanation.refusalKind).not.toBe("untrusted-issuer");
    }
    if (decision.stage === "policy") {
      expect(decision.provenDid).toBe(fixture.attacker.did);
    }
  });
});
