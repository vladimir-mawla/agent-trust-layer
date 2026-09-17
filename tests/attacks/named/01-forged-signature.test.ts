/**
 * ATTACK 1 — forged signature: a credential whose signature does not
 * verify against the public key its own header/`kid` names.
 *
 * Mechanism asserted: `lib/credentials/verify.ts` step 2 ("signature"),
 * `SignatureVerificationFailedError` — the Ed25519 check over
 * `base64url(header).base64url(payload)` fails. This must be caught
 * BEFORE the payload is even JSON-decoded (see `jws.ts`'s
 * `SignatureVerified` witness token), so nothing about the (forged)
 * claim's content ever gets a chance to matter.
 *
 * Distinguished from attack 2 ("tampered claim"): here the payload is
 * byte-for-byte what the real issuer signed — only the signature bytes
 * themselves are corrupted (as if bit-flipped in transit, or produced by
 * a party who never had the real key at all). Distinguished from attack
 * 7 ("self-issued authority") and attack 12 (issuer-trust bypass): this
 * credential never reaches issuer-trust or revocation at all, because it
 * fails one step earlier.
 */
import { describe, expect, it } from "vitest";
import { createChallenge } from "../../../lib/identity/index.js";
import { issueAuthorityCredential, verifyAuthorityCredential } from "../../../lib/credentials/index.js";
import { buildFourBeatFixture } from "../../../lib/negotiation/index.js";
import type { Presentation, NegotiationRequest } from "../../../lib/negotiation/index.js";
import { corruptSignatureSegment, ONE_YEAR_MS } from "../helpers.js";

describe("attack 1 — forged signature", () => {
  it("[mechanism] verifyAuthorityCredential fails at step \"signature\" via SignatureVerificationFailedError, never reaching structure/temporal/subject-binding/issuer-identity", () => {
    const fixture = buildFourBeatFixture();
    const genuineJwt = fixture.issuer.issueAuthorityCredentialTo({
      subjectDid: fixture.buyer.did,
      action: "purchase-office-supplies",
      scope: { amount: 500 },
      validFrom: new Date(fixture.now).toISOString(),
      validUntil: new Date(fixture.now + ONE_YEAR_MS).toISOString(),
      now: fixture.now,
    });
    const forgedJwt = corruptSignatureSegment(genuineJwt);
    expect(forgedJwt).not.toBe(genuineJwt);

    const challenge = createChallenge({ now: fixture.now });
    const proof = fixture.buyer.provePossession(challenge);

    const result = verifyAuthorityCredential(forgedJwt, proof, { now: fixture.now });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.step).toBe("signature");
      expect(result.cause).toBeInstanceOf(Error);
      expect((result.cause as Error).name).toBe("SignatureVerificationFailedError");
      // Explicitly NOT any later step — proves the chain stopped here,
      // not that it ran further and merely also disliked something else.
      expect(result.step).not.toBe("structure");
      expect(result.step).not.toBe("temporal");
      expect(result.step).not.toBe("subject-binding");
      expect(result.step).not.toBe("issuer-identity");
    }
  });

  it("[end-to-end] the Supplier refuses at the policy stage with refusalKind \"credential-verification-failed\", citing the \"signature\" step — never \"untrusted-issuer\" or \"revoked\"", async () => {
    const fixture = buildFourBeatFixture();
    const forgedJwt = corruptSignatureSegment(fixture.buyerAuthorityJwt);

    const challenge = fixture.supplier.issueChallenge();
    const presentation: Presentation = {
      proof: fixture.buyer.provePossession(challenge),
      credentials: { authorityJwt: forgedJwt, credentialStatus: fixture.buyerCredentialStatus },
    };
    const request: NegotiationRequest = { action: "purchase-office-supplies", scope: { amount: 100 } };

    const decision = await fixture.supplier.evaluatePresentation(challenge, presentation, request);

    expect(decision.stage).toBe("policy");
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("credential-verification-failed");
      expect(decision.explanation.field.path).toBe("credentialVerification.step:signature");
      // The RIGHT gate, not any of the other plausible-sounding ones.
      expect(decision.explanation.refusalKind).not.toBe("untrusted-issuer");
      expect(decision.explanation.refusalKind).not.toBe("revoked");
      expect(decision.explanation.refusalKind).not.toBe("over-scope");
    }
  });
});
