/**
 * ATTACK 7 — self-issued authority: the attacker mints itself an
 * `AuthorityCredential` (issuer === subject === attacker.did), signs it
 * with its own, genuinely-controlled key, and honestly proves possession
 * of that same key. Every cryptographic check M3 runs passes cleanly —
 * this is "I say I may, therefore I may", and the ENTIRE point of this
 * attack is that a valid signature is not the same question as a
 * trustworthy issuer (ADR 0003's own framing of the M3 finding that
 * motivated M4's existence).
 *
 * Mechanism asserted: `lib/trust/anchors.ts`'s `evaluateIssuerTrust`
 * checks `issuer === subject` BEFORE consulting the anchor set at all
 * (a deliberate ordering — see that module's own comment) and returns
 * `{ trusted: false, reason: { kind: "self-issued" } }`, unconditionally
 * — even if the attacker's own DID happened to be a configured anchor.
 * `lib/policy/engine.ts` turns this into `refusalKind: "untrusted-issuer"`.
 *
 * The task brief calls this out by name: this attack MUST be shown to
 * fail on issuer trust and explicitly NOT on
 * "credential-verification-failed", because the attacker's signature is
 * genuinely, cryptographically valid.
 */
import { describe, expect, it } from "vitest";
import { createChallenge } from "../../../lib/identity/index.js";
import { evaluateAuthorityCredentialTrust, evaluateIssuerTrust, TrustAnchorSet } from "../../../lib/trust/index.js";
import { KeyHolder, Supplier, buildFourBeatFixture } from "../../../lib/negotiation/index.js";
import type { Presentation, NegotiationRequest } from "../../../lib/negotiation/index.js";
import { ONE_YEAR_MS } from "../helpers.js";

describe("attack 7 — self-issued authority", () => {
  it("[mechanism, direct] evaluateIssuerTrust refuses self-issuance UNCONDITIONALLY — even when the self-issuing DID is itself a configured trust anchor", () => {
    const attacker = new KeyHolder();
    // Deliberately construct the WORST case for this gate: the attacker's
    // own DID IS a configured anchor. If self-issuance were checked
    // AFTER anchor membership (or skipped for anchors), this would wrongly
    // be trusted.
    const anchors = new TrustAnchorSet([attacker.did]);

    const result = evaluateIssuerTrust(attacker.did, { subject: attacker.did, anchors });

    expect(result.trusted).toBe(false);
    if (!result.trusted) {
      expect(result.reason.kind).toBe("self-issued");
      expect(result.reason.kind).not.toBe("untrusted-issuer");
    }
  });

  it("[mechanism] evaluateAuthorityCredentialTrust: credentialVerification.ok is TRUE (a genuinely valid signature) but accepted is FALSE at stage \"issuer-trust\", reason self-issued", async () => {
    const fixture = buildFourBeatFixture();
    const forgedJwt = fixture.attacker.issueAuthorityCredentialTo({
      subjectDid: fixture.attacker.did,
      action: "purchase-office-supplies",
      scope: { amount: 1_000_000 },
      validFrom: new Date(fixture.now).toISOString(),
      validUntil: new Date(fixture.now + ONE_YEAR_MS).toISOString(),
      now: fixture.now,
    });
    const challenge = createChallenge({ now: fixture.now });
    const proof = fixture.attacker.provePossession(challenge);

    const decision = await evaluateAuthorityCredentialTrust({
      jwt: forgedJwt,
      presenterProof: proof,
      anchors: fixture.anchors,
      now: fixture.now,
    });

    expect(decision.accepted).toBe(false);
    if (!decision.accepted) {
      // The attacker's signature genuinely verifies — this is the crux
      // of the whole attack, and the crux of this test.
      expect(decision.credentialVerification.ok).toBe(true);
      expect(decision.stage).toBe("issuer-trust");
      expect(decision.stage).not.toBe("credential-verification");
      if (decision.stage === "issuer-trust") {
        expect(decision.issuerTrust.trusted).toBe(false);
        expect(decision.issuerTrust.reason.kind).toBe("self-issued");
      }
    }
  });

  it("[end-to-end] the Supplier refuses with refusalKind \"untrusted-issuer\" (field.actual = \"self-issued\") — explicitly NOT \"credential-verification-failed\"", async () => {
    const fixture = buildFourBeatFixture();
    const forgedJwt = fixture.attacker.issueAuthorityCredentialTo({
      subjectDid: fixture.attacker.did,
      action: "purchase-office-supplies",
      scope: { amount: 1_000_000 },
      validFrom: new Date(fixture.now).toISOString(),
      validUntil: new Date(fixture.now + ONE_YEAR_MS).toISOString(),
      now: fixture.now,
    });
    const challenge = fixture.supplier.issueChallenge();
    const presentation: Presentation = {
      proof: fixture.attacker.provePossession(challenge),
      credentials: { authorityJwt: forgedJwt },
    };
    const request: NegotiationRequest = { action: "purchase-office-supplies", scope: { amount: 1000 } };

    const decision = await fixture.supplier.evaluatePresentation(challenge, presentation, request);

    expect(decision.stage).toBe("policy");
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("untrusted-issuer");
      expect(decision.explanation.field.actual).toBe("self-issued");
      // The brief's own explicit negative assertion: a genuinely valid
      // signature must never be mislabelled as a verification failure.
      expect(decision.explanation.refusalKind).not.toBe("credential-verification-failed");
    }
  });
});
