/**
 * ATTACK 6 — revoked credential: a genuinely valid, correctly-signed,
 * unexpired, correctly-anchored authority credential whose issuer has
 * since revoked it via the W3C Bitstring Status List (ADR 0003).
 *
 * Mechanism asserted: `lib/trust/status-list.ts`'s `checkRevocation`
 * resolves the real status list, finds the credential's own bit SET,
 * and returns `{ outcome: "revoked" }`; `lib/trust/trust-decision.ts`
 * turns that into `TrustDecision.stage === "revocation"`;
 * `lib/policy/engine.ts` turns THAT into `refusalKind: "revoked"`.
 * Distinguished explicitly from attack 5 (expired): M3's verification
 * chain (signature/structure/temporal/subject-binding/issuer-identity)
 * passes COMPLETELY here — `credentialVerification.ok === true` — this
 * is caught one whole layer later, by M4, never by M3.
 */
import { describe, expect, it } from "vitest";
import { createChallenge } from "../../../lib/identity/index.js";
import { evaluateAuthorityCredentialTrust, TrustAnchorSet, type StatusListResolver } from "../../../lib/trust/index.js";
import { KeyHolder, Supplier, buildFourBeatFixture } from "../../../lib/negotiation/index.js";
import type { Presentation, NegotiationRequest } from "../../../lib/negotiation/index.js";
import { ONE_YEAR_MS } from "../helpers.js";

describe("attack 6 — revoked credential", () => {
  it("[mechanism] evaluateAuthorityCredentialTrust reports stage \"revocation\", outcome \"revoked\" — while M3's own verification is completely clean (ok: true)", async () => {
    const now = Date.parse("2026-09-17T00:00:00.000Z");
    const issuer = new KeyHolder();
    const buyer = new KeyHolder();

    const revokedStatusListJwt = issuer.issueStatusListCredential({
      statusPurpose: "revocation",
      sizeBits: 128,
      revokedIndices: [0],
      now,
    });
    const statusListUrl = "https://issuer.example/status-lists/revoked-test";
    const resolver: StatusListResolver = async (url: string) => {
      if (url !== statusListUrl) throw new Error("unexpected url");
      return revokedStatusListJwt;
    };
    const credentialStatus = {
      type: "BitstringStatusListEntry" as const,
      statusPurpose: "revocation",
      statusListIndex: 0,
      statusListCredential: statusListUrl,
    };
    const authorityJwt = issuer.issueAuthorityCredentialTo({
      subjectDid: buyer.did,
      action: "purchase-office-supplies",
      scope: { amount: 500 },
      validFrom: new Date(now).toISOString(),
      validUntil: new Date(now + ONE_YEAR_MS).toISOString(),
      now,
    });
    const challenge = createChallenge({ now });
    const proof = buyer.provePossession(challenge);
    const anchors = new TrustAnchorSet([issuer.did]);

    const decision = await evaluateAuthorityCredentialTrust({
      jwt: authorityJwt,
      presenterProof: proof,
      anchors,
      credentialStatus,
      statusListResolver: resolver,
      now,
    });

    expect(decision.accepted).toBe(false);
    if (!decision.accepted) {
      expect(decision.stage).toBe("revocation");
      // M3's own verification chain succeeded completely — this really
      // is caught one layer later, by M4, never by M3.
      expect(decision.credentialVerification.ok).toBe(true);
      if (decision.stage === "revocation") {
        expect(decision.revocation.outcome).toBe("revoked");
      }
    }
  });

  it("[end-to-end] the Supplier refuses with refusalKind \"revoked\" — never \"credential-verification-failed\"", async () => {
    const fixture = buildFourBeatFixture();
    // Reissue a status list where the Buyer's own index (0) IS revoked,
    // reusing the fixture's real issuer/buyer/policy/anchors.
    const revokedStatusListJwt = fixture.issuer.issueStatusListCredential({
      statusPurpose: "revocation",
      sizeBits: 128,
      revokedIndices: [0],
      now: fixture.now,
    });
    const resolver: StatusListResolver = async (url: string) => {
      if (url !== fixture.buyerCredentialStatus.statusListCredential) throw new Error("unexpected url");
      return revokedStatusListJwt;
    };
    const supplier = new Supplier({ policy: fixture.policy, anchors: fixture.anchors, statusListResolver: resolver, now: fixture.now });

    const challenge = supplier.issueChallenge();
    const presentation: Presentation = {
      proof: fixture.buyer.provePossession(challenge),
      credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
    };
    const request: NegotiationRequest = { action: "purchase-office-supplies", scope: { amount: 100 } };

    const decision = await supplier.evaluatePresentation(challenge, presentation, request);

    expect(decision.stage).toBe("policy");
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("revoked");
      expect(decision.explanation.refusalKind).not.toBe("credential-verification-failed");
      expect(decision.explanation.field.path).toBe("revocation.outcome");
      expect(decision.explanation.field.actual).toBe("revoked");
    }
  });
});
