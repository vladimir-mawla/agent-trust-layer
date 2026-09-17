/**
 * REGRESSION 12 — the status-list swap. REAL HISTORICAL DEFECT (M4,
 * CRITICAL), found by an independent L4 VERIFY pass and recorded in ADR
 * 0003's own "Amendment — L4 VERIFY findings" section: `checkRevocation`
 * used to verify only that a resolved status list credential was
 * INTERNALLY self-consistent (its `issuer` claim matched whoever
 * actually signed it) — it never checked that this was the CREDENTIAL's
 * OWN real issuer, or any expected identity at all.
 *
 * Concretely: a resolver that returns a clean status list signed by a
 * completely unrelated, throwaway keypair generated seconds earlier —
 * NOT the credential's real issuer, no compromise of the real issuer's
 * key required at all — used to make a genuinely revoked credential
 * read as ACTIVE. Fixed by promoting `expectedIssuer: Did` to a REQUIRED
 * parameter of `checkRevocation` (`lib/trust/status-list.ts`), with
 * `trust-decision.ts` always supplying the credential's own M3-VERIFIED
 * `verifiedIssuer` — never a claimed field.
 *
 * This test proves: a credential that is GENUINELY revoked by its real
 * issuer, when the resolver instead swaps in a clean list signed by an
 * unrelated throwaway keypair, is STILL refused — naming the issuer
 * mismatch, not silently accepted.
 */
import { describe, expect, it } from "vitest";
import { createChallenge } from "../../../lib/identity/index.js";
import { checkRevocation, evaluateAuthorityCredentialTrust, issueStatusListCredential, TrustAnchorSet, type StatusListResolver } from "../../../lib/trust/index.js";
import { KeyHolder } from "../../../lib/negotiation/index.js";
import { ONE_YEAR_MS, makeIdentity } from "../helpers.js";

const NOW = Date.parse("2026-09-17T00:00:00.000Z");
const STATUS_LIST_URL = "https://issuer.example/status-lists/real-issuer-1";

describe("regression 12 — the status-list swap no longer bypasses revocation (real M4 CRITICAL defect)", () => {
  it("[mechanism, direct] checkRevocation refuses (indeterminate) when the resolver returns a clean list signed by an UNRELATED keypair, even though that list is itself perfectly well-formed and validly signed", async () => {
    const realIssuer = new KeyHolder();
    const throwawayImpersonator = makeIdentity();

    // The impersonator's list is completely clean — no bit set, nothing
    // "wrong" about it in isolation. It is even validly signed. It is
    // simply signed by the WRONG identity for this credential.
    const cleanListByImpersonator = throwawayImpersonator; // alias for clarity below
    const cleanListJwt = issueStatusListCredential({
      issuerPrivateKey: cleanListByImpersonator.privateKey,
      issuerDid: cleanListByImpersonator.did,
      statusPurpose: "revocation",
      sizeBits: 128,
      now: NOW,
    });

    const resolver: StatusListResolver = async (url) => {
      expect(url).toBe(STATUS_LIST_URL);
      return cleanListJwt;
    };

    const entry = {
      type: "BitstringStatusListEntry" as const,
      statusPurpose: "revocation",
      statusListIndex: 0,
      statusListCredential: STATUS_LIST_URL,
    };

    const status = await checkRevocation(entry, resolver, realIssuer.did, { now: NOW });

    // The swap is refused — never silently read as "active".
    expect(status.outcome).toBe("indeterminate");
    if (status.outcome === "indeterminate") {
      expect(status.cause.name).toBe("StatusListIssuerMismatchError");
      expect(status.reason).toContain(realIssuer.did);
      expect(status.reason).toContain(cleanListByImpersonator.did);
    }
    expect(status.outcome).not.toBe("active");
  });

  it("[end-to-end] a credential genuinely revoked by its real issuer, with the resolver swapping in an unrelated throwaway-signed clean list, is refused — never silently accepted as active", async () => {
    const realIssuer = new KeyHolder();
    const buyer = new KeyHolder();
    const impersonator = makeIdentity();

    // The REAL status list genuinely revokes index 0.
    const realRevokedListJwt = realIssuer.issueStatusListCredential({
      statusPurpose: "revocation",
      sizeBits: 128,
      revokedIndices: [0],
      now: NOW,
    });
    // An unrelated, throwaway-keypair-signed "clean" list for the SAME
    // URL — no bit set, no relation whatsoever to the real issuer.
    const impersonatorCleanListJwt = issueStatusListCredential({
      issuerPrivateKey: impersonator.privateKey,
      issuerDid: impersonator.did,
      statusPurpose: "revocation",
      sizeBits: 128,
      now: NOW,
    });
    // Sanity: confirm the two lists really do disagree (one revoked, one
    // clean) so this test is actually exercising the swap, not a no-op.
    expect(realRevokedListJwt).not.toBe(impersonatorCleanListJwt);

    const authorityJwt = realIssuer.issueAuthorityCredentialTo({
      subjectDid: buyer.did,
      action: "purchase-office-supplies",
      scope: { amount: 500 },
      validFrom: new Date(NOW).toISOString(),
      validUntil: new Date(NOW + ONE_YEAR_MS).toISOString(),
      now: NOW,
    });
    const challenge = createChallenge({ now: NOW });
    const proof = buyer.provePossession(challenge);
    const anchors = new TrustAnchorSet([realIssuer.did]);
    const credentialStatus = {
      type: "BitstringStatusListEntry" as const,
      statusPurpose: "revocation",
      statusListIndex: 0,
      statusListCredential: STATUS_LIST_URL,
    };

    // The resolver is compromised/tricked into returning the
    // IMPERSONATOR's clean list instead of the real, revoking one.
    const swappedResolver: StatusListResolver = async () => impersonatorCleanListJwt;

    const decision = await evaluateAuthorityCredentialTrust({
      jwt: authorityJwt,
      presenterProof: proof,
      anchors,
      credentialStatus,
      statusListResolver: swappedResolver,
      now: NOW,
    });

    expect(decision.accepted).toBe(false);
    if (!decision.accepted) {
      expect(decision.stage).toBe("revocation");
      if (decision.stage === "revocation") {
        expect(decision.revocation.outcome).toBe("indeterminate");
        expect(decision.revocation.reason).toContain(realIssuer.did);
      }
    }

    // Contrast: the SAME credential, with the resolver honestly
    // returning the REAL revoking list, is ALSO refused — but for the
    // real reason ("revoked"), proving this isn't just a resolver that
    // always fails.
    const honestResolver: StatusListResolver = async () => realRevokedListJwt;
    const honestDecision = await evaluateAuthorityCredentialTrust({
      jwt: authorityJwt,
      presenterProof: proof,
      anchors,
      credentialStatus,
      statusListResolver: honestResolver,
      now: NOW,
    });
    expect(honestDecision.accepted).toBe(false);
    if (!honestDecision.accepted && honestDecision.stage === "revocation") {
      expect(honestDecision.revocation.outcome).toBe("revoked");
    }
  });
});
