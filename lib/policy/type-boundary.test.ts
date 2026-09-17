/**
 * TIGHTEN_NEVER_LOOSEN — compile-time AND runtime proof that a history
 * attestation can never widen a permitted envelope, mirroring
 * `lib/credentials/type-boundary.test.ts` (ADR 0002) and
 * `lib/trust/type-boundary.test.ts` (the `Vouch` identity/authority
 * split) for this module's own version of the same discipline.
 *
 * ## Why both a compile-time AND a runtime proof
 *
 * `npm run typecheck` is the actual assertion for the `@ts-expect-error`
 * below — if `computeAuthorityEnvelope`'s parameter type is ever
 * accidentally loosened to accept a `HistoryTrustDecision` (directly, or
 * via some future shared supertype), this stops compiling and `tsc`
 * reports "Unused '@ts-expect-error' directive", failing the typecheck
 * gate. But a real policy's claims arrive as JSON (from a JWT payload, a
 * config file, a network response) — nothing stops a caller who bypasses
 * TypeScript entirely (a JS caller, or a cast) from trying to smuggle a
 * generous "grant" through the DATA this module actually operates on: a
 * `HistoryNarrowRule.narrowedMax` set absurdly high. The runtime tests
 * below prove that even in that case, the arithmetic itself
 * (`permitted-scope.ts`'s `Math.min`) cannot produce an envelope wider
 * than the authority credential's own scope — there is no value a
 * history-authored `narrowedMax` could take that increases what's
 * permitted, only ones that leave it unchanged or shrink it further.
 */
import { describe, expect, it } from "vitest";
import { createChallenge, encodeDidKey, generateKeyPair, provePossession, type Did, type ProofOfPossession } from "../identity/index.js";
import { issueAuthorityCredential, issueHistoryAttestation, type AuthorityCredential } from "../credentials/index.js";
import { TrustAnchorSet } from "../trust/anchors.js";
import { evaluateAuthorityCredentialTrust, evaluateHistoryAttestationTrust, type HistoryTrustDecision, type TrustDecision } from "../trust/index.js";
import { computeAuthorityEnvelope } from "./envelope.js";
import { computeHistoryConstraints } from "./history-constraints.js";
import { computeFieldBound } from "./permitted-scope.js";
import { evaluatePolicyRequest } from "./engine.js";
import { ACTION_SCOPE_RULE_KIND, HISTORY_NARROW_RULE_KIND, type Policy } from "./policy-types.js";

// ---------------------------------------------------------------------
// Compile-time proof
// ---------------------------------------------------------------------

function requiresAcceptedAuthorityDecision(decision: TrustDecision<AuthorityCredential> & { readonly accepted: true }): void {
  void computeAuthorityEnvelope(decision);
}

function proof_historyDecisionCannotSatisfyAuthorityEnvelopeInput(historyDecision: HistoryTrustDecision & { readonly accepted: true }): void {
  // @ts-expect-error — `HistoryTrustDecision`'s accepted variant carries
  // `credentialVerification: VerificationSuccess<HistoryAttestation>`,
  // which cannot structurally satisfy `computeAuthorityEnvelope`'s
  // required `VerificationSuccess<AuthorityCredential>` (ADR 0002: the
  // two credential kinds share no common shape a caller could smuggle
  // through). An envelope can only ever originate from a verified
  // AuthorityCredential — never from history, no matter how it's cast.
  computeAuthorityEnvelope(historyDecision);
}

void requiresAcceptedAuthorityDecision;
void proof_historyDecisionCannotSatisfyAuthorityEnvelopeInput;

describe("type-level: a HistoryTrustDecision can never satisfy computeAuthorityEnvelope's input", () => {
  it("is proven by the @ts-expect-error directive above compiling (i.e. `npm run typecheck` passing)", () => {
    // Nothing to execute at runtime — the assertion IS the typecheck.
    expect(typeof requiresAcceptedAuthorityDecision).toBe("function");
  });
});

// ---------------------------------------------------------------------
// Runtime proof
// ---------------------------------------------------------------------

interface Identity {
  readonly publicKey: Uint8Array;
  readonly privateKey: Uint8Array;
  readonly did: Did;
}

function makeIdentity(): Identity {
  const { publicKey, privateKey } = generateKeyPair();
  return { publicKey, privateKey, did: encodeDidKey(publicKey) };
}

function proofOfPossessionFor(identity: Identity, now = 0): ProofOfPossession {
  const challenge = createChallenge({ now, ttlMs: 60_000 });
  return provePossession(identity.privateKey, identity.did, challenge);
}

describe("runtime: history cannot widen an envelope", () => {
  it("computeFieldBound never returns a value larger than the authority credential's own scope, even when a HistoryNarrowRule's narrowedMax is absurdly high", async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const anchors = new TrustAnchorSet([issuer.did]);

    const jwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      action: "purchase",
      scope: { maxAmount: 500 },
      validUntil: "2099-01-01T00:00:00Z",
      now: 0,
    });
    const authorityDecision = await evaluateAuthorityCredentialTrust({
      jwt,
      presenterProof: proofOfPossessionFor(subject, 0),
      anchors,
      now: 0,
    });
    expect(authorityDecision.accepted).toBe(true);
    if (!authorityDecision.accepted) throw new Error("expected acceptance");
    const envelope = computeAuthorityEnvelope(authorityDecision);

    const historyJwt = issueHistoryAttestation({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      observationType: "transactions-completed",
      metrics: { count: 1_000_000 }, // a maximally glowing history
      now: 0,
    });
    const historyDecision = await evaluateHistoryAttestationTrust({
      jwt: historyJwt,
      presenterProof: proofOfPossessionFor(subject, 0),
      now: 0,
    });
    expect(historyDecision.accepted).toBe(true);

    // A rule that tries to "narrow" maxAmount to 10,000,000 -- an
    // absurdly generous value, larger than the credential's own 500.
    const generousRule = {
      kind: HISTORY_NARROW_RULE_KIND,
      id: "R-generous",
      description: "a maximally generous (mis-authored) history rule",
      action: "purchase",
      observationType: "transactions-completed",
      metric: "count",
      operator: "gte" as const,
      threshold: 1,
      scopeField: "maxAmount",
      narrowedMax: 10_000_000,
    };

    const triggered = computeHistoryConstraints([generousRule], "purchase", [historyDecision]);
    expect(triggered).toHaveLength(1); // the rule DID fire...

    const actionRule = { kind: ACTION_SCOPE_RULE_KIND, id: "R-purchase", description: "purchase ceiling", action: "purchase", maxScope: {} } as const;
    const bound = computeFieldBound("maxAmount", envelope, actionRule, triggered);

    // ...but it had ZERO effect: the bound is still the credential's own
    // 500, because Math.min(500, 10_000_000) === 500. History narrowed
    // nothing here because there was nothing narrower to apply — it
    // certainly did not WIDEN the 500 ceiling to 10,000,000.
    expect(bound).not.toBeNull();
    expect(bound?.value).toBe(500);
    expect(bound?.source.kind).toBe("authority-credential");
  });

  it("end to end: a request for more than the credential's own scope is refused even with a glowing, favourable history attached, and even with no authority credential at all", async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const anchors = new TrustAnchorSet([issuer.did]);

    const authorityJwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      action: "purchase",
      scope: { maxAmount: 500 },
      validUntil: "2099-01-01T00:00:00Z",
      now: 0,
    });
    const authorityDecision = await evaluateAuthorityCredentialTrust({ jwt: authorityJwt, presenterProof: proofOfPossessionFor(subject, 0), anchors, now: 0 });

    const historyJwt = issueHistoryAttestation({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      observationType: "transactions-completed",
      metrics: { disputes: 0, count: 500 },
      now: 0,
    });
    const historyDecision = await evaluateHistoryAttestationTrust({ jwt: historyJwt, presenterProof: proofOfPossessionFor(subject, 0), now: 0 });

    const policy: Policy = {
      id: "policy-widen-proof",
      version: "1.0.0",
      revocationHandling: { requireChecked: false, acknowledgedBy: "test-fixture", reason: "no status list wired up in this fixture" },
      rules: [
        { kind: ACTION_SCOPE_RULE_KIND, id: "R-purchase", description: "purchase ceiling", action: "purchase", maxScope: { maxAmount: 500 } },
        {
          kind: HISTORY_NARROW_RULE_KIND,
          id: "R-generous",
          description: "a maximally generous (mis-authored) history rule",
          action: "purchase",
          observationType: "transactions-completed",
          metric: "count",
          operator: "gte",
          threshold: 1,
          scopeField: "maxAmount",
          narrowedMax: 10_000_000,
        },
      ],
    };

    // With authority present: history's generosity changes nothing —
    // a request for 5,000 (over the credential's own 500) is refused.
    const withAuthority = evaluatePolicyRequest({
      policy,
      request: { action: "purchase", scope: { maxAmount: 5_000 } },
      authority: authorityDecision,
      history: [historyDecision],
    });
    expect(withAuthority.permitted).toBe(false);
    if (withAuthority.permitted) throw new Error("expected refusal");
    expect(withAuthority.explanation.refusalKind).toBe("over-scope");

    // Without authority at all: the same glowing history, alone,
    // permits nothing.
    const withoutAuthority = evaluatePolicyRequest({
      policy,
      request: { action: "purchase", scope: { maxAmount: 1 } },
      authority: null,
      history: [historyDecision],
    });
    expect(withoutAuthority.permitted).toBe(false);
    if (withoutAuthority.permitted) throw new Error("expected refusal");
    expect(withoutAuthority.explanation.refusalKind).toBe("no-authority-credential");
  });
});
