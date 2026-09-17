/**
 * PART 3 EXPLORATORY — idea 7: "integer overflow or precision loss in a
 * scope amount (Number.MAX_SAFE_INTEGER, 1e308, -0)".
 *
 * Most of this held (JS's IEEE-754 doubles compare correctly even at
 * extreme magnitudes, and `-0` behaves as plain zero with no special
 * bypass). ONE genuine gap was found here — the policy engine's scope
 * arithmetic enforced only an UPPER ceiling and never a lower bound, so
 * a NEGATIVE requested amount (e.g. `amount: -500000` against a
 * credential granting `maxAmount: 500`) was PERMITTED, identically to a
 * small in-range positive request.
 *
 * That finding was originally recorded here, in this exact file, as
 * `[FINDING — flagged, not fixed]`, deliberately asserting the CURRENT
 * (buggy) permissive behavior per the M7 brief's "if you find a real
 * defect, STOP and report it — do not fix library code" instruction for
 * exploratory work. It has SINCE been reviewed, confirmed as a genuine
 * defect (the same shape as the M5 review's own FINDING 3/FINDING 4 —
 * a bound that exists but does not constrain what a caller can actually
 * request), and fixed in `lib/policy/engine.ts` (see that file's own
 * comment, and ADR 0004's "Amendment — M7 exploratory attack suite
 * finding"). The test below that used to assert the bug now asserts the
 * fix — its provenance (how this was found, and that it WAS a real,
 * confirmed defect) is kept in this comment and in the test's own name,
 * rather than deleted, per the M7 brief's instruction not to erase the
 * history of what the exploratory suite discovered.
 *
 * This file also carries the additional coverage written when the fix
 * landed: every field a bounded numeric scope value can be bounded by
 * (the credential's own scope, a policy `maxScope` ceiling, a triggered
 * history-narrow rule), every extreme value named in the fix's own
 * brief (`Number.MIN_SAFE_INTEGER`, `-1e308`, `-Infinity`, `-NaN`), a
 * mixed valid+negative request, and a negative value arriving through a
 * non-throwing getter (must still refuse cleanly, never crash).
 */
import { describe, expect, it } from "vitest";
import { createChallenge, encodeDidKey, generateKeyPair, provePossession, type Did, type ProofOfPossession } from "../../../lib/identity/index.js";
import { issueAuthorityCredential, issueHistoryAttestation, type AuthorityCredential } from "../../../lib/credentials/index.js";
import { TrustAnchorSet } from "../../../lib/trust/anchors.js";
import { issueStatusListCredential } from "../../../lib/trust/status-list.js";
import { evaluateAuthorityCredentialTrust, evaluateHistoryAttestationTrust, type TrustDecision } from "../../../lib/trust/index.js";
import { evaluatePolicyRequest, type PolicyDecision, type PolicyRequest } from "../../../lib/policy/index.js";
import { ACTION_SCOPE_RULE_KIND, HISTORY_NARROW_RULE_KIND, type Policy } from "../../../lib/policy/policy-types.js";
import { buildFourBeatFixture, GRANTED_MAX_AMOUNT } from "../../../lib/negotiation/index.js";
import type { Presentation, NegotiationRequest } from "../../../lib/negotiation/index.js";

const ACTION = "purchase-office-supplies";

describe("exploratory 7 — extreme/edge numeric scope values", () => {
  it("HELD: Number.MAX_SAFE_INTEGER as a requested amount is correctly refused as over-scope (no precision-loss bypass)", async () => {
    const fixture = buildFourBeatFixture();
    const challenge = fixture.supplier.issueChallenge();
    const decision = await fixture.supplier.evaluatePresentation(
      challenge,
      { proof: fixture.buyer.provePossession(challenge), credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
      { action: ACTION, scope: { amount: Number.MAX_SAFE_INTEGER } },
    );
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("over-scope");
    }
  });

  it("HELD: 1e308 (a huge but still finite double, close to Number.MAX_VALUE) is correctly refused as over-scope, not mistaken for Infinity or NaN", async () => {
    const fixture = buildFourBeatFixture();
    expect(Number.isFinite(1e308)).toBe(true);
    const challenge = fixture.supplier.issueChallenge();
    const decision = await fixture.supplier.evaluatePresentation(
      challenge,
      { proof: fixture.buyer.provePossession(challenge), credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
      { action: ACTION, scope: { amount: 1e308 } },
    );
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("over-scope");
    }
  });

  it("DECIDED: -0 behaves as plain zero — within scope, PERMITTED, no special bypass or crash (Number.isFinite(-0) is true, -0 < 0 is false, -0 <= any positive ceiling)", async () => {
    const fixture = buildFourBeatFixture();
    const challenge = fixture.supplier.issueChallenge();
    const decision = await fixture.supplier.evaluatePresentation(
      challenge,
      { proof: fixture.buyer.provePossession(challenge), credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
      { action: ACTION, scope: { amount: -0 } },
    );
    // Deliberate, not merely incidental (see engine.ts's own comment on
    // the negative-value guard, added alongside this fix): `-0` and `0`
    // are the same real-world magnitude, so treating `-0` as refused
    // while `0` is permitted would itself be the kind of sign-only
    // technicality the fix exists to eliminate, not add.
    expect(decision.permitted).toBe(true);
  });

  it("DECIDED: a requested amount of exactly 0 is PERMITTED — a zero-usage request is harmless, and the negative-value fix below has no mandate to refuse it", async () => {
    const fixture = buildFourBeatFixture();
    const challenge = fixture.supplier.issueChallenge();
    const decision = await fixture.supplier.evaluatePresentation(
      challenge,
      { proof: fixture.buyer.provePossession(challenge), credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
      { action: ACTION, scope: { amount: 0 } },
    );
    expect(decision.permitted).toBe(true);
  });

  /**
   * ============================================================
   * FIXED FINDING (Part 3) — originally NOT a hypothetical: discovered
   * by direct code reading of `lib/policy/engine.ts` and
   * `permitted-scope.ts`, then confirmed empirically, exactly as this
   * comment historically recorded:
   *
   * The policy engine's scope-bound arithmetic (`computeFieldBound`,
   * `Math.min` across every source that names a bound, then
   * `requestedValue > bound.value` in `engine.ts`) enforced ONLY an
   * upper ceiling. There was no lower bound (e.g. "amount must be >= 0")
   * anywhere in `lib/policy` or `lib/credentials`'s scope model, so a
   * NEGATIVE numeric scope value was treated exactly like any other
   * in-range value: `-500000 > 500` is `false`, so it was PERMITTED,
   * identically to a small positive request.
   *
   * This WAS exploitable in exactly the way the original comment
   * flagged: a downstream consumer of a permitted "amount: -500000"
   * (e.g. a refund system where a negative purchase amount means
   * something very different from "no purchase") would have inherited
   * an authorization the credential's own `maxAmount: 500` ceiling never
   * intended to grant — "authority to spend up to 500" silently also
   * conferring "authority to move 500,000 in the other direction".
   *
   * REVIEWED AND FIXED (this milestone, after the finding was reported):
   * `lib/policy/engine.ts` now refuses any negative requested value for
   * any bounded numeric field, with a NEW, distinct `refusalKind` —
   * `"negative-scope-value"` — rather than folding it into `"over-scope"`
   * (which would misdescribe `-500000` against a ceiling of `500` as
   * "too much" rather than "the wrong sign entirely"). See ADR 0004's
   * "Amendment — M7 exploratory attack suite finding" for the full
   * reasoning, including why this is a deliberately narrow fix and not
   * a general lower-bound/signed-range policy language.
   * ============================================================
   */
  it("[FIXED — was flagged, not fixed] a NEGATIVE requested amount is now REFUSED with the distinct refusalKind \"negative-scope-value\", not permitted and not folded into \"over-scope\"", async () => {
    const fixture = buildFourBeatFixture();
    const challenge = fixture.supplier.issueChallenge();
    const decision = await fixture.supplier.evaluatePresentation(
      challenge,
      { proof: fixture.buyer.provePossession(challenge), credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
      { action: ACTION, scope: { amount: -GRANTED_MAX_AMOUNT * 1000 } }, // e.g. amount: -500000
    );
    // FIXED behavior: refused, distinctly, never permitted.
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("negative-scope-value");
      expect(decision.explanation.refusalKind).not.toBe("over-scope");
      expect(decision.explanation.field.path).toBe("scope.amount");
      expect(decision.explanation.field.requested).toBe(-GRANTED_MAX_AMOUNT * 1000);
      expect(decision.explanation.field.permitted).toBe(GRANTED_MAX_AMOUNT);
    }
  });

  it("Number.MIN_SAFE_INTEGER as a requested amount is refused as negative-scope-value (extreme-magnitude negative, still just \"negative\")", async () => {
    const fixture = buildFourBeatFixture();
    const challenge = fixture.supplier.issueChallenge();
    const decision = await fixture.supplier.evaluatePresentation(
      challenge,
      { proof: fixture.buyer.provePossession(challenge), credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
      { action: ACTION, scope: { amount: Number.MIN_SAFE_INTEGER } },
    );
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("negative-scope-value");
    }
  });

  it("-1e308 (a huge-magnitude but still finite negative double) is refused as negative-scope-value, not over-scope", async () => {
    const fixture = buildFourBeatFixture();
    expect(Number.isFinite(-1e308)).toBe(true);
    const challenge = fixture.supplier.issueChallenge();
    const decision = await fixture.supplier.evaluatePresentation(
      challenge,
      { proof: fixture.buyer.provePossession(challenge), credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
      { action: ACTION, scope: { amount: -1e308 } },
    );
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("negative-scope-value");
    }
  });

  it("DECIDED: -Infinity is refused as over-scope (the existing non-finite gate), NOT negative-scope-value — non-finite is checked first and wins, since a value that cannot be measured at all is a different, pre-existing failure mode from a value that can be measured and is on the wrong side of zero", async () => {
    const fixture = buildFourBeatFixture();
    expect(Number.isFinite(-Infinity)).toBe(false);
    const challenge = fixture.supplier.issueChallenge();
    const decision = await fixture.supplier.evaluatePresentation(
      challenge,
      { proof: fixture.buyer.provePossession(challenge), credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
      { action: ACTION, scope: { amount: -Infinity } },
    );
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("over-scope");
      expect(decision.explanation.refusalKind).not.toBe("negative-scope-value");
    }
  });

  it("DECIDED: -NaN (identical to NaN — unary minus does not change NaN's comparability) is refused as over-scope, NOT negative-scope-value, since Number.isFinite(-NaN) is false and the non-finite gate runs first", async () => {
    const fixture = buildFourBeatFixture();
    // eslint-disable-next-line no-compare-neg-zero -- deliberately testing -NaN, not -0
    expect(Number.isNaN(-NaN)).toBe(true);
    expect(Number.isFinite(-NaN)).toBe(false);
    const challenge = fixture.supplier.issueChallenge();
    const decision = await fixture.supplier.evaluatePresentation(
      challenge,
      { proof: fixture.buyer.provePossession(challenge), credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
      { action: ACTION, scope: { amount: -NaN } },
    );
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("over-scope");
      expect(decision.explanation.refusalKind).not.toBe("negative-scope-value");
    }
  });

  it("a mix of one valid positive field and one negative field in the SAME request is refused (negative-scope-value), regardless of the other field being fine", async () => {
    // Both fields bounded by BOTH the credential's own scope AND the
    // policy's maxScope, so this is independent of which single source
    // supplies the bound (that is covered by the dedicated tests below)
    // — this test is purely about a request naming more than one
    // bounded field, one negative and one not.
    const issuer = makeRawIdentity();
    const subject = makeRawIdentity();
    const anchors = new TrustAnchorSet([issuer.did]);
    const now = 0;

    const authorityJwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      action: "purchase",
      scope: { amount: 500, itemCount: 10 },
      validUntil: "2099-01-01T00:00:00Z",
      now,
    });
    const authority = await acceptedAuthority(authorityJwt, issuer, subject, anchors, now);

    const policy: Policy = {
      id: "mixed-fields-policy",
      version: "1.0.0",
      revocationHandling: { requireChecked: true },
      rules: [{ kind: ACTION_SCOPE_RULE_KIND, id: "R-mixed", description: "two bounded fields", action: "purchase", maxScope: { amount: 500, itemCount: 10 } }],
    };

    const decision = evaluatePolicyRequest({
      policy,
      request: { action: "purchase", scope: { amount: 200, itemCount: -3 } }, // amount valid, itemCount negative
      authority,
      history: [],
    });

    expect(decision.permitted).toBe(false);
    if (decision.permitted) throw new Error("expected refusal");
    expect(decision.explanation.refusalKind).toBe("negative-scope-value");
    expect(decision.explanation.field.path).toBe("scope.itemCount");
    expect(decision.explanation.field.requested).toBe(-3);
  });

  it("a negative value on a field bounded ONLY by the credential's own scope (not named by the policy's maxScope at all) is refused as negative-scope-value", async () => {
    const issuer = makeRawIdentity();
    const subject = makeRawIdentity();
    const anchors = new TrustAnchorSet([issuer.did]);
    const now = 0;

    // The credential grants TWO numeric scope dimensions; the policy's
    // own action-scope rule only ever mentions one of them (`amount`) —
    // `itemCount` is bounded ONLY because the credential itself names a
    // numeric value for it (per ADR 0004 decision 6 / FINDING 4: the
    // engine checks the UNION of every source's bounded fields, not
    // merely what the policy's maxScope names).
    const authorityJwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      action: "purchase",
      scope: { amount: 500, itemCount: 10 },
      validUntil: "2099-01-01T00:00:00Z",
      now,
    });
    const authority = await acceptedAuthority(authorityJwt, issuer, subject, anchors, now);

    const policy: Policy = {
      id: "credential-only-bound-policy",
      version: "1.0.0",
      revocationHandling: { requireChecked: true },
      rules: [{ kind: ACTION_SCOPE_RULE_KIND, id: "R-credential-only", description: "policy only ever names amount", action: "purchase", maxScope: { amount: 500 } }],
    };

    const decision = evaluatePolicyRequest({
      policy,
      request: { action: "purchase", scope: { amount: 100, itemCount: -5 } },
      authority,
      history: [],
    });

    expect(decision.permitted).toBe(false);
    if (decision.permitted) throw new Error("expected refusal");
    expect(decision.explanation.refusalKind).toBe("negative-scope-value");
    expect(decision.explanation.field.path).toBe("scope.itemCount");
    expect(decision.explanation.field.requested).toBe(-5);
    expect(decision.explanation.field.permitted).toBe(10); // the credential's own itemCount value, the only source that bounds it
  });

  it("a negative value on a field bounded ONLY by a triggered history-narrow rule (named by neither the credential's own scope nor the policy's maxScope) is refused as negative-scope-value", async () => {
    const issuer = makeRawIdentity();
    const subject = makeRawIdentity();
    const anchors = new TrustAnchorSet([issuer.did]);
    const now = 0;

    // The credential and the policy's action-scope rule only ever name
    // `amount`. `riskAdjustment` is a scope dimension that exists ONLY
    // because a `history-narrow` rule names it as its `scopeField` —
    // exactly the "a policy author can introduce a brand-new dimension
    // purely for history-based narrowing" case ADR 0004 decision 6
    // documents. It only becomes a BOUNDED field once the rule actually
    // triggers.
    const authorityJwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      action: "purchase",
      scope: { amount: 500 },
      validUntil: "2099-01-01T00:00:00Z",
      now,
    });
    const authority = await acceptedAuthority(authorityJwt, issuer, subject, anchors, now);

    const policy: Policy = {
      id: "history-only-bound-policy",
      version: "1.0.0",
      revocationHandling: { requireChecked: true },
      rules: [
        { kind: ACTION_SCOPE_RULE_KIND, id: "R-base", description: "base ceiling on amount only", action: "purchase", maxScope: { amount: 500 } },
        {
          kind: HISTORY_NARROW_RULE_KIND,
          id: "R-risk-narrow",
          description: "an observed risk score narrows riskAdjustment (a field named nowhere else) to 50",
          action: "purchase",
          observationType: "risk-observed",
          metric: "riskScore",
          operator: "gte",
          threshold: 1,
          scopeField: "riskAdjustment",
          narrowedMax: 50,
        },
      ],
    };

    const historyJwt = issueHistoryAttestation({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      observationType: "risk-observed",
      metrics: { riskScore: 5 }, // >= threshold 1, so the rule triggers
      now,
    });
    const history = await evaluateHistoryAttestationTrust({ jwt: historyJwt, presenterProof: proofOfPossessionFor(subject, now), now });
    expect(history.accepted).toBe(true);

    const decision = evaluatePolicyRequest({
      policy,
      request: { action: "purchase", scope: { amount: 100, riskAdjustment: -10 } },
      authority,
      history: [history],
    });

    expect(decision.permitted).toBe(false);
    if (decision.permitted) throw new Error("expected refusal");
    // Distinct from BOTH "history-constraint" (what an over-magnitude
    // request against this same triggered rule would produce) and
    // "over-scope" — negative wins as its own, more specific kind
    // regardless of which source supplied the ceiling.
    expect(decision.explanation.refusalKind).toBe("negative-scope-value");
    expect(decision.explanation.refusalKind).not.toBe("history-constraint");
    expect(decision.explanation.field.path).toBe("scope.riskAdjustment");
    expect(decision.explanation.field.requested).toBe(-10);
    expect(decision.explanation.field.permitted).toBe(50); // the triggered rule's narrowedMax, the only source that bounds this field
  });

  it("a negative value arriving via a non-throwing getter on request.scope still refuses cleanly (negative-scope-value), never throws — the getter itself is not the hazard, the value it returns is", async () => {
    const issuer = makeRawIdentity();
    const subject = makeRawIdentity();
    const anchors = new TrustAnchorSet([issuer.did]);
    const now = 0;

    const authorityJwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      action: "purchase",
      scope: { amount: 500 },
      validUntil: "2099-01-01T00:00:00Z",
      now,
    });
    const authority = await acceptedAuthority(authorityJwt, issuer, subject, anchors, now);

    const policy: Policy = {
      id: "getter-negative-policy",
      version: "1.0.0",
      revocationHandling: { requireChecked: true },
      rules: [{ kind: ACTION_SCOPE_RULE_KIND, id: "R-getter", description: "getter-sourced negative value", action: "purchase", maxScope: { amount: 500 } }],
    };

    const scope: Record<string, unknown> = {};
    let reads = 0;
    Object.defineProperty(scope, "amount", {
      enumerable: true,
      get() {
        reads += 1;
        return -250000; // a non-throwing getter that simply returns a negative number
      },
    });

    let decision: PolicyDecision | undefined;
    expect(() => {
      decision = evaluatePolicyRequest({ policy, request: { action: "purchase", scope } as unknown as PolicyRequest, authority, history: [] });
    }).not.toThrow();
    if (decision === undefined) throw new Error("unreachable");

    expect(decision.permitted).toBe(false);
    if (decision.permitted) throw new Error("expected refusal");
    expect(decision.explanation.refusalKind).toBe("negative-scope-value");
    expect(decision.explanation.field.path).toBe("scope.amount");
    expect(decision.explanation.field.requested).toBe(-250000);
    expect(reads).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------
// Small local helpers, self-contained (mirrors the pattern already
// established in lib/policy/history-constraints.test.ts and
// tests/attacks/regressions/14-throwing-scope-accessor.test.ts) so the
// additional fixed-finding coverage above doesn't need to route every
// scenario through the full negotiation/Supplier protocol just to
// exercise `evaluatePolicyRequest` directly with a custom credential or
// history shape.
// ---------------------------------------------------------------------
interface RawIdentity {
  readonly publicKey: Uint8Array;
  readonly privateKey: Uint8Array;
  readonly did: Did;
}

function makeRawIdentity(): RawIdentity {
  const { publicKey, privateKey } = generateKeyPair();
  return { publicKey, privateKey, did: encodeDidKey(publicKey) };
}

function proofOfPossessionFor(identity: RawIdentity, now = 0): ProofOfPossession {
  const challenge = createChallenge({ now, ttlMs: 60_000 });
  return provePossession(identity.privateKey, identity.did, challenge);
}

/** Run a freshly-issued authority JWT through the REAL M3+M4
 *  verification chain (never a fabricated/cast `TrustDecision`), with a
 *  real, clean (nothing revoked) status list, so every custom-fixture
 *  test above evaluates `evaluatePolicyRequest` against a genuinely
 *  accepted decision. */
async function acceptedAuthority(
  authorityJwt: string,
  issuer: RawIdentity,
  subject: RawIdentity,
  anchors: TrustAnchorSet,
  now: number,
): Promise<TrustDecision<AuthorityCredential> & { readonly accepted: true }> {
  const statusListJwt = issueStatusListCredential({ issuerPrivateKey: issuer.privateKey, issuerDid: issuer.did, statusPurpose: "revocation", sizeBits: 128, now });
  const authority = await evaluateAuthorityCredentialTrust({
    jwt: authorityJwt,
    presenterProof: proofOfPossessionFor(subject, now),
    anchors,
    credentialStatus: { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: 0, statusListCredential: "https://issuer.example/status/edge-cases" },
    statusListResolver: async () => statusListJwt,
    now,
  });
  if (!authority.accepted) throw new Error("fixture's own credential must be genuinely accepted for this test to be meaningful");
  return authority;
}
