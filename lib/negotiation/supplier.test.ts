/**
 * `Supplier` protocol-level guarantees that `scenario.test.ts`'s
 * beat-by-beat assertions don't already cover:
 *
 *   - a presentation answering a DIFFERENT challenge (a different
 *     session, or a captured/replayed one) is refused, and refused at
 *     the session-binding gate specifically, not the signature gate;
 *   - the spoofed-identity beat is refused WITHOUT the credential ever
 *     being examined — proved structurally (an injected resolver spy is
 *     never invoked), not just by the decision's own labelled stage;
 *   - the Supplier's decision is identical for an honest and a hostile
 *     counterparty EXCEPT for what each can actually prove;
 *   - nothing throws an unhandled error for a battery of malformed/
 *     hostile presentations and requests.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { createChallenge, encodeDidKey, generateKeyPair, provePossession, type Did } from "../identity/index.js";
import { issueAuthorityCredential } from "../credentials/index.js";
import { evaluateAuthorityCredentialTrust, issueVouch, TrustAnchorSet, type CredentialStatusEntry, type StatusListResolver } from "../trust/index.js";
import { KeyHolder } from "./agent.js";
import { buildFourBeatFixture } from "./scenario.js";
import { MAX_VOUCHES_PER_PRESENTATION, sanitizeScope, Supplier } from "./supplier.js";
import type { NegotiationRequest, Presentation } from "./messages.js";

const NOW = Date.parse("2026-09-17T00:00:00.000Z");
const ACTION = "purchase-office-supplies";

describe("session binding — a presentation must answer THIS session's own challenge", () => {
  it("refuses a presentation whose proof answers a different (e.g. earlier) challenge", async () => {
    const fixture = buildFourBeatFixture(NOW);

    const earlierChallenge = fixture.supplier.issueChallenge();
    const proofForEarlierChallenge = fixture.buyer.provePossession(earlierChallenge);

    // A NEW session issues its own, different challenge...
    const currentChallenge = fixture.supplier.issueChallenge();
    // ...but the presentation carries the proof for the EARLIER one —
    // exactly what a captured-and-replayed presentation looks like.
    const replayedPresentation: Presentation = {
      proof: proofForEarlierChallenge,
      credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
    };
    const request: NegotiationRequest = { action: ACTION, scope: { amount: 150 } };

    const decision = await fixture.supplier.evaluatePresentation(currentChallenge, replayedPresentation, request);

    expect(decision.stage).toBe("proof-of-possession");
    if (decision.stage === "proof-of-possession") {
      expect(decision.permitted).toBe(false);
      expect(decision.rule.ruleId).toBe("gate:session-challenge");
      // Refused for session mismatch, NOT for a bad signature — the
      // signature itself is perfectly valid over the OLD challenge.
      expect(decision.rule.ruleId).not.toBe("gate:proof-of-possession");
    }
  });

  it("the SAME proof answering the SAME (re-issued) challenge nonce IS accepted at this gate", async () => {
    // Sanity check on the mechanism itself: it is the NONCE that must
    // match, and a legitimate flow (challenge -> immediate response)
    // naturally satisfies that — this isn't accidentally refusing
    // everything.
    const fixture = buildFourBeatFixture(NOW);
    const challenge = fixture.supplier.issueChallenge();
    const proof = fixture.buyer.provePossession(challenge);
    const presentation: Presentation = {
      proof,
      credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
    };
    const decision = await fixture.supplier.evaluatePresentation(challenge, presentation, { action: ACTION, scope: { amount: 10 } });
    expect(decision.stage).toBe("policy");
  });
});

describe("Beat 3 mechanism — the credential is never examined, proved structurally", () => {
  it("never invokes the status-list resolver when proof of possession fails", async () => {
    const fixture = buildFourBeatFixture(NOW);
    const resolverSpy = vi.fn<StatusListResolver>(() => {
      throw new Error("resolver should never be called — proof of possession must fail first");
    });
    const supplier = new Supplier({ policy: fixture.policy, anchors: fixture.anchors, statusListResolver: resolverSpy, now: NOW });

    const challenge = supplier.issueChallenge();
    const spoofedProof = fixture.attacker.attemptProofOfPossessionFor(fixture.buyer.did, challenge);
    const presentation: Presentation = {
      proof: spoofedProof,
      credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
    };

    const decision = await supplier.evaluatePresentation(challenge, presentation, { action: ACTION, scope: { amount: 1 } });

    expect(decision.stage).toBe("proof-of-possession");
    expect(decision.permitted).toBe(false);
    expect(resolverSpy).not.toHaveBeenCalled();
  });

  it("refuses at proof-of-possession even when the presented credential is garbage that would ALSO fail if examined", async () => {
    // If the credential had been examined at all, a garbage JWT would
    // produce a "policy" stage decision with refusalKind
    // "credential-verification-failed" (verifyAuthorityCredential never
    // throws — it returns a structured failure). Getting
    // stage="proof-of-possession" instead proves control returned before
    // that call ever ran, regardless of what the credential contains.
    const fixture = buildFourBeatFixture(NOW);
    const challenge = fixture.supplier.issueChallenge();
    const spoofedProof = fixture.attacker.attemptProofOfPossessionFor(fixture.buyer.did, challenge);
    const presentation: Presentation = {
      proof: spoofedProof,
      credentials: { authorityJwt: "not-a-jwt-at-all" },
    };
    const decision = await fixture.supplier.evaluatePresentation(challenge, presentation, { action: ACTION, scope: { amount: 1 } });
    expect(decision.stage).toBe("proof-of-possession");
  });
});

describe("identical inputs, differing only in what can be proven", () => {
  it("the SAME credential and request produce a permit for the true holder and a proof-of-possession refusal for an impostor claiming the same DID", async () => {
    const fixture = buildFourBeatFixture(NOW);
    const request: NegotiationRequest = { action: ACTION, scope: { amount: 100 } };

    // Case A: the Buyer, honestly, over its own key.
    const honestChallenge = fixture.supplier.issueChallenge();
    const honestPresentation: Presentation = {
      proof: fixture.buyer.provePossession(honestChallenge),
      credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
    };
    const honestDecision = await fixture.supplier.evaluatePresentation(honestChallenge, honestPresentation, request);

    // Case B: the Attacker, claiming the identical DID, presenting the
    // IDENTICAL credential JWT and the IDENTICAL request — the only
    // difference anywhere in this input is which private key produced
    // the proof's signature.
    const hostileChallenge = fixture.supplier.issueChallenge();
    const hostilePresentation: Presentation = {
      proof: fixture.attacker.attemptProofOfPossessionFor(fixture.buyer.did, hostileChallenge),
      credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
    };
    const hostileDecision = await fixture.supplier.evaluatePresentation(hostileChallenge, hostilePresentation, request);

    expect(honestDecision.stage).toBe("policy");
    expect(honestDecision.permitted).toBe(true);

    expect(hostileDecision.stage).toBe("proof-of-possession");
    expect(hostileDecision.permitted).toBe(false);

    // Nothing about the credential, the policy, or the request differed
    // between the two calls — only the key behind the signature did.
  });
});

describe("every decision carries a structured explanation (no bare booleans)", () => {
  it("a proof-of-possession refusal names a rule, a field, and a narrative", async () => {
    const fixture = buildFourBeatFixture(NOW);
    const challenge = fixture.supplier.issueChallenge();
    const proof = fixture.attacker.attemptProofOfPossessionFor(fixture.buyer.did, challenge);
    const decision = await fixture.supplier.evaluatePresentation(
      challenge,
      { proof, credentials: { authorityJwt: fixture.buyerAuthorityJwt } },
      { action: ACTION, scope: { amount: 1 } },
    );
    expect(decision.stage).toBe("proof-of-possession");
    if (decision.stage === "proof-of-possession") {
      expect(decision.rule.ruleId.length).toBeGreaterThan(0);
      expect(decision.field.path.length).toBeGreaterThan(0);
      expect(decision.narrative.length).toBeGreaterThan(0);
    }
  });

  it("a policy-stage decision (permitted or refused) always has rule/field/narrative", async () => {
    const fixture = buildFourBeatFixture(NOW);
    const challenge = fixture.supplier.issueChallenge();
    const proof = fixture.buyer.provePossession(challenge);
    const decision = await fixture.supplier.evaluatePresentation(
      challenge,
      { proof, credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
      { action: ACTION, scope: { amount: 999_999 } },
    );
    expect(decision.stage).toBe("policy");
    if (decision.stage === "policy") {
      expect(decision.explanation.rule.ruleId.length).toBeGreaterThan(0);
      expect(decision.explanation.field.path.length).toBeGreaterThan(0);
      expect(decision.explanation.narrative.length).toBeGreaterThan(0);
    }
  });
});

describe("fail-closed: nothing throws for a malformed or hostile message", () => {
  function makeSupplier(): Supplier {
    const fixture = buildFourBeatFixture(NOW);
    return new Supplier({ policy: fixture.policy, anchors: fixture.anchors, statusListResolver: fixture.resolver, now: NOW });
  }

  const attacker = new KeyHolder();

  const hostileAuthorityJwts: readonly string[] = [
    "",
    "not-a-jwt",
    "a.b",
    "a.b.c.d",
    "....",
    "not base64url !!! . also not !!! . nor this !!!",
    "x".repeat(200_000), // exceeds MAX_JWS_LENGTH
  ];

  it.each(hostileAuthorityJwts)("evaluatePresentation resolves refused (never throws/rejects) for authorityJwt=%j", async (jwt) => {
    // The outcome here is fully knowable, not merely "it resolves": the
    // attacker proves possession of its OWN did honestly (proof-of-
    // possession passes), so control reaches the policy stage, where
    // every one of these garbage strings fails M3's own credential
    // verification (never throws — returns a structured failure) and is
    // refused as "credential-verification-failed". Strengthened per FIX
    // 2's audit (L4 M6 review) — a bare `.resolves.toBeDefined()` would
    // pass even if this silently started PERMITTING garbage.
    const supplier = makeSupplier();
    const challenge = supplier.issueChallenge();
    const proof = attacker.provePossession(challenge);
    await expect(
      supplier.evaluatePresentation(challenge, { proof, credentials: { authorityJwt: jwt } }, { action: ACTION, scope: { amount: 1 } }),
    ).resolves.toMatchObject({ stage: "policy", permitted: false });
  });

  it("resolves for a proof with a malformed claimed DID", async () => {
    const supplier = makeSupplier();
    const challenge = supplier.issueChallenge();
    const hostileProof = { did: "did:key:not-valid-base58" as unknown as `did:key:${string}`, challenge, signature: "00".repeat(64) };
    await expect(
      supplier.evaluatePresentation(challenge, { proof: hostileProof, credentials: { authorityJwt: "irrelevant" } }, { action: ACTION, scope: {} }),
    ).resolves.toMatchObject({ permitted: false });
  });

  it("resolves for a proof whose signature is garbage hex", async () => {
    const supplier = makeSupplier();
    const challenge = supplier.issueChallenge();
    const proof = { did: attacker.did, challenge, signature: "not-hex-at-all!!" };
    await expect(
      supplier.evaluatePresentation(challenge, { proof, credentials: { authorityJwt: "irrelevant" } }, { action: ACTION, scope: {} }),
    ).resolves.toMatchObject({ permitted: false });
  });

  it("resolves for a malformed credentialStatus (negative index, wrong purpose)", async () => {
    const fixture = buildFourBeatFixture(NOW);
    const supplier = new Supplier({ policy: fixture.policy, anchors: fixture.anchors, statusListResolver: fixture.resolver, now: NOW });
    const challenge = supplier.issueChallenge();
    const proof = fixture.buyer.provePossession(challenge);
    const hostileStatus: CredentialStatusEntry = {
      type: "BitstringStatusListEntry",
      statusPurpose: "revocation",
      statusListIndex: -1,
      statusListCredential: fixture.buyerCredentialStatus.statusListCredential,
    };
    await expect(
      supplier.evaluatePresentation(
        challenge,
        { proof, credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: hostileStatus } },
        { action: ACTION, scope: { amount: 1 } },
      ),
    ).resolves.toMatchObject({ permitted: false });
  });

  it("resolves for a resolver that rejects", async () => {
    const fixture = buildFourBeatFixture(NOW);
    const throwingResolver: StatusListResolver = () => Promise.reject(new Error("network is down"));
    const supplier = new Supplier({ policy: fixture.policy, anchors: fixture.anchors, statusListResolver: throwingResolver, now: NOW });
    const challenge = supplier.issueChallenge();
    const proof = fixture.buyer.provePossession(challenge);
    await expect(
      supplier.evaluatePresentation(
        challenge,
        { proof, credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
        { action: ACTION, scope: { amount: 1 } },
      ),
    ).resolves.toMatchObject({ permitted: false });
  });

  it("resolves refused for credentialStatus: null (would otherwise throw reading entry.statusSize)", async () => {
    // Knowable outcome, strengthened per FIX 2's audit: `credentialStatus:
    // null` sanitises to "no credentialStatus supplied", so revocation is
    // honestly reported "not-checked" — and this fixture's policy sets
    // `revocationHandling: { requireChecked: true }` (the default,
    // strict value), so this is deterministically refused under
    // "revocation-not-checked", never merely "resolves to something".
    const fixture = buildFourBeatFixture(NOW);
    const supplier = new Supplier({ policy: fixture.policy, anchors: fixture.anchors, statusListResolver: fixture.resolver, now: NOW });
    const challenge = supplier.issueChallenge();
    const proof = fixture.buyer.provePossession(challenge);
    await expect(
      supplier.evaluatePresentation(
        challenge,
        { proof, credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: null as unknown as CredentialStatusEntry } },
        { action: ACTION, scope: { amount: 1 } },
      ),
    ).resolves.toMatchObject({ stage: "policy", permitted: false, explanation: { refusalKind: "revocation-not-checked" } });
  });

  it("resolves when presentation.proof itself is null/undefined/a non-object", async () => {
    const supplier = makeSupplier();
    for (const hostileProof of [null, undefined, "just a string", 42, []] as const) {
      const challenge = supplier.issueChallenge();
      const decision = await supplier.evaluatePresentation(
        challenge,
        { proof: hostileProof as unknown as Presentation["proof"], credentials: { authorityJwt: "irrelevant" } },
        { action: ACTION, scope: {} },
      );
      expect(decision.permitted).toBe(false);
      expect(decision.stage).toBe("proof-of-possession");
    }
  });

  it("resolves when presentation.credentials itself is null/undefined/a non-object", async () => {
    const supplier = makeSupplier();
    const challenge = supplier.issueChallenge();
    const proof = attacker.provePossession(challenge);
    for (const hostileCredentials of [null, undefined, "nope", 7] as const) {
      const freshChallenge = supplier.issueChallenge();
      const freshProof = attacker.provePossession(freshChallenge);
      await expect(
        supplier.evaluatePresentation(
          freshChallenge,
          { proof: freshProof, credentials: hostileCredentials as unknown as Presentation["credentials"] },
          { action: ACTION, scope: {} },
        ),
      ).resolves.toMatchObject({ permitted: false });
    }
    void proof;
  });

  it("resolves when presentation itself, or request itself, is null/undefined", async () => {
    const supplier = makeSupplier();
    const challenge = supplier.issueChallenge();
    await expect(
      supplier.evaluatePresentation(challenge, null as unknown as Presentation, { action: ACTION, scope: {} }),
    ).resolves.toMatchObject({ permitted: false });

    const challenge2 = supplier.issueChallenge();
    const proof2 = attacker.provePossession(challenge2);
    // Knowable outcome, strengthened per FIX 2's audit: the attacker
    // proves possession of its own DID honestly, so this reaches the
    // policy stage, where `authorityJwt: "irrelevant"` deterministically
    // fails credential verification regardless of what `request` itself
    // was — refused, not merely "resolves to something".
    await expect(
      supplier.evaluatePresentation(challenge2, { proof: proof2, credentials: { authorityJwt: "irrelevant" } }, null as unknown as NegotiationRequest),
    ).resolves.toMatchObject({ stage: "policy", permitted: false });
  });

  it("refuses (never PERMITS, never throws) for request.scope: null and for a request itself missing 'action' (FIX 2, L4 M6 review)", async () => {
    // FIX 2: this test used to assert only `.resolves.toBeDefined()`,
    // with a comment claiming an empty/null scope "legitimately PERMITS"
    // because "an empty scope has no field to bound-check". That framed
    // a genuine authorization bypass as correct behaviour: `amount` IS a
    // bounded field here (the Buyer's real credential grants
    // `{ amount: GRANTED_MAX_AMOUNT }`, and the policy's own
    // `action-scope` rule ceilings it too), so a request that omits it
    // entirely must be REFUSED under FINDING 4 (M5's fix, merged from
    // `main`) — never permitted. Because the assertion only checked
    // "resolves at all", it passed identically before AND after that
    // bypass was fixed, so it never actually constrained anything that
    // mattered. This test now pins the CORRECT, specific outcome: a
    // structured refusal naming the omitted bounded field, not merely
    // "some decision came back".
    const fixture = buildFourBeatFixture(NOW);
    const supplier = new Supplier({ policy: fixture.policy, anchors: fixture.anchors, statusListResolver: fixture.resolver, now: NOW });
    const challenge = supplier.issueChallenge();
    const proof = fixture.buyer.provePossession(challenge);
    const decision = await supplier.evaluatePresentation(
      challenge,
      { proof, credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
      { action: ACTION, scope: null as unknown as Record<string, unknown> },
    );
    expect(decision.stage).toBe("policy");
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("over-scope");
      expect(decision.explanation.field.path).toBe("scope.amount");
    }

    // `{}` (no `scope` key at all, and no `action`) is likewise refused
    // — here because the sanitised action ("") can never match the
    // credential's own granted action, a DIFFERENT, equally knowable
    // refusal this test now pins by name rather than leaving unstated.
    const challenge2 = supplier.issueChallenge();
    const proof2 = fixture.buyer.provePossession(challenge2);
    const decision2 = await supplier.evaluatePresentation(
      challenge2,
      { proof: proof2, credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
      {} as unknown as NegotiationRequest,
    );
    expect(decision2.permitted).toBe(false);
    expect(decision2.stage).toBe("policy");
    if (decision2.stage === "policy" && !decision2.permitted) {
      expect(decision2.explanation.refusalKind).toBe("wrong-action");
    }
  });

  it("resolves for a resolver that throws synchronously (not even a rejected promise)", async () => {
    const fixture = buildFourBeatFixture(NOW);
    const throwingResolver: StatusListResolver = () => {
      throw new Error("thrown synchronously, not returned as a rejected promise");
    };
    const supplier = new Supplier({ policy: fixture.policy, anchors: fixture.anchors, statusListResolver: throwingResolver, now: NOW });
    const challenge = supplier.issueChallenge();
    const proof = fixture.buyer.provePossession(challenge);
    await expect(
      supplier.evaluatePresentation(
        challenge,
        { proof, credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
        { action: ACTION, scope: { amount: 1 } },
      ),
    ).resolves.toMatchObject({ permitted: false });
  });

  it("resolves PERMITTED for hostile historyJwts (garbage strings mixed with a valid one), since this fixture's policy has no history-narrow rule at all", async () => {
    // Knowable outcome, strengthened per FIX 2's audit: this fixture's
    // policy (`scenario.ts`) authors exactly one "action-scope" rule and
    // NO "history-narrow" rule, so `historyJwts` — garbage or not — can
    // never affect the outcome (`computeHistoryConstraints` has no rule
    // to evaluate them against). `amount: 1` is comfortably within the
    // credential's own granted ceiling, so this is deterministically
    // PERMITTED, not merely "resolves to something".
    const fixture = buildFourBeatFixture(NOW);
    const supplier = new Supplier({ policy: fixture.policy, anchors: fixture.anchors, statusListResolver: fixture.resolver, now: NOW });
    const challenge = supplier.issueChallenge();
    const proof = fixture.buyer.provePossession(challenge);
    await expect(
      supplier.evaluatePresentation(
        challenge,
        {
          proof,
          credentials: {
            authorityJwt: fixture.buyerAuthorityJwt,
            credentialStatus: fixture.buyerCredentialStatus,
            historyJwts: ["", "garbage", "a.b.c"],
          },
        },
        { action: ACTION, scope: { amount: 1 } },
      ),
    ).resolves.toMatchObject({ stage: "policy", permitted: true });
  });

  it("resolves for a request with non-numeric and oversized scope fields", async () => {
    const fixture = buildFourBeatFixture(NOW);
    const challenge = fixture.supplier.issueChallenge();
    const proof = fixture.buyer.provePossession(challenge);
    await expect(
      fixture.supplier.evaluatePresentation(
        challenge,
        { proof, credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
        { action: ACTION, scope: { amount: Number.MAX_SAFE_INTEGER, currency: "USD", nested: { a: 1 } } },
      ),
    ).resolves.toMatchObject({ permitted: false });
  });

  it("resolves for an empty presentation-shaped request naming an unknown action", async () => {
    const fixture = buildFourBeatFixture(NOW);
    const challenge = fixture.supplier.issueChallenge();
    const proof = fixture.buyer.provePossession(challenge);
    await expect(
      fixture.supplier.evaluatePresentation(
        challenge,
        { proof, credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
        { action: "definitely-not-a-real-action", scope: {} },
      ),
    ).resolves.toMatchObject({ permitted: false });
  });
});

describe("createChallenge / issueChallenge freshness", () => {
  it("Supplier.issueChallenge honours the configured deterministic clock", () => {
    const fixture = buildFourBeatFixture(NOW);
    const challenge = fixture.supplier.issueChallenge();
    expect(challenge.issuedAt).toBe(NOW);
    // Sanity: matches the low-level primitive with the same `now`.
    const direct = createChallenge({ now: NOW });
    expect(challenge.issuedAt).toBe(direct.issuedAt);
  });
});

// =========================================================================
// FIX 1 (L4 M6 review, CRITICAL), M6's own boundary — `sanitizeScope`.
// `lib/policy/engine.ts` now guards its OWN reads too (see
// `engine.test.ts`'s equivalent describe block), but the verifier's point
// stands that it is THIS Supplier's job to guard its own composition
// boundary, not to rely on a dependency. Every case below reaches
// `Supplier.evaluatePresentation` — the real, untrusted-counterparty-
// facing entry point — with a hostile `request.scope`.
// =========================================================================
describe("hostile request.scope accessors are refused, never thrown, at the Supplier's own boundary (FIX 1)", () => {
  async function expectRefusedNotThrown(scope: unknown): Promise<void> {
    const fixture = buildFourBeatFixture(NOW);
    const challenge = fixture.supplier.issueChallenge();
    const proof = fixture.buyer.provePossession(challenge);
    const decision = await fixture.supplier.evaluatePresentation(
      challenge,
      { proof, credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
      { action: ACTION, scope: scope as Record<string, unknown> },
    );
    expect(decision.stage).toBe("policy");
    expect(decision.permitted).toBe(false);
  }

  it("the exact L4 M6 repro: an own throwing getter for the bounded field resolves to a structured refusal", async () => {
    const scope: Record<string, unknown> = {};
    Object.defineProperty(scope, "amount", {
      enumerable: true,
      get() {
        throw new Error("boom-getter");
      },
    });
    await expect(
      (async () => {
        const fixture = buildFourBeatFixture(NOW);
        const challenge = fixture.supplier.issueChallenge();
        const proof = fixture.buyer.provePossession(challenge);
        return fixture.supplier.evaluatePresentation(
          challenge,
          { proof, credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
          { action: ACTION, scope } as unknown as NegotiationRequest,
        );
      })(),
    ).resolves.toMatchObject({ stage: "policy", permitted: false });
  });

  it("a getter inherited from the scope object's prototype (not an own property) refuses, never throws", async () => {
    const proto = {};
    Object.defineProperty(proto, "amount", {
      enumerable: true,
      get() {
        throw new Error("boom-prototype-getter");
      },
    });
    await expectRefusedNotThrown(Object.create(proto));
  });

  it("a Proxy whose get/ownKeys/getOwnPropertyDescriptor traps all throw refuses, never throws", async () => {
    const scope = new Proxy(
      {},
      {
        get() {
          throw new Error("boom-proxy-get");
        },
        ownKeys() {
          throw new Error("boom-proxy-ownKeys");
        },
        getOwnPropertyDescriptor() {
          throw new Error("boom-proxy-getOwnPropertyDescriptor");
        },
      },
    );
    await expectRefusedNotThrown(scope);
  });

  it("a bounded-field value whose own toString/valueOf throw is never coerced — refused for not being a number", async () => {
    const hostileValue = {
      valueOf(): number {
        throw new Error("boom-valueof");
      },
      toString(): string {
        throw new Error("boom-tostring");
      },
    };
    await expectRefusedNotThrown({ amount: hostileValue });
  });

  it("a bounded-field value that is itself an object with a throwing getter is never dereferenced — refused for not being a number", async () => {
    const nested: Record<string, unknown> = {};
    Object.defineProperty(nested, "innerField", {
      enumerable: true,
      get() {
        throw new Error("boom-nested-getter");
      },
    });
    await expectRefusedNotThrown({ amount: nested });
  });

  it("a Symbol-keyed property alongside a throwing getter for the bounded field is inert and never visited", async () => {
    const scope: Record<string, unknown> = {};
    const sym = Symbol("hostile-symbol-key");
    Object.defineProperty(scope, sym, {
      enumerable: true,
      get() {
        throw new Error("boom-symbol-getter");
      },
    });
    Object.defineProperty(scope, "amount", {
      enumerable: true,
      get() {
        throw new Error("boom-getter-alongside-symbol");
      },
    });
    await expectRefusedNotThrown(scope);
  });
});

// =========================================================================
// FIX 3 (L4 M6 review, MEDIUM): a challenge is single-use. One issued
// challenge plus one valid presentation used to be replayable against
// arbitrarily many different requests, all permitted. `Supplier` is the
// stateful, long-lived object for one session — this is where "may be
// answered at most once" is now enforced.
// =========================================================================
describe("challenge single-use (FIX 3, L4 M6 review)", () => {
  it("replaying the SAME valid presentation against the SAME challenge: first permitted, second refused at gate:challenge-single-use (distinct from gate:session-challenge and gate:proof-of-possession)", async () => {
    const fixture = buildFourBeatFixture(NOW);
    const challenge = fixture.supplier.issueChallenge();
    const proof = fixture.buyer.provePossession(challenge);
    const presentation: Presentation = {
      proof,
      credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
    };
    const request: NegotiationRequest = { action: ACTION, scope: { amount: 100 } };

    const first = await fixture.supplier.evaluatePresentation(challenge, presentation, request);
    expect(first.stage).toBe("policy");
    expect(first.permitted).toBe(true);

    const second = await fixture.supplier.evaluatePresentation(challenge, presentation, request);
    expect(second.stage).toBe("proof-of-possession");
    expect(second.permitted).toBe(false);
    if (second.stage === "proof-of-possession") {
      expect(second.rule.ruleId).toBe("gate:challenge-single-use");
      expect(second.rule.ruleId).not.toBe("gate:session-challenge");
      expect(second.rule.ruleId).not.toBe("gate:proof-of-possession");
    }
  });

  it("consumption happens even when the FIRST attempt is refused for an unrelated reason — a rejected attempt cannot be retried", async () => {
    const fixture = buildFourBeatFixture(NOW);
    const challenge = fixture.supplier.issueChallenge();
    const proof = fixture.buyer.provePossession(challenge);
    const credentials = { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus };

    // First attempt: a genuine, correctly-bound presentation for THIS
    // challenge, but refused at the POLICY stage (over-scope) — not a
    // proof-of-possession failure.
    const overScopeRequest: NegotiationRequest = { action: ACTION, scope: { amount: 999_999 } };
    const first = await fixture.supplier.evaluatePresentation(challenge, { proof, credentials }, overScopeRequest);
    expect(first.stage).toBe("policy");
    expect(first.permitted).toBe(false);

    // Retrying the SAME challenge with a request that WOULD have been
    // permitted is refused anyway — the nonce was already spent by the
    // first (refused) attempt.
    const wouldHavePermittedRequest: NegotiationRequest = { action: ACTION, scope: { amount: 1 } };
    const retry = await fixture.supplier.evaluatePresentation(challenge, { proof, credentials }, wouldHavePermittedRequest);
    expect(retry.stage).toBe("proof-of-possession");
    expect(retry.permitted).toBe(false);
    if (retry.stage === "proof-of-possession") {
      expect(retry.rule.ruleId).toBe("gate:challenge-single-use");
    }
  });

  it("replay after the challenge has expired is still refused (the natural expiry check backstops the single-use gate even once its own bookkeeping entry has been pruned)", async () => {
    // A mutable options object lets this SAME Supplier instance observe
    // time passing — proving the refusal holds independent of whether
    // the consumed-nonce bookkeeping entry itself is still tracked (see
    // `#pruneExpiredNonces`'s own comment on bounded memory).
    const fixture = buildFourBeatFixture(NOW);
    const options = { policy: fixture.policy, anchors: fixture.anchors, statusListResolver: fixture.resolver, now: NOW };
    const supplier = new Supplier(options);

    const shortLivedChallenge = supplier.issueChallenge({ ttlMs: 1_000 });
    const proof = fixture.buyer.provePossession(shortLivedChallenge);
    const presentation: Presentation = {
      proof,
      credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
    };
    const request: NegotiationRequest = { action: ACTION, scope: { amount: 1 } };

    const first = await supplier.evaluatePresentation(shortLivedChallenge, presentation, request);
    expect(first.permitted).toBe(true);

    // Advance this SAME Supplier's clock well past the challenge's TTL
    // (and past its own pruning window) before replaying.
    options.now = NOW + 60_000;
    const replay = await supplier.evaluatePresentation(shortLivedChallenge, presentation, request);
    expect(replay.permitted).toBe(false);
    expect(replay.stage).toBe("proof-of-possession");
  });

  it("two different challenges in flight concurrently both work — consuming one nonce never affects the other", async () => {
    const fixture = buildFourBeatFixture(NOW);
    const challengeA = fixture.supplier.issueChallenge();
    const challengeB = fixture.supplier.issueChallenge();
    expect(challengeA.nonce).not.toBe(challengeB.nonce);

    const proofA = fixture.buyer.provePossession(challengeA);
    const proofB = fixture.buyer.provePossession(challengeB);
    const credentials = { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus };

    const decisionA = await fixture.supplier.evaluatePresentation(challengeA, { proof: proofA, credentials }, { action: ACTION, scope: { amount: 10 } });
    const decisionB = await fixture.supplier.evaluatePresentation(challengeB, { proof: proofB, credentials }, { action: ACTION, scope: { amount: 20 } });

    expect(decisionA.stage).toBe("policy");
    expect(decisionA.permitted).toBe(true);
    expect(decisionB.stage).toBe("policy");
    expect(decisionB.permitted).toBe(true);

    // Both are now consumed — replaying EITHER is refused at the
    // single-use gate, proving they were tracked independently rather
    // than one nonce accidentally invalidating the other (or both
    // sharing one slot).
    const replayA = await fixture.supplier.evaluatePresentation(challengeA, { proof: proofA, credentials }, { action: ACTION, scope: { amount: 10 } });
    const replayB = await fixture.supplier.evaluatePresentation(challengeB, { proof: proofB, credentials }, { action: ACTION, scope: { amount: 20 } });
    expect(replayA.permitted).toBe(false);
    expect(replayB.permitted).toBe(false);
    if (replayA.stage === "proof-of-possession") expect(replayA.rule.ruleId).toBe("gate:challenge-single-use");
    if (replayB.stage === "proof-of-possession") expect(replayB.rule.ruleId).toBe("gate:challenge-single-use");
  });
});

// =========================================================================
// FIX 4 (MEDIUM, L4 M6 review): M4's `vouched` issuer-trust path, wired
// through this protocol for the first time via `PresentedCredentials.
// vouches`. `lib/trust/anchors.ts`'s `evaluateIssuerTrust` (frozen,
// unmodified) already implements and tests the depth-1 vouching model in
// isolation — these tests prove M6's own composition of it: a presenter
// can now actually REACH that path through the real protocol, and hostile
// `vouches` shapes are sanitised at this module's own boundary before
// ever being forwarded.
// =========================================================================
describe("vouching, wired through the protocol for the first time (FIX 4, L4 M6 review)", () => {
  const VOUCH_ACTION = "vouch-test-action";
  const ONE_YEAR_MS = 365 * 24 * 60 * 60 * 1000;

  interface RawIdentity {
    readonly did: Did;
    readonly privateKey: Uint8Array;
  }
  function makeRawIdentity(): RawIdentity {
    const { publicKey, privateKey } = generateKeyPair();
    return { did: encodeDidKey(publicKey), privateKey };
  }

  function vouchPolicy(): unknown {
    return {
      id: "vouch-test-policy",
      version: "1.0.0",
      revocationHandling: { requireChecked: false, acknowledgedBy: "test-fixture", reason: "no status list wired up for this fixture" },
      rules: [{ kind: "action-scope", id: "R-vouch", description: "x", action: VOUCH_ACTION, maxScope: { amount: 500 } }],
    };
  }

  function issueTestAuthority(issuer: RawIdentity, subject: RawIdentity): string {
    return issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      action: VOUCH_ACTION,
      scope: { amount: 100 },
      validFrom: new Date(NOW).toISOString(),
      validUntil: new Date(NOW + ONE_YEAR_MS).toISOString(),
      now: NOW,
    });
  }

  it("an issuer vouched for by a direct anchor is accepted, and the underlying M4 trust decision names the REAL voucher (the cryptographic signer, never a claimed field)", async () => {
    const anchor = makeRawIdentity();
    const issuerB = makeRawIdentity();
    const presenter = makeRawIdentity();
    const anchors = new TrustAnchorSet([anchor.did]);

    const vouchJwt = issueVouch({ voucherPrivateKey: anchor.privateKey, voucherDid: anchor.did, vouchedIssuerDid: issuerB.did, now: NOW });
    const authorityJwt = issueTestAuthority(issuerB, presenter);

    const supplier = new Supplier({ policy: vouchPolicy(), anchors, now: NOW });
    const challenge = supplier.issueChallenge();
    const proof = provePossession(presenter.privateKey, presenter.did, challenge);

    const decision = await supplier.evaluatePresentation(
      challenge,
      { proof, credentials: { authorityJwt, vouches: [vouchJwt] } },
      { action: VOUCH_ACTION, scope: { amount: 50 } },
    );

    expect(decision.stage).toBe("policy");
    expect(decision.permitted).toBe(true);

    // The underlying M4 trust decision — exactly what `Supplier` itself
    // calls internally — names the REAL voucher: cryptographically the
    // vouch JWS's own signer (recovered from its `kid`), never something
    // an attacker could merely claim in a payload field.
    const authority = await evaluateAuthorityCredentialTrust({ jwt: authorityJwt, presenterProof: proof, anchors, vouches: [vouchJwt], now: NOW });
    expect(authority.accepted).toBe(true);
    if (authority.accepted) {
      expect(authority.issuerTrust.reason.kind).toBe("vouched");
      if (authority.issuerTrust.reason.kind === "vouched") {
        expect(authority.issuerTrust.reason.voucher).toBe(anchor.did);
      }
    }
  });

  it("a vouch signed by a non-anchor attacker naming itself is refused — the voucher must itself be a direct anchor", async () => {
    const anchor = makeRawIdentity();
    const attacker = makeRawIdentity();
    const presenter = makeRawIdentity();
    const anchors = new TrustAnchorSet([anchor.did]);

    // The attacker signs a vouch FOR ITSELF (not a direct anchor), then
    // issues the actual authority credential to a separate presenter —
    // `issuer !== subject`, so this exercises the VOUCH check, not the
    // unconditional self-issuance refusal Beat 4 already covers.
    const selfVouch = issueVouch({ voucherPrivateKey: attacker.privateKey, voucherDid: attacker.did, vouchedIssuerDid: attacker.did, now: NOW });
    const authorityJwt = issueTestAuthority(attacker, presenter);

    const supplier = new Supplier({ policy: vouchPolicy(), anchors, now: NOW });
    const challenge = supplier.issueChallenge();
    const proof = provePossession(presenter.privateKey, presenter.did, challenge);

    const decision = await supplier.evaluatePresentation(
      challenge,
      { proof, credentials: { authorityJwt, vouches: [selfVouch] } },
      { action: VOUCH_ACTION, scope: { amount: 50 } },
    );

    expect(decision.stage).toBe("policy");
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("untrusted-issuer");
      expect(decision.explanation.field.actual).toBe("untrusted-issuer");
    }
  });

  it("a vouch naming a DIFFERENT issuer than the one who actually signed the presented credential is refused — a vouch cannot be replayed onto an unrelated issuer", async () => {
    const anchor = makeRawIdentity();
    const issuerB = makeRawIdentity(); // vouched for by the anchor
    const issuerC = makeRawIdentity(); // NOT vouched for; actually signs the credential
    const presenter = makeRawIdentity();
    const anchors = new TrustAnchorSet([anchor.did]);

    const vouchForB = issueVouch({ voucherPrivateKey: anchor.privateKey, voucherDid: anchor.did, vouchedIssuerDid: issuerB.did, now: NOW });
    const authorityJwt = issueTestAuthority(issuerC, presenter);

    const supplier = new Supplier({ policy: vouchPolicy(), anchors, now: NOW });
    const challenge = supplier.issueChallenge();
    const proof = provePossession(presenter.privateKey, presenter.did, challenge);

    const decision = await supplier.evaluatePresentation(
      challenge,
      { proof, credentials: { authorityJwt, vouches: [vouchForB] } },
      { action: VOUCH_ACTION, scope: { amount: 50 } },
    );

    expect(decision.stage).toBe("policy");
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("untrusted-issuer");
    }
  });

  it("a depth-2 vouch chain (anchor vouches B, B vouches C) is refused at the depth-1 limit", async () => {
    const anchor = makeRawIdentity();
    const issuerB = makeRawIdentity();
    const issuerC = makeRawIdentity();
    const presenter = makeRawIdentity();
    const anchors = new TrustAnchorSet([anchor.did]);

    const anchorVouchesB = issueVouch({ voucherPrivateKey: anchor.privateKey, voucherDid: anchor.did, vouchedIssuerDid: issuerB.did, now: NOW });
    const bVouchesC = issueVouch({ voucherPrivateKey: issuerB.privateKey, voucherDid: issuerB.did, vouchedIssuerDid: issuerC.did, now: NOW });
    const authorityJwt = issueTestAuthority(issuerC, presenter);

    const supplier = new Supplier({ policy: vouchPolicy(), anchors, now: NOW });
    const challenge = supplier.issueChallenge();
    const proof = provePossession(presenter.privateKey, presenter.did, challenge);

    const decision = await supplier.evaluatePresentation(
      challenge,
      { proof, credentials: { authorityJwt, vouches: [anchorVouchesB, bVouchesC] } },
      { action: VOUCH_ACTION, scope: { amount: 50 } },
    );

    expect(decision.stage).toBe("policy");
    expect(decision.permitted).toBe(false);
    if (decision.stage === "policy" && !decision.permitted) {
      expect(decision.explanation.refusalKind).toBe("untrusted-issuer");
    }
  });

  it("hostile `vouches` shapes (non-array, null/garbage entries, 1000 entries) resolve, never throw", async () => {
    const anchor = makeRawIdentity();
    const presenter = makeRawIdentity();
    const anchors = new TrustAnchorSet([anchor.did]);
    // Self-issued, so refused regardless of `vouches` content — isolates
    // the property under test (never throws) from the vouch mechanism
    // itself (already covered by the other tests in this block).
    const authorityJwt = issueTestAuthority(presenter, presenter);

    const hostileVouchesShapes: readonly unknown[] = [
      "not-an-array",
      null,
      undefined,
      42,
      [null, 123, {}, "garbage-jwt", "a.b.c"],
      Array.from({ length: 1000 }, (_, i) => `garbage-vouch-${i}`),
    ];

    for (const hostileVouches of hostileVouchesShapes) {
      const supplier = new Supplier({ policy: vouchPolicy(), anchors, now: NOW });
      const challenge = supplier.issueChallenge();
      const proof = provePossession(presenter.privateKey, presenter.did, challenge);
      await expect(
        supplier.evaluatePresentation(
          challenge,
          { proof, credentials: { authorityJwt, vouches: hostileVouches as unknown as readonly string[] } },
          { action: VOUCH_ACTION, scope: { amount: 50 } },
        ),
      ).resolves.toMatchObject({ stage: "policy", permitted: false });
    }
  });
});

// =========================================================================
// SECOND L4 M6 REVIEW — FIX A (CRITICAL): the prune predicate must be the
// exact complement of M1's `verifyPossession` expiry check. The previous
// round's `#pruneExpiredNonces` evicted a bookkeeping entry when
// `expiresAt <= now`, but `verifyPossession` only refuses when
// `now > expiresAt` — a one-instant disagreement, at `now === expiresAt`,
// during which pruning forgot a nonce proof-of-possession still treated
// as live, reopening the exact replay window FIX 3 (first review) closed.
// =========================================================================
describe("prune/expiry boundary — the prune predicate is the exact complement of verifyPossession's expiry check (FIX A, second L4 M6 review, CRITICAL)", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  /** A Supplier that reads `Date.now()` (mockable via `vi.setSystemTime`)
   *  on every call, instead of a fixed injected `now` — so these tests
   *  can walk fake-timer time forward in exact, single-millisecond
   *  steps up to and past a challenge's own `expiresAt`. */
  function buildRealtimeSupplier(): { readonly fixture: ReturnType<typeof buildFourBeatFixture>; readonly supplier: Supplier } {
    const fixture = buildFourBeatFixture(NOW);
    const supplier = new Supplier({ policy: fixture.policy, anchors: fixture.anchors, statusListResolver: fixture.resolver });
    return { fixture, supplier };
  }

  async function replayAfterPruneAt(offsetFromExpiry: number): Promise<{ readonly firstPermitted: boolean; readonly replayPermitted: boolean; readonly replayStage: string }> {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);

    const { fixture, supplier } = buildRealtimeSupplier();
    const challenge = supplier.issueChallenge({ ttlMs: 1_000 });
    const proof = fixture.buyer.provePossession(challenge);
    const presentation: Presentation = {
      proof,
      credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
    };
    const request: NegotiationRequest = { action: ACTION, scope: { amount: 1 } };

    // Consume the challenge legitimately.
    const first = await supplier.evaluatePresentation(challenge, presentation, request);

    // Advance the clock to the requested instant relative to
    // `expiresAt`, then trigger pruning via an UNRELATED
    // `evaluatePresentation` call at that same instant — pruning runs
    // at the top of every call, regardless of which challenge it names.
    vi.setSystemTime(challenge.expiresAt + offsetFromExpiry);
    const unrelatedChallenge = supplier.issueChallenge({ ttlMs: 60_000 });
    const unrelatedProof = fixture.buyer.provePossession(unrelatedChallenge);
    await supplier.evaluatePresentation(
      unrelatedChallenge,
      { proof: unrelatedProof, credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
      request,
    );

    // Replay the IDENTICAL already-used (challenge, presentation) pair.
    const replay = await supplier.evaluatePresentation(challenge, presentation, request);
    return { firstPermitted: first.permitted, replayPermitted: replay.permitted, replayStage: replay.stage };
  }

  it("one ms BEFORE expiry: the nonce is nowhere near pruned — replay refused at the single-use gate (sanity baseline)", async () => {
    const result = await replayAfterPruneAt(-1);
    expect(result.firstPermitted).toBe(true);
    expect(result.replayPermitted).toBe(false);
    expect(result.replayStage).toBe("proof-of-possession");
  });

  it("EXACTLY at expiry (now === expiresAt): still refused — the regression test that matters. verifyPossession would still ACCEPT a fresh proof at this exact instant (now > expiresAt is false), so pruning must not have forgotten this nonce, and the replay must not be silently permitted", async () => {
    const result = await replayAfterPruneAt(0);
    expect(result.firstPermitted).toBe(true);
    expect(result.replayPermitted).toBe(false);
    expect(result.replayStage).toBe("proof-of-possession");
  });

  it("one ms AFTER expiry: refused regardless — even if pruning DID drop the bookkeeping entry here, verifyPossession's own ChallengeExpiredError backstops it", async () => {
    const result = await replayAfterPruneAt(1);
    expect(result.firstPermitted).toBe(true);
    expect(result.replayPermitted).toBe(false);
    expect(result.replayStage).toBe("proof-of-possession");
  });
});

// =========================================================================
// SECOND L4 M6 REVIEW — FIX B: consumption must happen only AFTER
// `verifyPossession` actually succeeds, not the instant a presentation
// merely cites a nonce. The previous ordering let anyone who knew or
// intercepted a challenge nonce burn the legitimate holder's one shot
// with a garbage signature, without holding any private key.
// =========================================================================
describe("consumption happens only after possession is genuinely proven (FIX B, second L4 M6 review)", () => {
  it("a garbage-signed presentation for a challenge, followed by the legitimate presentation for the SAME challenge: the legitimate one is PERMITTED (no longer burned by the impostor's failed attempt)", async () => {
    const fixture = buildFourBeatFixture(NOW);
    const supplier = new Supplier({ policy: fixture.policy, anchors: fixture.anchors, statusListResolver: fixture.resolver, now: NOW });
    const challenge = supplier.issueChallenge();
    const request: NegotiationRequest = { action: ACTION, scope: { amount: 1 } };
    const credentials = { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus };

    // An attacker who merely knows/intercepted the challenge nonce (it
    // travels on the wire in plain sight — only private keys are
    // secret) submits a presentation citing it, but with a signature
    // that does not verify.
    const garbageProof: Presentation["proof"] = { did: fixture.buyer.did, challenge, signature: "00".repeat(64) };
    const garbageDecision = await supplier.evaluatePresentation(challenge, { proof: garbageProof, credentials }, request);
    expect(garbageDecision.stage).toBe("proof-of-possession");
    expect(garbageDecision.permitted).toBe(false);
    if (garbageDecision.stage === "proof-of-possession") {
      expect(garbageDecision.rule.ruleId).toBe("gate:proof-of-possession");
    }

    // The REAL Buyer now answers the SAME challenge, genuinely — this
    // must be permitted; the failed impostor attempt above must not
    // have spent the nonce.
    const legitProof = fixture.buyer.provePossession(challenge);
    const legitDecision = await supplier.evaluatePresentation(challenge, { proof: legitProof, credentials }, request);
    expect(legitDecision.stage).toBe("policy");
    expect(legitDecision.permitted).toBe(true);
  });

  it("a genuinely valid presentation, once accepted, is still refused if replayed — single-use still holds for a REAL presentation", async () => {
    const fixture = buildFourBeatFixture(NOW);
    const challenge = fixture.supplier.issueChallenge();
    const proof = fixture.buyer.provePossession(challenge);
    const presentation: Presentation = { proof, credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } };
    const request: NegotiationRequest = { action: ACTION, scope: { amount: 1 } };

    const first = await fixture.supplier.evaluatePresentation(challenge, presentation, request);
    expect(first.permitted).toBe(true);

    const replay = await fixture.supplier.evaluatePresentation(challenge, presentation, request);
    expect(replay.permitted).toBe(false);
    expect(replay.stage).toBe("proof-of-possession");
    if (replay.stage === "proof-of-possession") {
      expect(replay.rule.ruleId).toBe("gate:challenge-single-use");
    }
  });

  it("two calls racing on ONE challenge via Promise.all: exactly one is permitted — the concurrency property did not regress when consumption moved after verification", async () => {
    const fixture = buildFourBeatFixture(NOW);
    const challenge = fixture.supplier.issueChallenge();
    const proof = fixture.buyer.provePossession(challenge);
    const presentation: Presentation = { proof, credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } };
    const request: NegotiationRequest = { action: ACTION, scope: { amount: 1 } };

    const [a, b] = await Promise.all([
      fixture.supplier.evaluatePresentation(challenge, presentation, request),
      fixture.supplier.evaluatePresentation(challenge, presentation, request),
    ]);

    const permittedCount = [a, b].filter((decision) => decision.permitted).length;
    expect(permittedCount).toBe(1);
  });

  it("a presentation refused at POLICY (valid signature, over scope) still consumes the nonce — possession WAS proven, so retrying is refused at the single-use gate, not re-evaluated", async () => {
    const fixture = buildFourBeatFixture(NOW);
    const challenge = fixture.supplier.issueChallenge();
    const proof = fixture.buyer.provePossession(challenge);
    const credentials = { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus };

    const overScopeRequest: NegotiationRequest = { action: ACTION, scope: { amount: 999_999 } };
    const first = await fixture.supplier.evaluatePresentation(challenge, { proof, credentials }, overScopeRequest);
    expect(first.stage).toBe("policy");
    expect(first.permitted).toBe(false);

    const wouldHavePermittedRequest: NegotiationRequest = { action: ACTION, scope: { amount: 1 } };
    const retry = await fixture.supplier.evaluatePresentation(challenge, { proof, credentials }, wouldHavePermittedRequest);
    expect(retry.stage).toBe("proof-of-possession");
    expect(retry.permitted).toBe(false);
    if (retry.stage === "proof-of-possession") {
      expect(retry.rule.ruleId).toBe("gate:challenge-single-use");
    }
  });
});

// =========================================================================
// SECOND L4 M6 REVIEW — FIX C, guarantee #1: `sanitizeScope` must hand
// onward a plain, inert COPY, not the caller's own object by reference.
// Mutation testing found that gutting this to a passthrough broke none
// of the (then) 288 tests, because `lib/policy/engine.ts`'s own guard
// (`safe-scope-read.ts`) independently tolerates the same hostile scope
// shapes and produces an identical DECISION either way — testing THROUGH
// the engine cannot distinguish "copied defensively" from "passed by
// reference, but still safely read downstream". Only calling
// `sanitizeScope` directly and inspecting its return value's identity
// can pin this property.
// =========================================================================
describe("sanitizeScope's own boundary property: a plain, inert copy (FIX C, second L4 M6 review)", () => {
  it("returns a NEW object, never the same reference as its input, and mutations after the call cross the boundary in NEITHER direction", () => {
    const input: Record<string, unknown> = { amount: 100, currency: "USD" };
    const copy = sanitizeScope(input);

    // The property a reference-passthrough mutant would violate:
    expect(copy).not.toBe(input);
    expect(copy).toEqual({ amount: 100, currency: "USD" });

    // Mutating the ORIGINAL after the call must not reach the copy —
    // this is what "inert" means, and what a real Supplier composition
    // boundary needs against a counterparty that retains a handle to
    // the object it handed over.
    input.amount = 999_999;
    (input as Record<string, unknown>).injected = "attacker-added-after-the-call";
    expect(copy.amount).toBe(100);
    expect(copy).not.toHaveProperty("injected");

    // And the reverse: mutating the COPY must not reach back to the
    // caller's original object.
    (copy as Record<string, unknown>).pokedFromCopy = "should-not-appear-on-input";
    expect(input).not.toHaveProperty("pokedFromCopy");
  });

  it("an empty/non-object input still produces its own fresh, independently-mutable object each call", () => {
    const a = sanitizeScope(null);
    const b = sanitizeScope(null);
    expect(a).not.toBe(b);
    expect(a).toEqual({});
    (a as Record<string, unknown>).x = 1;
    expect(b).not.toHaveProperty("x");
  });
});

// =========================================================================
// SECOND L4 M6 REVIEW — FIX C, guarantee #2: the vouch cap
// (`MAX_VOUCHES_PER_PRESENTATION`) demonstrably changes real outcomes,
// yet mutation testing found removing its `.slice` broke none of the
// (then) 288 tests — nothing in the suite exercised enough vouches at
// once to notice. This pins the cap's actual, observable effect: a real
// vouch beyond the cap is dropped and never reaches `evaluateIssuerTrust`
// at all, while the identical vouch placed within the cap is accepted.
// =========================================================================
describe("vouch cap enforcement regression (FIX C, second L4 M6 review)", () => {
  const CAP_ACTION = "vouch-cap-test-action";
  const ONE_YEAR_MS = 365 * 24 * 60 * 60 * 1000;

  interface RawIdentity {
    readonly did: Did;
    readonly privateKey: Uint8Array;
  }
  function makeRawIdentity(): RawIdentity {
    const { publicKey, privateKey } = generateKeyPair();
    return { did: encodeDidKey(publicKey), privateKey };
  }

  function capPolicy(): unknown {
    return {
      id: "vouch-cap-test-policy",
      version: "1.0.0",
      revocationHandling: { requireChecked: false, acknowledgedBy: "test-fixture", reason: "no status list wired up for this fixture" },
      rules: [{ kind: "action-scope", id: "R-cap", description: "x", action: CAP_ACTION, maxScope: { amount: 500 } }],
    };
  }

  function issueTestAuthority(issuer: RawIdentity, subject: RawIdentity): string {
    return issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      action: CAP_ACTION,
      scope: { amount: 100 },
      validFrom: new Date(NOW).toISOString(),
      validUntil: new Date(NOW + ONE_YEAR_MS).toISOString(),
      now: NOW,
    });
  }

  it(`a real vouch beyond the ${MAX_VOUCHES_PER_PRESENTATION}-entry cap (as entry #${MAX_VOUCHES_PER_PRESENTATION + 1}) is dropped and refused, while the SAME vouch placed within the first ${MAX_VOUCHES_PER_PRESENTATION} entries is accepted — fails if the cap's .slice is removed`, async () => {
    const anchor = makeRawIdentity();
    const issuerB = makeRawIdentity();
    const presenter = makeRawIdentity();
    const anchors = new TrustAnchorSet([anchor.did]);

    const realVouch = issueVouch({ voucherPrivateKey: anchor.privateKey, voucherDid: anchor.did, vouchedIssuerDid: issuerB.did, now: NOW });
    const authorityJwt = issueTestAuthority(issuerB, presenter);
    const bogusVouches = Array.from({ length: MAX_VOUCHES_PER_PRESENTATION }, (_, i) => `not-a-real-vouch-${i}`);

    // Case A: MAX_VOUCHES_PER_PRESENTATION bogus vouches, THEN the one
    // real vouch as the (MAX + 1)th entry. If the cap is enforced, the
    // real vouch never reaches `evaluateIssuerTrust` — refused, since no
    // vouch among the surviving (capped) entries verifies.
    const supplierA = new Supplier({ policy: capPolicy(), anchors, now: NOW });
    const challengeA = supplierA.issueChallenge();
    const proofA = provePossession(presenter.privateKey, presenter.did, challengeA);
    const decisionA = await supplierA.evaluatePresentation(
      challengeA,
      { proof: proofA, credentials: { authorityJwt, vouches: [...bogusVouches, realVouch] } },
      { action: CAP_ACTION, scope: { amount: 50 } },
    );
    expect(decisionA.stage).toBe("policy");
    expect(decisionA.permitted).toBe(false);
    if (decisionA.stage === "policy" && !decisionA.permitted) {
      expect(decisionA.explanation.refusalKind).toBe("untrusted-issuer");
    }

    // Case B: the IDENTICAL real vouch, but placed WITHIN the cap
    // (replacing the last bogus entry) — survives, verifies, accepted.
    const withinCap = [...bogusVouches.slice(0, MAX_VOUCHES_PER_PRESENTATION - 1), realVouch];
    expect(withinCap.length).toBe(MAX_VOUCHES_PER_PRESENTATION);
    const supplierB = new Supplier({ policy: capPolicy(), anchors, now: NOW });
    const challengeB = supplierB.issueChallenge();
    const proofB = provePossession(presenter.privateKey, presenter.did, challengeB);
    const decisionB = await supplierB.evaluatePresentation(
      challengeB,
      { proof: proofB, credentials: { authorityJwt, vouches: withinCap } },
      { action: CAP_ACTION, scope: { amount: 50 } },
    );
    expect(decisionB.stage).toBe("policy");
    expect(decisionB.permitted).toBe(true);
  });
});
