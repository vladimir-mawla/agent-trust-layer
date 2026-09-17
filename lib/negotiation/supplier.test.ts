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
import { describe, expect, it, vi } from "vitest";
import { createChallenge } from "../identity/index.js";
import type { CredentialStatusEntry, StatusListResolver } from "../trust/index.js";
import { KeyHolder } from "./agent.js";
import { buildFourBeatFixture } from "./scenario.js";
import { Supplier } from "./supplier.js";
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

  it.each(hostileAuthorityJwts)("evaluatePresentation resolves (never throws/rejects) for authorityJwt=%j", async (jwt) => {
    const supplier = makeSupplier();
    const challenge = supplier.issueChallenge();
    const proof = attacker.provePossession(challenge);
    await expect(
      supplier.evaluatePresentation(challenge, { proof, credentials: { authorityJwt: jwt } }, { action: ACTION, scope: { amount: 1 } }),
    ).resolves.toBeDefined();
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

  it("resolves for credentialStatus: null (would otherwise throw reading entry.statusSize)", async () => {
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
    ).resolves.toBeDefined();
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
    await expect(
      supplier.evaluatePresentation(challenge2, { proof: proof2, credentials: { authorityJwt: "irrelevant" } }, null as unknown as NegotiationRequest),
    ).resolves.toBeDefined();
  });

  it("resolves for request.scope: null and request itself missing 'action'", async () => {
    const fixture = buildFourBeatFixture(NOW);
    const supplier = new Supplier({ policy: fixture.policy, anchors: fixture.anchors, statusListResolver: fixture.resolver, now: NOW });
    const challenge = supplier.issueChallenge();
    const proof = fixture.buyer.provePossession(challenge);
    // `scope: null` is sanitised to `{}` — an empty scope has no field to
    // bound-check, so this legitimately PERMITS (the action itself still
    // matches a real, granted, unrevoked authority credential); the point
    // of this assertion is only that it resolves at all, never throws.
    await expect(
      supplier.evaluatePresentation(
        challenge,
        { proof, credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
        { action: ACTION, scope: null as unknown as Record<string, unknown> },
      ),
    ).resolves.toBeDefined();

    const challenge2 = supplier.issueChallenge();
    const proof2 = fixture.buyer.provePossession(challenge2);
    await expect(
      supplier.evaluatePresentation(
        challenge2,
        { proof: proof2, credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
        {} as unknown as NegotiationRequest,
      ),
    ).resolves.toMatchObject({ permitted: false });
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

  it("resolves for hostile historyJwts (garbage strings mixed with a valid one)", async () => {
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
    ).resolves.toBeDefined();
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
