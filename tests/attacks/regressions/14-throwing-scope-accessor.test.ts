/**
 * REGRESSION 14 — a throwing scope accessor rejected instead of
 * refusing. REAL HISTORICAL DEFECT (M6, CRITICAL — FIX 1 of the first
 * L4 M6 review): `Object.defineProperty(scope, "amount", { enumerable:
 * true, get() { throw ... } })` made `evaluatePresentation` REJECT (an
 * unhandled promise rejection) instead of resolving to a structured
 * refusal — a hostile `request.scope` (never re-validated the way
 * `policy` is — see `lib/policy/safe-scope-read.ts`'s own comment) could
 * turn "never-quite-verified input" into a crash instead of the
 * structured `PolicyDecision` this engine's whole contract promises.
 *
 * Fixed at TWO independent layers: `lib/policy/safe-scope-read.ts`'s
 * `readScopeField` (the root-layer fix, inside `engine.ts` itself) and
 * `lib/negotiation/supplier.ts`'s `sanitizeScope` (a redundant boundary
 * guard one layer up). This suite exercises the ROOT layer directly
 * (`evaluatePolicyRequest`, bypassing `Supplier`'s own sanitisation) so
 * the assertions pin the actual mechanism that matters, per the
 * `lib/policy/engine.test.ts` comment: "proving the ROOT-LAYER fix... holds
 * even for a caller that bypasses `Supplier`'s own boundary sanitisation
 * entirely" — plus one end-to-end test through the real `Supplier` for
 * good measure.
 *
 * This suite goes BEYOND the family already pinned in
 * `lib/policy/engine.test.ts`/`lib/negotiation/supplier.test.ts` — it adds
 * a `has`-trap Proxy, a getter that throws only on its SECOND invocation
 * (proving the engine reads a field AT MOST ONCE, so no such getter can
 * ever actually reach its throwing branch), an object that attempts to
 * inject new keys into itself WHILE being enumerated (proving
 * `Reflect.ownKeys`'s snapshot-before-iterate ordering makes that
 * pointless), and getters returning a `Symbol`/`BigInt` instead of a
 * number (proving neither ever reaches a `JSON.stringify` call with a
 * value it cannot serialise).
 */
import { describe, expect, it } from "vitest";
import { createChallenge } from "../../../lib/identity/index.js";
import type { AuthorityCredential } from "../../../lib/credentials/index.js";
import { evaluateAuthorityCredentialTrust, type TrustDecision } from "../../../lib/trust/index.js";
import { buildFourBeatFixture, type FourBeatFixture, type Presentation, type NegotiationRequest } from "../../../lib/negotiation/index.js";
import { sanitizeScope } from "../../../lib/negotiation/supplier.js";
import { evaluatePolicyRequest, renderExplanation, type PolicyDecision, type PolicyRequest } from "../../../lib/policy/index.js";

/** Build a GENUINE, fully-verified, accepted `TrustDecision` from the
 *  real four-beat fixture — never a fabricated/cast object — so this
 *  suite's hostile-`request.scope` attacks are isolated to exactly the
 *  one input this defect is actually about. */
async function realAcceptedAuthority(fixture: FourBeatFixture): Promise<TrustDecision<AuthorityCredential> & { readonly accepted: true }> {
  const challenge = createChallenge({ now: fixture.now });
  const proof = fixture.buyer.provePossession(challenge);
  const decision = await evaluateAuthorityCredentialTrust({
    jwt: fixture.buyerAuthorityJwt,
    presenterProof: proof,
    anchors: fixture.anchors,
    credentialStatus: fixture.buyerCredentialStatus,
    statusListResolver: fixture.resolver,
    now: fixture.now,
  });
  if (!decision.accepted) throw new Error("fixture's own credential must be genuinely accepted for this test to be meaningful");
  return decision;
}

function expectRefusedNotThrown(policy: unknown, request: { readonly action: string; readonly scope: unknown }, authority: TrustDecision<AuthorityCredential> & { readonly accepted: true }): Extract<PolicyDecision, { readonly permitted: false }> {
  let decision: PolicyDecision | undefined;
  expect(() => {
    decision = evaluatePolicyRequest({ policy, request: request as unknown as PolicyRequest, authority, history: [] });
  }).not.toThrow();
  if (decision === undefined) throw new Error("unreachable");
  expect(decision.permitted).toBe(false);
  if (decision.permitted) throw new Error("expected a refusal");
  // Rendering must not itself throw — proves no hostile raw value ever
  // reached JSON.stringify unguarded.
  expect(() => renderExplanation(decision!.explanation)).not.toThrow();
  return decision;
}

describe("regression 14 — a throwing scope accessor resolves to a structured refusal, never a crash (real M6 CRITICAL defect)", () => {
  it("[repro, direct] an own throwing getter for the bounded field refuses, never throws", async () => {
    const fixture = buildFourBeatFixture();
    const authority = await realAcceptedAuthority(fixture);
    const scope: Record<string, unknown> = {};
    Object.defineProperty(scope, "amount", { enumerable: true, get() { throw new Error("boom-getter"); } });

    const decision = expectRefusedNotThrown(fixture.policy, { action: "purchase-office-supplies", scope }, authority);
    expect(decision.explanation.refusalKind).toBe("over-scope");
  });

  it("a prototype-chain getter (not an own property) refuses, never throws", async () => {
    const fixture = buildFourBeatFixture();
    const authority = await realAcceptedAuthority(fixture);
    const proto = {};
    Object.defineProperty(proto, "amount", { enumerable: true, get() { throw new Error("boom-prototype"); } });
    const scope: Record<string, unknown> = Object.create(proto);

    expectRefusedNotThrown(fixture.policy, { action: "purchase-office-supplies", scope }, authority);
  });

  it("a Proxy whose get/ownKeys/getOwnPropertyDescriptor/has traps ALL throw refuses, never throws", async () => {
    const fixture = buildFourBeatFixture();
    const authority = await realAcceptedAuthority(fixture);
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
        has() {
          throw new Error("boom-proxy-has");
        },
      },
    );

    expectRefusedNotThrown(fixture.policy, { action: "purchase-office-supplies", scope }, authority);
  });

  it("a hostile valueOf/toString on the bounded field's value is never coerced — refused for not being a number, not crashed", async () => {
    const fixture = buildFourBeatFixture();
    const authority = await realAcceptedAuthority(fixture);
    const hostileValue = {
      valueOf(): number {
        throw new Error("boom-valueof");
      },
      toString(): string {
        throw new Error("boom-tostring");
      },
    };

    expectRefusedNotThrown(fixture.policy, { action: "purchase-office-supplies", scope: { amount: hostileValue } }, authority);
  });

  it("a getter that throws only on its SECOND invocation never actually throws — the field is read AT MOST ONCE", async () => {
    const fixture = buildFourBeatFixture();
    const authority = await realAcceptedAuthority(fixture);
    let readCount = 0;
    const scope: Record<string, unknown> = {};
    Object.defineProperty(scope, "amount", {
      enumerable: true,
      get() {
        readCount += 1;
        if (readCount >= 2) throw new Error("boom-on-second-read");
        return 10; // well within the credential's own 500 ceiling
      },
    });

    let decision: PolicyDecision | undefined;
    expect(() => {
      decision = evaluatePolicyRequest({ policy: fixture.policy, request: { action: "purchase-office-supplies", scope }, authority, history: [] });
    }).not.toThrow();
    // The engine reads the field exactly once, so the first (valid, in-
    // scope) value is what decides the outcome — never the throwing
    // second read, which never happens at all.
    expect(readCount).toBe(1);
    expect(decision?.permitted).toBe(true);
  });

  it("an object that injects a NEW key into itself while being read is inert — Reflect.ownKeys already snapshotted the key list before enumeration began", () => {
    const scope: Record<string, unknown> = {};
    Object.defineProperty(scope, "amount", {
      enumerable: true,
      get() {
        // Self-mutating hazard: try to widen what gets copied WHILE the
        // copy is in progress.
        Object.defineProperty(scope, "injectedDuringEnumeration", { enumerable: true, value: 999_999_999 });
        return 10;
      },
    });

    const copy = sanitizeScope(scope);
    expect(copy).toEqual({ amount: 10 });
    expect(Object.keys(copy)).not.toContain("injectedDuringEnumeration");
  });

  it("a getter returning a Symbol is treated as non-numeric and refused, and never reaches a JSON.stringify that would throw on it", async () => {
    const fixture = buildFourBeatFixture();
    const authority = await realAcceptedAuthority(fixture);
    const scope = { amount: Symbol("hostile-symbol-value") };

    const decision = expectRefusedNotThrown(fixture.policy, { action: "purchase-office-supplies", scope }, authority);
    expect(decision.explanation.refusalKind).toBe("over-scope");
    // The hostile raw value must never have been threaded into
    // `field.requested` — only into a `note`, if anywhere at all.
    expect(decision.explanation.field.requested).toBeUndefined();
  });

  it("a getter returning a BigInt is treated as non-numeric and refused, and never reaches a JSON.stringify that would throw on it", async () => {
    const fixture = buildFourBeatFixture();
    const authority = await realAcceptedAuthority(fixture);
    const scope = { amount: 10n };

    const decision = expectRefusedNotThrown(fixture.policy, { action: "purchase-office-supplies", scope }, authority);
    expect(decision.explanation.refusalKind).toBe("over-scope");
    expect(decision.explanation.field.requested).toBeUndefined();
  });

  it("[end-to-end] the SAME hostile getter, presented through the real Supplier, resolves to a structured refusal — never an unhandled rejection", async () => {
    const fixture = buildFourBeatFixture();
    const scope: Record<string, unknown> = {};
    Object.defineProperty(scope, "amount", { enumerable: true, get() { throw new Error("boom-getter-end-to-end"); } });

    const challenge = fixture.supplier.issueChallenge();
    const presentation: Presentation = {
      proof: fixture.buyer.provePossession(challenge),
      credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
    };
    const request: NegotiationRequest = { action: "purchase-office-supplies", scope: scope as unknown as Record<string, unknown> };

    await expect(fixture.supplier.evaluatePresentation(challenge, presentation, request)).resolves.toMatchObject({ stage: "policy", permitted: false });
  });
});
