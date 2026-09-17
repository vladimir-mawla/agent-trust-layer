/**
 * REGRESSION 15 — a one-millisecond comparator disagreement reopened the
 * replay window. REAL HISTORICAL DEFECT (M6, CRITICAL — FIX A of the
 * SECOND L4 M6 review): `Supplier.#pruneExpiredNonces` evicted a
 * consumed-nonce bookkeeping entry using `expiresAt <= now`, while M1's
 * frozen `verifyPossession` only refuses a fresh proof at
 * `now > expiresAt` (i.e. it still ACCEPTS at the exact boundary
 * `now === expiresAt`). At that single instant, pruning had already
 * forgotten a nonce that proof-of-possession still considered live —
 * so an already-spent presentation was permitted a SECOND time, exactly
 * at `now === expiresAt`, reopening the single-use replay window FIX 3
 * (the first L4 M6 review) existed to close in the first place.
 *
 * Fixed by making the prune predicate the exact logical complement of
 * `verifyPossession`'s own check (`expiresAt < now`, i.e. evict only
 * when `now > expiresAt`) — the two must never independently drift.
 *
 * This test uses fake timers to walk to the EXACT instant that matters
 * and its immediate neighbours, proving the replay is refused at
 * `expiresAt - 1`, `expiresAt` (the regression that matters), and
 * `expiresAt + 1`.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { verifyPossession } from "../../../lib/identity/index.js";
import { buildFourBeatFixture, Supplier } from "../../../lib/negotiation/index.js";
import type { Presentation, NegotiationRequest } from "../../../lib/negotiation/index.js";

const NOW = Date.parse("2026-09-17T00:00:00.000Z");
const ACTION = "purchase-office-supplies";

describe("regression 15 — the nonce-prune boundary is the exact complement of verifyPossession's expiry check (real M6 CRITICAL defect)", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  async function replayAtOffsetFromExpiry(offsetFromExpiry: number): Promise<{ readonly firstPermitted: boolean; readonly replayPermitted: boolean; readonly replayStage: string }> {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);

    const fixture = buildFourBeatFixture(NOW);
    // A Supplier that reads the mockable Date.now() on every call
    // (rather than a fixed injected `now`), so fake-timer time can be
    // walked forward in single-millisecond steps around the challenge's
    // own `expiresAt`.
    const supplier = new Supplier({ policy: fixture.policy, anchors: fixture.anchors, statusListResolver: fixture.resolver });

    const challenge = supplier.issueChallenge({ ttlMs: 1_000 });
    const proof = fixture.buyer.provePossession(challenge);
    const presentation: Presentation = {
      proof,
      credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
    };
    const request: NegotiationRequest = { action: ACTION, scope: { amount: 1 } };

    // Consume the challenge legitimately.
    const first = await supplier.evaluatePresentation(challenge, presentation, request);

    // Advance to the instant under test, then trigger pruning (which
    // runs at the top of EVERY `evaluatePresentation` call, regardless
    // of which challenge it names) via an unrelated call.
    vi.setSystemTime(challenge.expiresAt + offsetFromExpiry);
    const unrelatedChallenge = supplier.issueChallenge({ ttlMs: 60_000 });
    const unrelatedProof = fixture.buyer.provePossession(unrelatedChallenge);
    await supplier.evaluatePresentation(
      unrelatedChallenge,
      { proof: unrelatedProof, credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus } },
      request,
    );

    // Replay the IDENTICAL, already-used (challenge, presentation) pair.
    const replay = await supplier.evaluatePresentation(challenge, presentation, request);
    return { firstPermitted: first.permitted, replayPermitted: replay.permitted, replayStage: replay.stage };
  }

  it("one ms BEFORE expiry (expiresAt - 1): replay refused at the single-use gate (sanity baseline — the nonce is nowhere near pruned)", async () => {
    const result = await replayAtOffsetFromExpiry(-1);
    expect(result.firstPermitted).toBe(true);
    expect(result.replayPermitted).toBe(false);
    expect(result.replayStage).toBe("proof-of-possession");
  });

  it("EXACTLY at expiry (now === expiresAt): still refused — THE regression that matters. verifyPossession would still accept a FRESH proof at this exact instant (now > expiresAt is false), so pruning must not have forgotten this nonce", async () => {
    const result = await replayAtOffsetFromExpiry(0);
    expect(result.firstPermitted).toBe(true);
    expect(result.replayPermitted).toBe(false);
    expect(result.replayStage).toBe("proof-of-possession");
  });

  it("one ms AFTER expiry (expiresAt + 1): refused regardless — verifyPossession's own ChallengeExpiredError backstops it even if pruning dropped the bookkeeping entry here", async () => {
    const result = await replayAtOffsetFromExpiry(1);
    expect(result.firstPermitted).toBe(true);
    expect(result.replayPermitted).toBe(false);
    expect(result.replayStage).toBe("proof-of-possession");
  });

  it("[mechanism, direct] a fresh (never-before-seen) proof against a challenge is still genuinely ACCEPTED by verifyPossession exactly AT its own expiresAt — confirming the boundary this whole regression is about", () => {
    const fixture = buildFourBeatFixture(NOW);
    const challenge = fixture.supplier.issueChallenge({ ttlMs: 1_000 });
    const proof = fixture.buyer.provePossession(challenge);
    // now === expiresAt exactly: verifyPossession's own check is
    // `now > expiresAt`, which is false here, so this must NOT throw.
    expect(() => verifyPossession(proof, { now: challenge.expiresAt })).not.toThrow();
    // One ms later, it must throw.
    expect(() => verifyPossession(proof, { now: challenge.expiresAt + 1 })).toThrow();
  });
});
