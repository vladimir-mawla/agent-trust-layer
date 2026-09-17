/**
 * The four beats, proved — not merely printed. `scripts/demo-negotiation.ts`
 * renders these same beats for a human; this file is the actual evidence
 * that each one behaves as M6's brief requires, asserting on the
 * STRUCTURE of each decision (stage, refusalKind, the exact field/
 * numbers), never merely "it was refused" or "it printed something".
 */
import { describe, expect, it } from "vitest";
import { buildFourBeatFixture, runFourBeats } from "./scenario.js";

describe("the four-beat negotiation scenario", () => {
  it("Beat 1 — accepted: within granted authority, revocation checked and clean", async () => {
    const fixture = buildFourBeatFixture();
    const [beat1] = await runFourBeats(fixture);
    const decision = beat1!.decision;

    expect(decision.stage).toBe("policy");
    if (decision.stage !== "policy" || !decision.permitted) {
      throw new Error(`expected Beat 1 to be permitted, got ${JSON.stringify(decision)}`);
    }
    expect(decision.provenDid).toBe(fixture.buyer.did);
    expect(decision.explanation.outcome).toBe("permitted");
    expect(decision.explanation.rule.ruleId).toBe("R-purchase-office-supplies");
    expect(decision.explanation.field.requested).toBe("purchase-office-supplies");
    expect(decision.envelope.issuer).toBe(fixture.issuer.did);
    // Structured explanation, not a bare boolean.
    expect(typeof decision.explanation.narrative).toBe("string");
    expect(decision.explanation.narrative.length).toBeGreaterThan(0);
  });

  it("Beat 2 — refused over scope: names the exact field and BOTH numbers", async () => {
    const fixture = buildFourBeatFixture();
    const [, beat2] = await runFourBeats(fixture);
    const decision = beat2!.decision;

    expect(decision.stage).toBe("policy");
    if (decision.stage !== "policy" || decision.permitted) {
      throw new Error(`expected Beat 2 to be refused, got ${JSON.stringify(decision)}`);
    }
    expect(decision.explanation.refusalKind).toBe("over-scope");
    expect(decision.explanation.field.path).toBe("scope.amount");
    expect(decision.explanation.field.requested).toBe(5000);
    expect(decision.explanation.field.permitted).toBe(500);
    expect(decision.provenDid).toBe(fixture.buyer.did);
  });

  it('Beat 3 — refused as spoofed identity: stage is "proof-of-possession", not "policy"', async () => {
    const fixture = buildFourBeatFixture();
    const [, , beat3] = await runFourBeats(fixture);
    const decision = beat3!.decision;

    // The stage itself is the proof this failed BEFORE credential
    // examination — a "policy" stage decision (even a refused one) would
    // mean the credential was at least looked at.
    expect(decision.stage).toBe("proof-of-possession");
    if (decision.stage !== "proof-of-possession") {
      throw new Error("unreachable");
    }
    expect(decision.permitted).toBe(false);
    expect(decision.claimedDid).toBe(fixture.buyer.did);
    expect(decision.rule.ruleId).toBe("gate:proof-of-possession");
    expect(decision.narrative).toContain("did not prove possession");
  });

  it("Beat 3's impostor DID is byte-for-byte identical to the Buyer's real DID (the whole point of the attack)", async () => {
    const fixture = buildFourBeatFixture();
    const [, , beat3] = await runFourBeats(fixture);
    const decision = beat3!.decision;
    expect(decision.stage).toBe("proof-of-possession");
    if (decision.stage === "proof-of-possession") {
      expect(decision.claimedDid).toBe(fixture.buyer.did);
      expect(decision.claimedDid).not.toBe(fixture.attacker.did);
    }
  });

  it('Beat 4 — refused as forged credential: refusalKind is "untrusted-issuer" (self-issued), never a signature failure', async () => {
    const fixture = buildFourBeatFixture();
    const [, , , beat4] = await runFourBeats(fixture);
    const decision = beat4!.decision;

    expect(decision.stage).toBe("policy");
    if (decision.stage !== "policy" || decision.permitted) {
      throw new Error(`expected Beat 4 to be refused, got ${JSON.stringify(decision)}`);
    }
    // The critical distinction this test exists to prove: NOT
    // "credential-verification-failed" (which would mean the signature
    // didn't check out — it does, genuinely). Specifically
    // "untrusted-issuer", because the credential's signature is valid.
    expect(decision.explanation.refusalKind).toBe("untrusted-issuer");
    expect(decision.explanation.refusalKind).not.toBe("credential-verification-failed");
    expect(decision.explanation.field.actual).toBe("self-issued");
    expect(decision.provenDid).toBe(fixture.attacker.did);
  });

  it("runs all four beats with their labelled expectations satisfied", async () => {
    const fixture = buildFourBeatFixture();
    const beats = await runFourBeats(fixture);
    expect(beats).toHaveLength(4);
    for (const beat of beats) {
      const actualPermitted = beat.decision.permitted;
      const expectedPermitted = beat.expected === "permitted";
      expect(actualPermitted, `beat "${beat.id}" expected permitted=${expectedPermitted}`).toBe(expectedPermitted);
    }
  });
});
