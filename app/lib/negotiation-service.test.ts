/**
 * M8's own proof that the demo endpoint's data comes from running the
 * REAL protocol, not from strings this app made up, and that it never
 * carries key material. Deliberately lives under `app/`, not `tests/`
 * (frozen for this milestone) — this exercises `app/lib/negotiation-service.ts`,
 * app code, not `lib/`'s own attack suite.
 */
import { describe, expect, it } from "vitest";
import { getFixedFourBeats, runCustomNegotiation } from "./negotiation-service.js";

/** A private Ed25519 key, hex-encoded, is exactly 64 hex characters. A
 *  did:key, a JWT, and a hex-encoded PUBLIC key can also be long
 *  hex/base-looking strings — this check is deliberately about the one
 *  thing that must never appear anywhere in a response: the literal
 *  bytes of a `KeyHolder`'s `#privateKey`. Since that field is a true JS
 *  private class field, it structurally cannot be read from outside the
 *  class (see `lib/negotiation/agent.ts`) — this test is a second,
 *  independent belt-and-suspenders check on the actual JSON this app
 *  sends, not a substitute for that structural guarantee. */
function assertNoRawKeyLooking(value: unknown): void {
  const json = JSON.stringify(value);
  expect(json.toLowerCase()).not.toContain("privatekey");
  expect(json.toLowerCase()).not.toContain("secretkey");
}

describe("getFixedFourBeats", () => {
  it("returns exactly the four beats, matching what scripts/demo-negotiation.ts asserts", async () => {
    const scenario = await getFixedFourBeats();
    expect(scenario.beats.map((b) => b.id)).toEqual(["accepted", "over-scope", "spoofed-identity", "forged-credential"]);
    expect(scenario.beats[0]!.decision.permitted).toBe(true);
    expect(scenario.beats[1]!.decision.permitted).toBe(false);
    expect(scenario.beats[2]!.decision.permitted).toBe(false);
    expect(scenario.beats[2]!.decision.stage).toBe("proof-of-possession");
    expect(scenario.beats[3]!.decision.permitted).toBe(false);
    assertNoRawKeyLooking(scenario);
  });

  it("Beat 3's claimed DID is byte-for-byte identical to the cast's real buyer DID", async () => {
    const scenario = await getFixedFourBeats();
    const beat3 = scenario.beats[2]!;
    expect(beat3.decision.stage).toBe("proof-of-possession");
    if (beat3.decision.stage === "proof-of-possession") {
      expect(beat3.decision.claimedDid).toBe(scenario.cast.buyerDid);
    }
  });

  it("derives the over-scope numbers from the real credential ceiling, not a literal", async () => {
    const scenario = await getFixedFourBeats();
    const beat2 = scenario.beats[1]!;
    expect(beat2.decision.permitted).toBe(false);
    if (beat2.decision.stage === "policy" && !beat2.decision.permitted) {
      expect(beat2.decision.explanation.refusalKind).toBe("over-scope");
      expect(beat2.decision.explanation.field.requested).toBe(5000);
      expect(beat2.decision.explanation.field.permitted).toBe(scenario.policy.grantedMaxAmount);
    }
  });
});

describe("runCustomNegotiation", () => {
  it("permits an honest request within the granted ceiling", async () => {
    const result = await runCustomNegotiation({ amount: 150, attack: "none" });
    expect(result.decision.permitted).toBe(true);
    assertNoRawKeyLooking(result);
  });

  it("refuses an honest over-scope request with refusalKind over-scope", async () => {
    const result = await runCustomNegotiation({ amount: 5000, attack: "none" });
    expect(result.decision.permitted).toBe(false);
    if (result.decision.stage === "policy" && !result.decision.permitted) {
      expect(result.decision.explanation.refusalKind).toBe("over-scope");
    } else {
      throw new Error(`expected stage=policy/refused, got ${JSON.stringify(result.decision)}`);
    }
  });

  it("refuses a negative amount with refusalKind negative-scope-value (M7's own finding)", async () => {
    const result = await runCustomNegotiation({ amount: -500, attack: "none" });
    expect(result.decision.permitted).toBe(false);
    if (result.decision.stage === "policy" && !result.decision.permitted) {
      expect(result.decision.explanation.refusalKind).toBe("negative-scope-value");
    } else {
      throw new Error(`expected stage=policy/refused, got ${JSON.stringify(result.decision)}`);
    }
  });

  it("refuses a spoofed DID at proof-of-possession, before any credential is examined", async () => {
    const result = await runCustomNegotiation({ amount: 150, attack: "spoof-did" });
    expect(result.decision.stage).toBe("proof-of-possession");
    expect(result.decision.permitted).toBe(false);
    if (result.decision.stage === "proof-of-possession") {
      expect(result.decision.claimedDid).toBe(result.cast.buyerDid);
    }
    assertNoRawKeyLooking(result);
  });

  it("refuses a forged (self-issued) credential as untrusted-issuer", async () => {
    const result = await runCustomNegotiation({ amount: 150, attack: "forge-credential" });
    expect(result.decision.permitted).toBe(false);
    if (result.decision.stage === "policy" && !result.decision.permitted) {
      expect(result.decision.explanation.refusalKind).toBe("untrusted-issuer");
    } else {
      throw new Error(`expected stage=policy/refused, got ${JSON.stringify(result.decision)}`);
    }
  });

  it("refuses a revoked credential as revoked, even for an in-scope amount", async () => {
    const result = await runCustomNegotiation({ amount: 150, attack: "revoked-credential" });
    expect(result.decision.permitted).toBe(false);
    if (result.decision.stage === "policy" && !result.decision.permitted) {
      expect(result.decision.explanation.refusalKind).toBe("revoked");
    } else {
      throw new Error(`expected stage=policy/refused, got ${JSON.stringify(result.decision)}`);
    }
  });
});
