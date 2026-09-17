#!/usr/bin/env -S npx tsx
/**
 * M6 demo: `npm run demo:negotiation`.
 *
 * A thin presentation layer over `lib/negotiation` — every outcome
 * printed below is produced by running the REAL protocol
 * (`lib/negotiation/scenario.ts`'s `runFourBeatScenario`, which itself
 * composes real `lib/identity` + `lib/credentials` + `lib/trust` +
 * `lib/policy` code) end to end. Nothing in this file computes a
 * decision, forges a credential, or checks a signature — it only reads
 * `Beat`/`NegotiationDecision` values this module never touches the
 * internals of, and prints them legibly.
 *
 * Self-checking (per M6's own requirement): each beat's ACTUAL outcome
 * is compared against what that beat claims to demonstrate, plus one
 * beat-specific structural assertion (e.g. Beat 3 must fail at the
 * `"proof-of-possession"` stage, not merely be refused — a refusal for
 * the wrong reason is exactly as much a failure here as an acceptance
 * would be). Exit code is 0 only if every beat matches; a real,
 * reproducible narration should never be blocked by this script quietly
 * "passing" a beat that behaved wrong.
 */
import { GRANTED_MAX_AMOUNT, runFourBeatScenario, type Beat, type NegotiationDecision } from "../lib/negotiation/index.js";

function truncateDid(did: string): string {
  // Long enough to be recognisably distinct between two different DIDs,
  // short enough to read in a terminal — and, critically for Beat 3,
  // long enough that two IDENTICAL DIDs (the Buyer's real one and the
  // one the impostor claims) are visibly, unmistakably the same string.
  return did.length <= 28 ? did : `${did.slice(0, 20)}…${did.slice(-6)}`;
}

function renderDecisionLine(decision: NegotiationDecision): string {
  if (decision.stage === "proof-of-possession") {
    return [
      `    stage:      proof-of-possession (refused BEFORE any credential was examined)`,
      `    rule:       ${decision.rule.ruleId} — ${decision.rule.description}`,
      `    field:      ${decision.field.path}${decision.field.actual !== undefined ? ` = ${JSON.stringify(decision.field.actual)}` : ""}`,
      `    reason:     ${decision.narrative}`,
    ].join("\n");
  }
  const explanation = decision.explanation;
  const verdict = decision.permitted ? "PERMITTED" : `REFUSED (${explanation.refusalKind})`;
  return [
    `    stage:      policy (identity proven as ${truncateDid(decision.provenDid)}; credential + trust + policy all evaluated)`,
    `    verdict:    ${verdict}`,
    `    rule:       ${explanation.rule.ruleId} — ${explanation.rule.description}`,
    `    field:      ${explanation.field.path}${explanation.field.requested !== undefined ? ` requested=${JSON.stringify(explanation.field.requested)}` : ""}${
      explanation.field.permitted !== undefined ? ` permitted=${JSON.stringify(explanation.field.permitted)}` : ""
    }${explanation.field.actual !== undefined ? ` actual=${JSON.stringify(explanation.field.actual)}` : ""}`,
    `    reason:     ${explanation.narrative}`,
  ].join("\n");
}

/** Beat-specific structural checks — asserting the STAGE/refusalKind a
 *  beat is supposed to demonstrate, not merely permitted-vs-refused. A
 *  demo that "refuses for the wrong reason" is exactly the failure mode
 *  the M6 brief warns a printed string can paper over. */
function checkBeat(beat: Beat): { readonly ok: boolean; readonly detail: string } {
  const d = beat.decision;
  switch (beat.id) {
    case "accepted":
      if (d.stage === "policy" && d.permitted) return { ok: true, detail: "permitted, as expected" };
      return { ok: false, detail: `expected stage=policy/permitted=true, got stage=${d.stage} permitted=${d.permitted}` };
    case "over-scope":
      if (d.stage === "policy" && !d.permitted && d.explanation.refusalKind === "over-scope") {
        return { ok: true, detail: 'refused with refusalKind="over-scope", as expected' };
      }
      return {
        ok: false,
        detail: `expected stage=policy/refused with refusalKind="over-scope", got stage=${d.stage} permitted=${d.permitted}${
          d.stage === "policy" && !d.permitted ? ` refusalKind=${d.explanation.refusalKind}` : ""
        }`,
      };
    case "spoofed-identity":
      if (d.stage === "proof-of-possession" && !d.permitted) {
        return { ok: true, detail: "refused at stage=proof-of-possession, BEFORE any credential was examined, as expected" };
      }
      return { ok: false, detail: `expected stage=proof-of-possession, got stage=${d.stage} permitted=${d.permitted}` };
    case "forged-credential":
      if (d.stage === "policy" && !d.permitted && d.explanation.refusalKind === "untrusted-issuer") {
        return { ok: true, detail: 'refused with refusalKind="untrusted-issuer", as expected' };
      }
      return {
        ok: false,
        detail: `expected stage=policy/refused with refusalKind="untrusted-issuer", got stage=${d.stage} permitted=${d.permitted}${
          d.stage === "policy" && !d.permitted ? ` refusalKind=${d.explanation.refusalKind}` : ""
        }`,
      };
    default: {
      const exhaustive: never = beat.id;
      return exhaustive;
    }
  }
}

async function main(): Promise<void> {
  console.log("=".repeat(78));
  console.log("agent-trust-layer — M6 cross-agent negotiation demo");
  console.log("=".repeat(78));
  console.log(
    [
      "",
      "Two independent agents, each holding its own Ed25519 keypair: a Buyer and",
      "an Attacker. A Supplier holds a policy and a set of trust anchors — never",
      "anyone else's private key (see lib/negotiation/agent.ts). Ed25519 keys are",
      "freshly generated THIS run (via @noble/curves) — the DID strings below",
      "will differ on your next run; what stays invariant across every run is",
      "the RELATIONSHIP between them (e.g. Beat 3's impostor DID being byte-for-",
      'byte identical to the Buyer\'s real DID). The clock is fixed ("now" =',
      "2026-09-17T00:00:00.000Z) so every other part of this run is reproducible.",
      "",
    ].join("\n"),
  );

  const { fixture, beats } = await runFourBeatScenario();

  console.log("Cast for this run:");
  console.log(`  issuer (trust anchor)   ${fixture.issuer.did}`);
  console.log(`  buyer                   ${fixture.buyer.did}`);
  console.log(`  attacker                ${fixture.attacker.did}`);
  console.log("");
  console.log(
    `Supplier's policy "${fixture.policy.id}" v${fixture.policy.version}: action-scope rule permits\n` +
      `"${fixture.policy.rules[0]!.action}" up to amount=${GRANTED_MAX_AMOUNT}; revocation must be checked` +
      ` (revocationHandling.requireChecked = true).`,
  );
  console.log("=".repeat(78));

  let allOk = true;

  for (const beat of beats) {
    console.log("");
    console.log(`${beat.title}`);
    console.log(`  asker:      ${beat.asker}`);
    console.log(`  asked for:  ${beat.askedFor}`);
    console.log(renderDecisionLine(beat.decision));

    const check = checkBeat(beat);
    const actualPermitted = beat.decision.permitted;
    const expectedPermitted = beat.expected === "permitted";
    const outcomeOk = actualPermitted === expectedPermitted && check.ok;
    allOk = allOk && outcomeOk;
    console.log(`  self-check: ${outcomeOk ? "PASS" : "FAIL"} — ${check.detail}`);
  }

  console.log("");
  console.log("=".repeat(78));
  if (allOk) {
    console.log("ALL FOUR BEATS PRODUCED THEIR EXPECTED OUTCOME.");
    console.log("=".repeat(78));
    process.exitCode = 0;
  } else {
    console.log("AT LEAST ONE BEAT DID NOT PRODUCE ITS EXPECTED OUTCOME — SEE 'FAIL' ABOVE.");
    console.log("=".repeat(78));
    process.exitCode = 1;
  }
}

main().catch((error: unknown) => {
  console.error("demo-negotiation.ts crashed unexpectedly:", error);
  process.exitCode = 1;
});
