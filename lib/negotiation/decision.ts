/**
 * `NegotiationDecision` — the Supplier's answer to a presentation.
 * Always a discriminated union of structured data, never a bare
 * boolean, continuing `every-decision-is-explainable`
 * (context-graph.json) one layer up from `lib/policy`'s own
 * `PolicyDecision`.
 *
 * Two `stage`s, corresponding to the two places a refusal can originate
 * in this protocol:
 *   - `"proof-of-possession"` — refused before ANY credential was
 *     examined at all (`supplier.ts` returns this without ever calling
 *     `evaluateAuthorityCredentialTrust`). Carries `claimedDid` — the
 *     DID the presenter CLAIMED, which is all the Supplier ever learns
 *     when that claim couldn't be backed by a valid proof.
 *   - `"policy"` — everything from M4/M5 ran; the decision is exactly
 *     M5's own `PolicyDecision`, carried through unchanged (this module
 *     adds no second opinion on top of it), plus `provenDid` — the DID
 *     the Supplier actually verified the presenter possesses, which
 *     `PolicyDecision` itself has no notion of.
 *
 * A caller narrowing on `decision.permitted` gets `decision.explanation`
 * narrowed to the matching `Explanation` variant for stage `"policy"`
 * (the same `Extract<...>` idiom `lib/policy/engine.ts`'s own
 * `PolicyDecision` uses), and on `decision.stage` to tell the two
 * refusal origins apart when that distinction matters (as it does for
 * M6's own required tests — see `scenario.test.ts`).
 */
import type { Did } from "../identity/index.js";
import type { AuthorityEnvelope, Explanation } from "../policy/index.js";
import type { NegotiationFieldEvidence, NegotiationRuleRef } from "./explanation.js";

export type NegotiationDecision =
  | {
      readonly stage: "proof-of-possession";
      readonly permitted: false;
      readonly claimedDid: Did;
      readonly rule: NegotiationRuleRef;
      readonly field: NegotiationFieldEvidence;
      readonly narrative: string;
    }
  | {
      readonly stage: "policy";
      readonly permitted: true;
      readonly provenDid: Did;
      readonly explanation: Extract<Explanation, { readonly outcome: "permitted" }>;
      readonly envelope: AuthorityEnvelope;
    }
  | {
      readonly stage: "policy";
      readonly permitted: false;
      readonly provenDid: Did;
      readonly explanation: Extract<Explanation, { readonly outcome: "refused" }>;
    };

/**
 * Render a human-readable line PURELY from `NegotiationDecision`'s
 * structured fields — the M6 analogue of
 * `lib/policy/explanation.ts`'s `renderExplanation`, extended to also
 * cover the proof-of-possession stage that module knows nothing about.
 * For stage `"policy"`, delegates to M5's own `renderExplanation` so the
 * two stages render with the same voice.
 */
export function renderNegotiationDecision(decision: NegotiationDecision, renderExplanation: (explanation: Explanation) => string): string {
  if (decision.stage === "proof-of-possession") {
    const verdict = "REFUSED (proof-of-possession)";
    return `${verdict} — rule "${decision.rule.ruleId}" (${decision.rule.description}); field "${decision.field.path}"${
      decision.field.actual !== undefined ? ` [actual=${JSON.stringify(decision.field.actual)}]` : ""
    }; ${decision.narrative}`;
  }
  return renderExplanation(decision.explanation);
}
