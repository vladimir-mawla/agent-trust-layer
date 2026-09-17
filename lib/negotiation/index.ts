/**
 * Public API of the negotiation module (M6): a real, two-agent
 * challenge/presentation/decision protocol composing M1 (identity) with
 * M4 (trust) and M5 (policy) into one explainable Supplier decision, plus
 * the fixed four-beat demo scenario `scripts/demo-negotiation.ts` (and
 * M8's UI) render.
 *
 * Framework-free by design, same as `lib/identity`, `lib/credentials`,
 * `lib/trust`, and `lib/policy` — nothing here may import from Next.js
 * or React.
 */
export { KeyHolder } from "./agent.js";

export type { Challenge, NegotiationRequest, PresentedCredentials, Presentation, ProofOfPossession } from "./messages.js";

export {
  GATE_PROOF_OF_POSSESSION,
  GATE_SESSION_CHALLENGE,
  negotiationFieldEvidence,
  type NegotiationFieldEvidence,
  type NegotiationRuleRef,
} from "./explanation.js";

export { renderNegotiationDecision, type NegotiationDecision } from "./decision.js";

export { Supplier, type SupplierOptions } from "./supplier.js";

export {
  ACTION,
  DEFAULT_SCENARIO_NOW,
  GRANTED_MAX_AMOUNT,
  STATUS_LIST_URL,
  buildFourBeatFixture,
  runFourBeatScenario,
  runFourBeats,
  type Beat,
  type FourBeatFixture,
} from "./scenario.js";
