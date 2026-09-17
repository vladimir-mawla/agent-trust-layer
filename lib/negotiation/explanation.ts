/**
 * Structured explanations for the one gate M6 adds ahead of M5's own
 * policy engine: proof of possession. Mirrors the shape
 * `lib/policy/explanation.ts` already established for
 * `every-decision-is-explainable` (context-graph.json) — a stable
 * `RuleRef` naming WHAT fired, a `FieldEvidence` naming WHICH field, and
 * a human `narrative` — so a proof-of-possession refusal and a policy
 * refusal render identically to a consumer (M6's demo script, M8's UI)
 * even though they come from two different modules.
 */

/** A reference to the named gate that fired — the M6 analogue of
 *  `lib/policy/explanation.ts`'s `RuleRef`, for the one stage that isn't
 *  a policy-authored rule at all: this project's own protocol gate. */
export interface NegotiationRuleRef {
  readonly ruleId: string;
  readonly description: string;
}

/** The field that satisfied or failed the gate, with concrete evidence
 *  — never a bare "no". Mirrors `lib/policy/explanation.ts`'s
 *  `FieldEvidence`. */
export interface NegotiationFieldEvidence {
  readonly path: string;
  readonly requested?: unknown;
  readonly permitted?: unknown;
  readonly actual?: unknown;
  readonly note?: string;
}

export function negotiationFieldEvidence(
  path: string,
  parts: { readonly requested?: unknown; readonly permitted?: unknown; readonly actual?: unknown; readonly note?: string } = {},
): NegotiationFieldEvidence {
  return {
    path,
    ...(parts.requested !== undefined ? { requested: parts.requested } : {}),
    ...(parts.permitted !== undefined ? { permitted: parts.permitted } : {}),
    ...(parts.actual !== undefined ? { actual: parts.actual } : {}),
    ...(parts.note !== undefined ? { note: parts.note } : {}),
  };
}

/** A presented proof answers a challenge nonce this session did not
 *  issue — either a different session entirely, or a captured proof
 *  being replayed into a new one. Checked BEFORE the proof's own
 *  signature, since "is this even for us" is cheaper than, and logically
 *  prior to, "is this cryptographically valid". */
export const GATE_SESSION_CHALLENGE: NegotiationRuleRef = {
  ruleId: "gate:session-challenge",
  description:
    "a presented proof of possession must answer the EXACT challenge this session issued; a proof for any other challenge (a different session, or a captured/replayed one) is refused before any credential is examined",
};

/** The proof-of-possession gate itself: the claimed DID must be backed
 *  by a signature only its true private key could produce, over THIS
 *  session's fresh challenge. This is the mechanism the brief's named
 *  "spoofed identity" failure test exercises — see `supplier.ts`. */
export const GATE_PROOF_OF_POSSESSION: NegotiationRuleRef = {
  ruleId: "gate:proof-of-possession",
  description:
    "the presenter must prove possession of the private key behind its claimed DID by signing this session's fresh challenge (M1); possessing or copying the DID string alone proves nothing",
};

/** A `Presentation` whose `proof` (or `proof.challenge`) is missing or
 *  not even shaped like a proof at all — e.g. `undefined`, `null`, or a
 *  JSON value with no `challenge` object. Checked before `proof.did`/
 *  `proof.challenge.nonce` are ever dereferenced, so a malformed or
 *  hostile message is refused here, never an unhandled `TypeError`. */
export const GATE_MALFORMED_PRESENTATION: NegotiationRuleRef = {
  ruleId: "gate:malformed-presentation",
  description:
    "a presentation must carry a proof shaped as { did, challenge: { nonce, issuedAt, expiresAt }, signature } before anything about it can be checked",
};
