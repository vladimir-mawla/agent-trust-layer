/**
 * Pure formatting over `lib/negotiation`'s `NegotiationDecision` /
 * `lib/policy`'s `Explanation` — the ONE place M8 turns structured data
 * into display strings, used identically by the server-rendered fixed
 * four beats (`app/page.tsx`) and the client-rendered custom result
 * (`app/components/InteractivePanel.tsx`), so the two can never drift
 * into two different renderings of the same kind of decision.
 *
 * Every field below is read straight off `decision.rule` / `.field` /
 * `.narrative` (proof-of-possession stage) or `decision.explanation.*`
 * (policy stage) — never a hardcoded per-beat string. Change what
 * `lib/policy`/`lib/negotiation` compute (a ceiling, a rule id, a
 * refusal kind) and this file's output changes with it automatically.
 *
 * Only TYPE-level imports from `lib/`: erased at compile time, so this
 * module pulls in none of `lib/negotiation`'s runtime (which transitively
 * imports `node:zlib` via `lib/trust/bitstring.ts` — see
 * `negotiation-service.ts`'s module comment). That is what makes this
 * one file safe to import from a "use client" component.
 */
import type { NegotiationDecision } from "../../lib/negotiation/index.js";

export interface DisplayFieldValue {
  readonly path: string;
  readonly requested?: unknown;
  readonly permitted?: unknown;
  readonly actual?: unknown;
  readonly note?: string;
}

export interface DisplayDecision {
  readonly permitted: boolean;
  readonly verdictLabel: "PERMITTED" | "REFUSED";
  readonly refusalKind?: string;
  readonly stage: "proof-of-possession" | "policy";
  readonly stageLabel: string;
  readonly ruleId: string;
  readonly ruleDescription: string;
  readonly field: DisplayFieldValue;
  readonly narrative: string;
  readonly claimedDid?: string;
  readonly provenDid?: string;
}

function copyField(field: { readonly path: string; readonly requested?: unknown; readonly permitted?: unknown; readonly actual?: unknown; readonly note?: string }): DisplayFieldValue {
  return {
    path: field.path,
    ...(field.requested !== undefined ? { requested: field.requested } : {}),
    ...(field.permitted !== undefined ? { permitted: field.permitted } : {}),
    ...(field.actual !== undefined ? { actual: field.actual } : {}),
    ...(field.note !== undefined ? { note: field.note } : {}),
  };
}

/** Derive everything a `BeatCard` renders purely from the structured
 *  `NegotiationDecision` — see this module's own comment. */
export function toDisplayDecision(decision: NegotiationDecision): DisplayDecision {
  if (decision.stage === "proof-of-possession") {
    return {
      permitted: false,
      verdictLabel: "REFUSED",
      stage: "proof-of-possession",
      stageLabel: "proof of possession — refused before any credential was examined",
      ruleId: decision.rule.ruleId,
      ruleDescription: decision.rule.description,
      field: copyField(decision.field),
      narrative: decision.narrative,
      claimedDid: decision.claimedDid,
    };
  }

  const explanation = decision.explanation;
  return {
    permitted: decision.permitted,
    verdictLabel: decision.permitted ? "PERMITTED" : "REFUSED",
    stage: "policy",
    stageLabel: "policy — identity proven; credential, issuer trust, revocation, and scope all evaluated",
    ruleId: explanation.rule.ruleId,
    ruleDescription: explanation.rule.description,
    field: copyField(explanation.field),
    narrative: explanation.narrative,
    provenDid: decision.provenDid,
    ...(explanation.outcome === "refused" ? { refusalKind: explanation.refusalKind } : {}),
  };
}

/** Middle-truncate a long `did:key:...` string, keeping the head (the
 *  part that makes Beat 3's identical-DID point readable at a glance)
 *  and the tail visible. Mirrors `scripts/demo-negotiation.ts`'s own
 *  `truncateDid` in spirit (short enough to read, long enough that two
 *  identical DIDs are visibly identical) — reimplemented here rather
 *  than imported, since `scripts/` is a standalone CLI entry point, not
 *  a module this app depends on. */
export function truncateDid(did: string, headLength = 22, tailLength = 8): string {
  if (did.length <= headLength + tailLength + 1) {
    return did;
  }
  return `${did.slice(0, headLength)}…${did.slice(-tailLength)}`;
}

/** Format an evidence value (a requested/permitted/actual number, or any
 *  other JSON value) for monospace display. */
export function formatEvidenceValue(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  return JSON.stringify(value);
}
