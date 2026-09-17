/**
 * The structured explanation every `PolicyDecision` carries —
 * `every-decision-is-explainable` (context-graph.json) made concrete for
 * M5, the same way `lib/credentials/verification-result.ts` made it
 * concrete for M3 and `lib/trust/trust-decision.ts`'s `TrustDecision`
 * made it concrete for M4.
 *
 * ## Machine-readable first, prose second
 *
 * `Explanation` is a discriminated union (`outcome: "permitted" |
 * "refused"`) of plain data: `rule` names WHICH rule fired (a stable
 * `ruleId` plus its authored `description` — or, for a refusal that
 * isn't about any single authored `PolicyRule` at all, one of this
 * module's own named structural gates, e.g. `GATE_AUTHORITY_REQUIRED`),
 * and `field` names WHICH credential field satisfied or failed it,
 * carrying the REQUESTED and PERMITTED values side by side so a
 * consumer never has to string-parse "insufficient authority" back into
 * "$5,000 vs 500". `narrative` is a human sentence, but it is NOT the
 * authoritative artifact — `renderExplanation` below proves that by
 * building its OWN sentence purely from `outcome`/`refusalKind`/`rule`/
 * `field`, with `narrative` appended only as extra context, never as the
 * only place the "real" information lives. This is what M6's demo
 * narration, M8's UI, and any future consumer are meant to render from —
 * never a prose string with fields glued in after the fact.
 *
 * `caveats` is a separate, always-present (possibly empty) array for
 * information that doesn't fit the single rule/field shape — today,
 * exactly one caveat kind exists: recording that a PERMIT relied on a
 * policy's explicit, justified opt-in to accept unchecked revocation
 * (see `policy-types.ts`'s `RevocationRequirement`). Modelled as
 * structured data, not a boolean flag or a note buried in `narrative`,
 * so "this permit involved an explicit risk acceptance" is something a
 * consumer can query for programmatically.
 */
import type { Did } from "../identity/index.js";

/** Every distinct, named way a request can be refused — see the M5
 *  brief's own "Refusal reasons must be distinguishable" requirement.
 *  Each is produced by exactly one `switch` arm in `engine.ts`; there is
 *  no code path that returns `refused` without picking one of these.
 *
 *  `"negative-scope-value"` (added for the M7 exploratory attack suite's
 *  own finding — see `engine.ts`'s comment on the guard that produces
 *  it) is DELIBERATELY its own kind, never folded into `"over-scope"`:
 *  "over scope" is a misleading description of a request like
 *  `amount: -500000` against a ceiling of `500` — the request is not
 *  ABOVE the ceiling, it is on the wrong side of zero entirely, and a
 *  consumer narrating this decision (M6's demo, M8's UI, this milestone's
 *  own attack suite) needs to be able to say so precisely, not merely
 *  "too much". */
export type RefusalKind =
  | "no-authority-credential"
  | "credential-verification-failed"
  | "untrusted-issuer"
  | "revoked"
  | "revocation-not-checked"
  | "wrong-action"
  | "no-matching-rule"
  | "over-scope"
  | "history-constraint"
  | "negative-scope-value";

/** A reference to whatever fired: either an authored `PolicyRule`'s own
 *  `id`/`description`, or one of this module's structural gates below. */
export interface RuleRef {
  readonly ruleId: string;
  readonly description: string;
}

/** The credential (or request) field that satisfied or failed the rule,
 *  with the concrete values involved — never just "insufficient". Every
 *  member is optional because different refusal kinds have different
 *  evidence available (an untrusted-issuer refusal has no numeric
 *  `requested`/`permitted` pair; an over-scope refusal always does), but
 *  `path` is always present: there is always at least a named field. */
export interface FieldEvidence {
  readonly path: string;
  readonly requested?: unknown;
  readonly permitted?: unknown;
  readonly actual?: unknown;
  /** Free-text supplementary detail (e.g. the M3_STEP_LABEL refinement)
   *  — never the ONLY signal for anything a test asserts on; always
   *  paired with a structured field above that already names the fact. */
  readonly note?: string;
}

function evidence(path: string, parts: { requested?: unknown; permitted?: unknown; actual?: unknown; note?: string } = {}): FieldEvidence {
  return {
    path,
    ...(parts.requested !== undefined ? { requested: parts.requested } : {}),
    ...(parts.permitted !== undefined ? { permitted: parts.permitted } : {}),
    ...(parts.actual !== undefined ? { actual: parts.actual } : {}),
    ...(parts.note !== undefined ? { note: parts.note } : {}),
  };
}
export { evidence as fieldEvidence };

/** Recorded on a PERMIT whose authority credential's revocation was
 *  never checked, but whose policy explicitly, affirmatively opted in
 *  to accepting that (see `RevocationRequirement`). Never produced for
 *  any other reason, and never produced silently: its mere presence in
 *  `caveats` IS the record that this happened. */
export interface RevocationNotCheckedCaveat {
  readonly kind: "revocation-not-checked-accepted";
  readonly acknowledgedBy: string;
  readonly reason: string;
}

export type ExplanationCaveat = RevocationNotCheckedCaveat;

export type Explanation =
  | {
      readonly outcome: "permitted";
      readonly rule: RuleRef;
      readonly field: FieldEvidence;
      readonly narrative: string;
      readonly caveats: readonly ExplanationCaveat[];
    }
  | {
      readonly outcome: "refused";
      readonly refusalKind: RefusalKind;
      readonly rule: RuleRef;
      readonly field: FieldEvidence;
      readonly narrative: string;
      readonly caveats: readonly ExplanationCaveat[];
    };

export function permittedExplanation(
  rule: RuleRef,
  field: FieldEvidence,
  narrative: string,
  caveats: readonly ExplanationCaveat[] = [],
): Extract<Explanation, { readonly outcome: "permitted" }> {
  return { outcome: "permitted", rule, field, narrative, caveats };
}

export function refusedExplanation(
  refusalKind: RefusalKind,
  rule: RuleRef,
  field: FieldEvidence,
  narrative: string,
): Extract<Explanation, { readonly outcome: "refused" }> {
  return { outcome: "refused", refusalKind, rule, field, narrative, caveats: [] };
}

/**
 * Named structural gates: refusals (and one permit-time citation) that
 * are not about any single human-authored `PolicyRule`, but about a
 * fixed requirement of this project's design — most importantly
 * `GATE_AUTHORITY_REQUIRED`, the literal encoding of ADR 0002's "history
 * may tighten a decision but never loosen one; an authority credential
 * is always required for an action to be permitted". Every one of these
 * still satisfies "every decision names the rule that fired" — a
 * structural gate is still a rule, just not one a policy author wrote
 * down field-by-field, and naming it explicitly here (rather than
 * leaving `rule` blank for these cases) is what keeps that invariant
 * exceptionless.
 */
export const GATE_AUTHORITY_REQUIRED: RuleRef = {
  ruleId: "gate:authority-required",
  description:
    "an authority credential is always required for an action to be permitted; history attestations can never grant authority on their own, no matter how favourable (ADR 0002)",
};

export const GATE_CREDENTIAL_VERIFICATION: RuleRef = {
  ruleId: "gate:credential-verification",
  description: "the presented authority credential must pass lib/credentials's full verification chain (M3)",
};

export const GATE_ISSUER_TRUST: RuleRef = {
  ruleId: "gate:issuer-trust",
  description: "the credential's issuer must be a configured trust anchor, or vouched for by one (M4)",
};

export const GATE_REVOCATION: RuleRef = {
  ruleId: "gate:revocation",
  description: "a credential must not be revoked, and a revocation check that could not be confirmed is treated as fail-closed, exactly like a positive revocation (M4)",
};

export const GATE_REVOCATION_UNCHECKED: RuleRef = {
  ruleId: "gate:revocation-unchecked",
  description:
    "revocation must be checked before a credential is accepted, unless this policy's revocationHandling explicitly and justifiably opts in to accepting an unchecked credential",
};

export const GATE_ACTION_MATCH: RuleRef = {
  ruleId: "gate:action-match",
  description: "the requested action must equal the authority credential's own granted action",
};

export const GATE_NO_MATCHING_RULE: RuleRef = {
  ruleId: "gate:no-matching-rule",
  description: "this policy authors no action-scope rule for the credential's granted action — an unauthored action is refused, never silently permitted",
};

/** Citation for a bound that came from the authority credential's own
 *  scope, rather than from any authored `PolicyRule`. */
export const RULE_AUTHORITY_OWN_SCOPE: RuleRef = {
  ruleId: "credential:own-scope",
  description: "the presented authority credential's own granted scope",
};

/**
 * Render a human-readable sentence PURELY from `Explanation`'s
 * structured fields (never reading anything a consumer couldn't also
 * read) with `narrative` appended only as extra context — the
 * demonstration that the structured fields are the authoritative
 * artifact and the prose is derived from them, not the other way
 * around.
 */
export function renderExplanation(explanation: Explanation): string {
  const verdict = explanation.outcome === "permitted" ? "PERMITTED" : `REFUSED (${explanation.refusalKind})`;
  const values = [
    explanation.field.requested !== undefined ? `requested=${JSON.stringify(explanation.field.requested)}` : undefined,
    explanation.field.permitted !== undefined ? `permitted=${JSON.stringify(explanation.field.permitted)}` : undefined,
    explanation.field.actual !== undefined ? `actual=${JSON.stringify(explanation.field.actual)}` : undefined,
  ].filter((entry): entry is string => entry !== undefined);
  const valuesStr = values.length > 0 ? ` [${values.join(", ")}]` : "";
  const caveatsStr =
    explanation.caveats.length > 0
      ? ` (caveats: ${explanation.caveats.map((c) => `${c.kind} by ${c.acknowledgedBy} — ${c.reason}`).join("; ")})`
      : "";
  return `${verdict} — rule "${explanation.rule.ruleId}" (${explanation.rule.description}); field "${explanation.field.path}"${valuesStr}; ${explanation.narrative}${caveatsStr}`;
}

/** Re-exported so `engine.ts`'s history-constraint explanations can cite
 *  the triggering attestation's issuer without a separate import. */
export type { Did };
