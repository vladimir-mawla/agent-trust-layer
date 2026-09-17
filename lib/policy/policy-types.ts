/**
 * The declarative policy data model — M5's own analogue to
 * `lib/credentials/vc-types.ts`: types only, no evaluation logic (that
 * lives in `engine.ts`, `envelope.ts`, `history-constraints.ts`).
 *
 * ## Why declarative data, not imperative code
 *
 * A policy authored as a chain of `if`/`else` in TypeScript can only be
 * read by reading code — a human predicting what it will decide has to
 * mentally execute a program. A `Policy` value here is plain, JSON-
 * serialisable data (`JSON.stringify(policy)` round-trips through
 * `validatePolicy` — see that module): every field a human policy author
 * writes (`action`, `maxScope`, `observationType`, `threshold`, …) is
 * printable and diffable on its own, with no hidden control flow. This
 * is the concrete form of DONE.html's own framing of the cognitive job:
 * "the policy itself is authored by a human". `validatePolicy` is the
 * runtime boundary that re-checks this shape even when a `Policy` value
 * did NOT arrive through TypeScript's type checker at all (e.g. loaded
 * from a JSON config file) — see that module's comment for why a type
 * annotation alone is not enough here, the same reason M3/M4 never
 * trusted a bare parsed JWT payload just because a type said so.
 *
 * ## One unified, discriminated `rules` array
 *
 * A `Policy` has exactly one `rules` array holding a discriminated union
 * (`PolicyRule`, tagged by `kind`) rather than separate
 * `authorityRules`/`historyRules` arrays. Reading a policy top to bottom
 * — one ordered list — is what makes "someone should be able to look at
 * a policy and predict what it will decide" true in practice: an
 * `"action-scope"` rule grants nothing by itself (that authority comes
 * only from a verified `AuthorityCredential` — see `envelope.ts`) and
 * merely places a human-authored ceiling on what a credential's own
 * scope is allowed to permit; a `"history-narrow"` rule can ONLY ever
 * tighten that ceiling further — its own type has no field that could
 * express a grant (no `minScope`, no "widen" direction at all, only
 * `narrowedMax`) — see the module comment on `history-constraints.ts`
 * and `type-boundary.test.ts` for the structural (not just conventional)
 * enforcement of "history may tighten a decision but never loosen one"
 * (ADR 0002).
 */
import type { Did } from "../identity/index.js";

/** Discriminant for an authored rule that places a numeric ceiling on an
 *  authority credential's own scope for a given action. */
export const ACTION_SCOPE_RULE_KIND = "action-scope" as const;
/** Discriminant for an authored rule that can further NARROW an
 *  action-scope ceiling, triggered by an observed history metric. Never
 *  a grant — see the module comment. */
export const HISTORY_NARROW_RULE_KIND = "history-narrow" as const;

/** How a `HistoryNarrowRule`'s `metric` is compared against its
 *  `threshold` to decide whether the narrowing fires. Plain data, not a
 *  callback, so a `HistoryNarrowRule` stays JSON-serialisable. */
export type ComparisonOperator = "lte" | "lt" | "gte" | "gt" | "eq";

/**
 * A human-authored ceiling on what an authority credential's own scope
 * is allowed to permit for one action. This is a CAP, never a grant: if
 * the credential itself grants less than `maxScope` says, the
 * credential's own (tighter) value still wins — see `permitted-scope.ts`'s
 * `computeFieldBound`, which always takes the MINIMUM across every
 * source that names a bound for a field, never the maximum.
 */
export interface ActionScopeRule {
  readonly kind: typeof ACTION_SCOPE_RULE_KIND;
  /** Stable identifier a human can cite ("rule R-014 fired"). */
  readonly id: string;
  /** Human-readable prose describing intent — shown verbatim in
   *  explanations, never parsed by the engine. */
  readonly description: string;
  /** The action this rule governs. Exactly one `action-scope` rule may
   *  govern a given action within one policy — `validatePolicy` throws
   *  `PolicyContradictionError` for a second one, since two rules for
   *  the same action with no ordering rule between them is genuinely
   *  ambiguous, not just inconvenient. */
  readonly action: string;
  /** Numeric ceilings, keyed by the `AuthorityClaim.scope` field they
   *  bound (e.g. `{ maxAmount: 500 }`). Only numeric fields are
   *  supported — see DELIBERATE_OMISSIONS in the M5 report for why
   *  non-numeric scope dimensions are out of scope for this milestone. */
  readonly maxScope: Readonly<Record<string, number>>;
}

/**
 * A human-authored rule that narrows an `ActionScopeRule`'s ceiling for
 * one `scopeField`, triggered when a VERIFIED, ACCEPTED history
 * attestation's `metrics[metric]` satisfies `operator`/`threshold`
 * against `action`/`observationType`. There is deliberately no field
 * here (or anywhere in this module) that could express "grant more than
 * the authority credential itself allows" — `narrowedMax` can only ever
 * be compared against existing bounds with `Math.min`, never `Math.max`
 * — see `history-constraints.ts` and `permitted-scope.ts`.
 */
export interface HistoryNarrowRule {
  readonly kind: typeof HISTORY_NARROW_RULE_KIND;
  readonly id: string;
  readonly description: string;
  /** Which authority action this narrowing applies to — must match an
   *  `ActionScopeRule.action` to ever have an effect, but a policy is
   *  still valid (just inert for this rule) if it doesn't. */
  readonly action: string;
  /** Which `HistoryClaim.observationType` this rule watches. */
  readonly observationType: string;
  /** Which `HistoryClaim.metrics` key this rule reads. */
  readonly metric: string;
  readonly operator: ComparisonOperator;
  readonly threshold: number;
  /** Which `AuthorityClaim.scope` field gets narrowed when this rule
   *  fires. */
  readonly scopeField: string;
  /** The tightened ceiling applied to `scopeField` when this rule fires.
   *  Always combined with every other bound via `Math.min` — see
   *  `permitted-scope.ts`. Setting this HIGHER than the authority
   *  credential's own scope (or any `ActionScopeRule` ceiling) has
   *  exactly zero effect, by construction, not by convention: that is
   *  this module's runtime proof that history cannot widen an envelope
   *  (see `type-boundary.test.ts`). */
  readonly narrowedMax: number;
}

export type PolicyRule = ActionScopeRule | HistoryNarrowRule;

/**
 * How this policy handles an authority credential whose revocation was
 * never checked (`TrustDecision.revocation.outcome === "not-checked"`,
 * i.e. the caller of `lib/trust` never supplied `credentialStatus`/
 * `statusListResolver` — see `RevocationNotChecked`'s warning comment in
 * `lib/trust/trust-decision.ts`, which names this exact gap as "M5's
 * problem").
 *
 * Scope, precisely: this gate governs the AUTHORITY credential only —
 * `engine.ts`'s `GATE_REVOCATION_UNCHECKED` never consults it for a
 * `HistoryTrustDecision`, and `history-constraints.ts` narrows a ceiling
 * identically whether or not a history attestation's own revocation was
 * checked. That is deliberate, not an oversight: see
 * `history-constraints.ts`'s module comment (FINDING 6, L4 M5 review) for
 * why extending this gate to history would make the engine MORE
 * permissive, not more cautious — backwards for a tighten-never-loosen
 * design.
 *
 * This is a REQUIRED field of `Policy` (see below), not an optional flag
 * on the evaluation call, and not a boolean. Three deliberate choices,
 * each closing a way M4's own bypass (an omitted, forgettable argument)
 * could recur here:
 *
 *   1. **Required, not optional.** `validatePolicy` throws
 *      `PolicyMalformedError` if a policy omits this field entirely —
 *      omission fails closed at the POLICY-LOADING boundary, before any
 *      request is ever evaluated, rather than silently defaulting to
 *      "accept unchecked" the moment nobody bothered to set it.
 *   2. **The easy, one-field value IS the strict one.**
 *      `{ requireChecked: true }` is the trivial, obvious thing to write
 *      — "defaulting to mandatory" isn't an implicit fallback the code
 *      supplies for you, it's simply the shortest valid value a policy
 *      author can write.
 *   3. **The permissive value cannot be a bare `true`/`false` flip.** To
 *      allow an unchecked credential through, an author must write
 *      `requireChecked: false` AND supply `acknowledgedBy` and `reason`
 *      — two required sibling fields with no default — so the choice is
 *      visible both in the policy's own printed/diffed form (this is a
 *      POLICY input, authored data, not a hidden call-site default) and
 *      in the resulting `Explanation`'s `caveats` (see `explanation.ts`),
 *      which records exactly who acknowledged the risk and why whenever
 *      a decision actually relied on it.
 */
export type RevocationRequirement =
  | { readonly requireChecked: true }
  | {
      readonly requireChecked: false;
      /** Free text naming who/what made this call — e.g. an operator's
       *  name, a ticket id, a role. Never used by the engine for
       *  anything but recording it back in the explanation. */
      readonly acknowledgedBy: string;
      /** Why this policy accepts an unchecked credential for this
       *  action (e.g. "no status list infra yet for this low-risk
       *  action class"). */
      readonly reason: string;
    };

export interface Policy {
  readonly id: string;
  readonly version: string;
  readonly rules: readonly PolicyRule[];
  readonly revocationHandling: RevocationRequirement;
}

/** What a counterparty is asking to do. Plain data — no verification
 *  claims live here, only the free-form request being checked against
 *  what was verified elsewhere (`lib/trust`). */
export interface PolicyRequest {
  readonly action: string;
  readonly scope: Readonly<Record<string, unknown>>;
}

/** Re-exported for callers building `credentialSubject.id`-shaped
 *  evidence in a `FieldEvidence` without importing `lib/identity`
 *  directly. */
export type { Did };
