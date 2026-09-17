# ADR 0004 — Declarative rules, structured explanations, and a mandatory revocation gate for the policy engine

- **Date:** 2026-09-17
- **Status:** accepted
- **Phase / milestone:** M5 BUILD (`lib/policy/`)

## Context

M3 answers "is this credential authentic?"; M4 answers "is it still valid, and is its issuer
trustworthy?". Neither answers the only question that matters to a counterparty: given everything
verified, may this agent do this specific thing right now — and why? That is M5's whole job, and
the brief is explicit that the answer must never degrade into "a score" — a number, however
computed, that stands in for a real accept/refuse mechanism. Two design tensions had to be settled
before writing any evaluation logic:

1. **How is a policy expressed?** A policy encoded as nested `if`/`else` in TypeScript can only be
   read by mentally executing a program — a human predicting what it will decide has no artifact to
   read except code. DONE.html's own locked spec says "the policy itself is authored by a human";
   that only holds if a policy is something a human (or a diff tool) can actually read.
2. **How does history's role stay bounded, structurally?** ADR 0002 already split
   `AuthorityCredential` and `HistoryAttestation` into structurally distinct types specifically so
   that "history may tighten a decision but never loosen one" could not be violated by a caller
   forgetting to check which kind of credential it was holding. M5 is where that rule actually gets
   exercised as *logic* — combining an authority credential's own granted scope with observed
   history to (possibly) narrow it. If the combination step re-opens a path for history to expand
   what's permitted, the type-level work of ADR 0002 doesn't matter: the reputation-score hole the
   brief disqualifies would simply move one layer up, into the one module (`lib/policy`) whose
   entire purpose is to prevent exactly that.

A third, narrower problem was carried forward explicitly from M4's own verification: M4's
`RevocationNotChecked` result (`lib/trust/trust-decision.ts`) can produce `accepted: true` for a
credential whose revocation was never actually checked, and that module's own comment names this as
"M5's problem" — a caller who omits `credentialStatus`/`statusListResolver` must not have that
omission silently read downstream as "verified clean".

## Decision

**1. A `Policy` is plain, JSON-serialisable data — one discriminated `rules` array, not two.**
`lib/policy/policy-types.ts`'s `Policy` holds a single `rules: readonly PolicyRule[]`, where
`PolicyRule` is a union of `ActionScopeRule` (`kind: "action-scope"` — a human-authored numeric
ceiling on one action's scope) and `HistoryNarrowRule` (`kind: "history-narrow"` — a rule that can
tighten an `ActionScopeRule`'s ceiling when a specific, verified history metric crosses a
threshold). Every field a human author writes — `action`, `maxScope`, `observationType`,
`operator`, `threshold`, `narrowedMax` — is data: no callback, no embedded function, nothing that
resists `JSON.stringify`. `validatePolicy` (`lib/policy/validate.ts`) is the runtime boundary that
re-checks this shape even for a `Policy` that never passed through TypeScript's own checker (loaded
from a config file, say) — the same reasoning M3/M4 already applied to credentials arriving as
JSON, applied here to the policy itself, which is just as much untrusted input the moment it
crosses a real boundary. `evaluatePolicyRequest`'s own `policy` parameter is typed `unknown`
specifically so this validation cannot be skipped by construction — see `engine.ts`.

**2. History can only ever narrow, enforced by a TYPE gate and an ARITHMETIC gate, not by
convention.** Two separate, independently-checked mechanisms combine to make "history widens an
envelope" impossible rather than merely discouraged:
   - **Gating:** `computeAuthorityEnvelope` (`envelope.ts`) — the only function in this module
     allowed to originate a permitted envelope — takes
     `TrustDecision<AuthorityCredential> & { accepted: true }` as its parameter, never
     `HistoryTrustDecision`, never a union of the two. Because `TrustDecision<C>`/
     `HistoryTrustDecision` (`lib/trust/trust-decision.ts`) each wrap M3's `VerificationSuccess<C>`
     generic over ADR 0002's already-structurally-distinct credential kinds, a `HistoryTrustDecision`
     cannot satisfy this parameter's type in either direction — `type-boundary.test.ts` proves this
     with a documented `@ts-expect-error`, the same pattern `lib/credentials/type-boundary.test.ts`
     and `lib/trust/type-boundary.test.ts` already established for ADR 0002 and the `Vouch`
     identity/authority split. `engine.ts` calls `computeAuthorityEnvelope` ONLY after confirming
     `authority !== null && authority.accepted === true` — if no authority credential was ever
     presented and accepted, this function is never invoked at all, which is how "history
     attestations present but no authority → still refused" holds structurally rather than by the
     engine happening to check things in the right order.
   - **Arithmetic:** once an envelope exists, `permitted-scope.ts`'s `computeFieldBound` combines
     every source that names a bound for one scope field — the credential's own scope value, an
     `ActionScopeRule`'s ceiling, and any triggered `HistoryNarrowRule`s (`history-constraints.ts`)
     — with `Math.min`, exclusively. A `HistoryNarrowRule.narrowedMax` set higher than the existing
     bound has, and can only ever have, zero effect — there is no code path where a history value
     is compared with `Math.max` or otherwise allowed to override a tighter existing bound.
     `type-boundary.test.ts` exercises this at runtime with a deliberately-oversized `narrowedMax`
     (10,000,000 against a credential's own scope of 500) and asserts the effective bound is
     unchanged.
   - **Arithmetic, corrected:** the combinator now uses the REAL, literal
     `Math.min` (`Math.min(...candidates.map(c => c.value))`), not the
     hand-rolled `<`-comparison `reduce` this ADR originally described.
     They are not the same function: real `Math.min` poisons to `NaN`
     unconditionally the instant any candidate is non-finite, while the
     `reduce` only poisoned when the non-finite candidate happened to be
     FIRST — for any other position it silently kept a finite-but-not-
     actually-tighter candidate instead, discarding a genuinely
     non-finite bound rather than surfacing it. `engine.ts` now also
     explicitly refuses (never permits) when `computeFieldBound`'s
     returned bound, or the request's own value, is not finite — a
     `NaN`/`Infinity` ceiling compared with `>` would otherwise read as
     "never over scope", i.e. an unconditional permit. See the L4 M5
     review amendment below (FINDING 3 / FINDING 8).

**3. The mandatory revocation gate is a required, justified field of the POLICY, not an optional
call-site flag.** `Policy.revocationHandling: RevocationRequirement` is REQUIRED — `validatePolicy`
throws `PolicyMalformedError` if it's missing, so omission fails closed at the policy-LOADING
boundary, before any request is evaluated. Its type has exactly two shapes: `{ requireChecked: true
}` (the trivial, obvious value to write — "defaulting to mandatory" is simply the shortest valid
policy, not an implicit fallback the code supplies) or `{ requireChecked: false, acknowledgedBy,
reason }` (both sibling fields required, no default) — a caller who wants to accept an unchecked
credential cannot flip a bare boolean and move on; they must write down who decided this and why.
When a decision relies on that opt-in, `Explanation.caveats` records
`{ kind: "revocation-not-checked-accepted", acknowledgedBy, reason }` — never silently folded into
an ordinary "accepted" explanation. This mirrors exactly the shape of M4's own fix for its critical
bypass (`expectedIssuer` promoted from optional to a required parameter in `checkRevocation`) —
applied here one layer up, to the policy author's decision rather than a function call's argument,
because THIS decision ("should this policy ever accept an unchecked credential") is a human policy
choice, not an implementation detail a function caller should be trusted to remember.

**4. Every decision is a discriminated `PolicyDecision` whose `explanation` is structured data,
never a bare boolean.** `Explanation` (`explanation.ts`) names `outcome`, and for a refusal, one of
nine distinct `RefusalKind`s (`no-authority-credential`, `credential-verification-failed`,
`untrusted-issuer`, `revoked`, `revocation-not-checked`, `wrong-action`, `no-matching-rule`,
`over-scope`, `history-constraint`) — each produced by exactly one code path in `engine.ts`, never
inferred after the fact. Every `Explanation` also names `rule` (the authored `PolicyRule` that
fired, OR one of this module's own named structural gates, e.g. `GATE_AUTHORITY_REQUIRED` — a
structural refusal is still a rule firing, and is named as one) and `field` (the exact credential/
request field, with `requested`/`permitted`/`actual` values attached — an over-scope refusal always
carries both the requested and permitted numbers, never a prose "insufficient authority").
`renderExplanation` builds its human-readable sentence purely from these structured fields (with the
supplementary `narrative` string appended only as extra context), proving the structured data is
the authoritative artifact a future consumer (M6's demo, M8's UI) should render from, not a prose
string with fields glued on after the fact.

**5. M3's "parse" step label ambiguity is recovered, without editing M3.** `verify.ts` reports both
"the JWS itself is malformed" (pre-signature) and "a real signature verified over non-JSON bytes"
(post-signature — a materially stronger attack signal) as the identical `step: "parse"`, by its own
deliberate design. `verification-step-detail.ts`'s `refineParseFailure` recovers the distinction for
M5's explanations by matching the exact, pinned message `decodeVerifiedPayload` uniquely produces
(`"payload is not valid JSON"`) — confined to enriching an explanation's `field.note`, never used to
change any accept/refuse outcome, and tested against a genuinely fabricated signed-non-JSON JWS so a
future change to that message fails this module's own test rather than silently losing the
distinction again.

**6. An omitted-but-bounded scope field is refused, not treated as zero
usage.** `evaluatePolicyRequest` evaluates the UNION of fields named by
the authority credential's own scope, the matching `ActionScopeRule`'s
`maxScope`, and any triggered `HistoryNarrowRule`'s `scopeField` — never
merely the fields the incoming `PolicyRequest.scope` happens to mention.
A field this engine knows a bound for, that the request does not supply
a numeric value for, is treated as an UNBOUNDED, unverifiable request for
that dimension and refused (`over-scope`/`history-constraint`, matching
whichever source names the tightest bound) — never silently read as "0 /
not requested, therefore fine". The alternative reading ("omitted means
zero, permit") was rejected because it is exactly the shape of a bypass:
a counterparty could omit precisely the field it would be limited on and
receive an unconditional permit without the credential's own ceiling ever
being consulted. See the L4 M5 review amendment below (FINDING 4).

## Consequences

- Positive: a policy is printable, diffable, and predictable by reading — the exact property the
  brief's "conceptual clarity" judging criterion rewards. History cannot become a de facto
  reputation score no matter how a policy is authored (a malicious or merely careless
  `narrowedMax` has zero effect if it isn't actually tighter), closing the gap ADR 0002 opened but
  didn't itself have logic to exercise. The revocation gap M4's own verification flagged as
  unresolved is closed at the policy-authoring layer, with the same "promote to required, never
  leave an optional argument a caller can forget" fix that closed M4's own critical bypass.
- Negative / cost: `Policy`'s numeric-only scope-bound checking (`ActionScopeRule.maxScope`,
  `HistoryNarrowRule.narrowedMax`) does not attempt to bound non-numeric scope dimensions (a string
  enum field, say) — see DELIBERATE_OMISSIONS in the M5 report. `validatePolicy` re-validates a
  policy's full shape on every call from `evaluatePolicyRequest`, trading a small amount of
  per-request CPU for the guarantee that a hand-mutated or JSON-sourced `Policy` object can never
  bypass validation by virtue of already having the right TypeScript type.
- **Invariant added to context-graph.json:** none new required — this ADR is the concrete
  implementation of `no-unverified-claim-reaches-policy` (the engine's own input types admit only
  `TrustDecision`/`HistoryTrustDecision`, never a raw claim) and `every-decision-is-explainable`
  (this ADR's point 4) for M5's own slice, plus the concrete enforcement of ADR 0002's "history may
  tighten but never loosen" as actual logic rather than merely a type split.

## Amendment — L4 VERIFY review findings (2026-09-17, `m5-policy-fixes`)

An independent L4 VERIFY pass REJECTED the M5 build this ADR originally
described, on six findings. All six are fixed; this amendment records
what changed so the ADR's own claims stay true of the code:

- **FINDING 1 (critical):** `evaluatePolicyRequest`'s `authority`/
  `history` parameters are typed as trusted `TrustDecision`/
  `HistoryTrustDecision` values, but — exactly as this ADR's own
  "claims arrive as JSON, not TypeScript" framing implies — a value
  crossing a real serialization boundary is not bound by that type. Before
  this fix, anything other than literal `null` for `authority` (or any
  malformed `history` entry once a `history-narrow` rule existed to
  iterate into it) threw a bare, unhandled `TypeError` — the same class
  of defect ADR history already rejected once for M3. Fixed with
  `lib/policy/decision-guards.ts`: a runtime shape check, at the engine
  boundary, that treats anything which isn't a well-formed decision
  exactly as if it were absent (`null` for authority, filtered out of
  `history`) — fail closed, always a structured `PolicyDecision`, never a
  throw.
- **FINDING 2 (high):** the tighten-never-loosen combinator
  (`computeFieldBound`) was validated by coincidence — mutating it to
  `return candidates[0]` broke only 1 of 196 tests, and not the dedicated
  runtime proof in `type-boundary.test.ts` (whose fixture happened to
  have the first-pushed candidate already be the tightest). Fixed by
  adding `lib/policy/permitted-scope.test.ts` (fixtures where each of the
  three bound sources is tightest in a non-first position) and
  strengthening the dedicated proof test itself with a genuinely-tighter
  case. The same mutation now breaks 9 of 225 tests, including that
  proof test.
- **FINDING 3 (high):** see decision 2's "Arithmetic, corrected" bullet
  above and decision 6 above.
- **FINDING 4 (high):** see decision 6 above.
- **FINDING 5 (medium):** `credential-verification-failed` — one of the
  nine `RefusalKind`s — had zero test coverage despite being reachable.
  Added a test reaching it through the real `evaluateAuthorityCredentialTrust`
  path with a malformed JWT.
- **FINDING 6 (medium):** the mandatory revocation gate
  (`GATE_REVOCATION_UNCHECKED`) covers the authority credential only —
  `computeHistoryConstraints` never inspects a `HistoryTrustDecision`'s
  `revocation.outcome`, so an unchecked-revocation history attestation
  narrows a ceiling exactly like a checked-and-clean one. Reviewed
  deliberately and kept as-is, now documented in `history-constraints.ts`
  and `policy-types.ts`: because history can only ever narrow, the worst
  an unverifiable history observation can do is cause an unearned
  REFUSAL (a false negative), never an unearned permit (a false
  positive) — extending the mandatory-checked gate to history would make
  the engine MORE permissive whenever a history attestation's revocation
  happens not to have been checked, which is backwards for a
  tighten-never-loosen design. A regression test
  (`history-constraints.test.ts`) makes this explicit rather than merely
  documented.

## Alternatives rejected

- **A single `Credential`-shaped "evidence" list scored by weight, with a threshold to permit** —
  why not: this is precisely the "score with no mechanism" the brief disqualifies, and it cannot
  express "wrong action" or "over scope" as distinct, named refusals at all — everything collapses
  into a single number crossing (or not) a cutoff, which is exactly the failure mode ADR 0001/0002
  already rejected this project's whole design around.
- **`RevocationRequirement` as an optional parameter to `evaluatePolicyRequest` (defaulting to
  `requireChecked: true` when omitted)** — why not: an optional parameter with a safe default is
  still a parameter a caller can forget, and forgetting it would be invisible at the call site
  (the exact shape of M4's own critical bypass, before `expectedIssuer` was made required).  Making
  it a required field of the authored `Policy` instead means a missing value fails to VALIDATE, not
  just silently falls back — and keeps the choice visible in the one artifact ("the policy") a human
  is actually meant to read and diff.
- **Modelling history narrowing as a callback function on `HistoryNarrowRule`
  (`constrain: (metrics, requestedScope) => Constraint | null`)** — why not: a function value is not
  JSON-serialisable, so a policy carrying one could no longer be loaded from a config file, printed,
  or diffed — reintroducing the "policy as code" problem this ADR's whole first decision exists to
  avoid, for a narrowing rule that a small, fixed vocabulary of comparison operators
  (`lte`/`lt`/`gte`/`gt`/`eq`) already expresses without it.

<!-- Copy this file to NNNN-<slug>.md for each irreversible decision.
     Then add a one-line pointer in implementation-notes.html "Decisions that bind". -->
