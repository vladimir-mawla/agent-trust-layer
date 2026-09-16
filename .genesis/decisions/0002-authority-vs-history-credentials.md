# ADR 0002 — Authority credentials and history attestations are structurally distinct types

- **Date:** 2026-09-17
- **Status:** accepted
- **Phase / milestone:** M3 BUILD (`lib/credentials/`)

## Context
M3 needs two kinds of claim about an agent: a forward-looking grant of authority ("Acme grants
agent X authority to buy up to $500 of office supplies until date D") and a backward-looking
observation of what an agent has actually done ("Acme observed agent X complete 47 transactions
with 0 disputes"). It would be easy — and wrong — to model both as "a signed claim with a JSON
payload" and let a policy engine (M5) decide at runtime which payloads it trusts as grants of
permission. That is exactly how a reputation "score" quietly regrows inside a system that claims
not to have one: if a history attestation can flow into the same code path an authority credential
flows into, nothing stops a big enough pile of good history from eventually being treated as
permission, which is precisely the "score with no mechanism" the brief disqualifies. The rule this
project commits to is: **history may tighten a decision but never loosen one** — an authority
credential is always required for an action to be permitted, and history can only narrow what an
already-granted authority allows.

## Decision
`AuthorityCredential` and `HistoryAttestation` (`lib/credentials/vc-types.ts`) are two separate
TypeScript interfaces with no common supertype a caller could hold instead of picking one, built so
that neither structurally satisfies the other in either direction:
- Their `type` tuples differ at a literal position (`["VerifiableCredential", "AuthorityCredential", ...]`
  vs. `["VerifiableCredential", "HistoryAttestation", ...]`), which alone makes them incompatible
  under TypeScript's structural typing.
- Their `credentialSubject` claim shapes differ in required fields with no overlap
  (`AuthorityClaim` needs `action`/`scope`; `HistoryClaim` needs `observationType`/`metrics`), so
  even a hypothetical loosening of the `type` tuple wouldn't reopen the hole.
- `AuthorityCredential.validUntil` is required (an authority credential that never expires isn't a
  stricter grant, it's a bug); `HistoryAttestation.validUntil` stays optional.
- Issuance is two distinct, differently-typed functions (`issueAuthorityCredential`,
  `issueHistoryAttestation`) — never a shared `issueCredential(kind: string, ...)` a caller could
  pass the wrong string to. Verification mirrors this: `verifyAuthorityCredential` and
  `verifyHistoryAttestation` each return a `VerificationResult` parameterised over their own type,
  and the "structure" step of the chain rejects a syntactically well-formed credential of the wrong
  kind before trusting anything else about it.
- `type-boundary.test.ts` proves this at compile time with a documented `@ts-expect-error`: passing
  a verified `HistoryAttestation` where a verified `AuthorityCredential` is required fails
  `npm run typecheck`, not just a runtime check a caller could skip.

M5's policy engine (not built yet) is the actual place the "tighten but never loosen" rule gets
enforced as *logic* — combining a verified authority credential with verified history to narrow its
scope. M3's job, and the only claim this ADR makes, is that the type system makes it impossible to
skip straight to "history alone" and have that compile where authority is required.

## Consequences
- Positive: the distinction the brief's judging criteria explicitly reward ("real mechanism, not a
  score") is enforced by the compiler for every future caller, including M5's own policy engine, not
  merely documented for a reviewer to notice is being followed today.
- Negative / cost: two credential kinds mean two issuance functions, two verification functions, and
  (necessarily) two sets of tests to keep in sync — there is no single generic `Credential<Kind>`
  shortcut, because a shortcut like that is exactly the shape that would let the two kinds mix.
- **Invariant added to context-graph.json:** none new required — this ADR is the concrete
  implementation of the existing `no-unverified-claim-reaches-policy` invariant's sibling concern
  (which credential *kind* reaches policy), not a new rule.

## Alternatives rejected
- A single `Credential` type with a `kind: "authority" | "history"` string field, discriminated only
  at runtime — why not: a caller (or a future M5 policy function) could still accept the union type
  and forget to narrow it before treating a claim as authority; the whole point is that this must be
  a compile error, not a discipline problem.
- Modeling history as authority with a permanently-empty `scope` ("history is just a credential that
  grants nothing yet") — why not: it keeps both on the same axis (grants of permission) and invites
  exactly the drift the brief warns against, where "grants nothing yet" quietly becomes "grants a
  little" once some scoring logic gets added on top.

<!-- Copy this file to NNNN-<slug>.md for each irreversible decision.
     Then add a one-line pointer in implementation-notes.html "Decisions that bind". -->
