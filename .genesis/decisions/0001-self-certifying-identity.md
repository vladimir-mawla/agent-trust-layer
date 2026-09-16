# ADR 0001 — Self-certifying identity with verifiable credentials

- **Date:** 2026-09-16
- **Status:** accepted
- **Phase / milestone:** G0.5 brainstorm, binds M1-M9

## Context
The brief asks for a trust layer for AI agents — reputation, verifiable credentials, and scoped
authority — judged on conceptual clarity, technical depth ("real signing/verification, not
vibes"), demo quality, failure thinking, and a two-year thesis, with bonus points for using or
extending DIDs and W3C Verifiable Credentials and for a cross-agent (not single-agent) demo. It
also carries two explicit disqualifiers: a reputation "score" with no underlying mechanism, and no
demo of a trust-gated decision. Any design that stores a number in a database and calls it trust
fails the brief outright. The decision that matters most, before any code is written, is where the
authority to say "this agent is who it claims to be, and is allowed to do this" actually lives —
in a service, in a shared ledger, or in the credential itself.

## Decision
Agents are identified by `did:key` — a DID whose identifier is derived directly from an Ed25519
public key — and every claim about an agent (its granted authority, its observed history) is a
W3C Verifiable Credential signed by an issuer's own `did:key`, so any party can verify a
presentation offline with no registry, network call, or third party in the loop.

## Consequences
- Positive: verification needs no infrastructure — the demo is fully deterministic, which matters
  for a 90-second, judge-run demo; DIDs + VCs are the brief's named bonus; the model composes
  cleanly with scoped, revocable authority credentials and separately with backward-looking
  history attestations, which is what keeps this a mechanism rather than a score.
- Negative / cost: revocation is not free with pure offline verification — it genuinely needs
  somewhere a verifier can look (a revocation list an issuer publishes), which is its own
  milestone (M4) rather than a byproduct of the identity model; key loss is unrecoverable by
  design, since the DID has no owner but the key itself.
- **Invariant added to context-graph.json:** `no-private-key-material-escapes` — a direct
  consequence of the private key being the entire identity; if it leaks, the identity is
  permanently compromised with no reset mechanism.

## Alternatives rejected
- Approach A, a central trust registry — why not: it IS the "score with no mechanism" the brief
  disqualifies, and it is a single point of trust and failure nobody outside the registry can
  verify.
- Approach C, on-chain attestations — why not: cost and latency make a 90-second demo painful, and
  the parts of the brief actually being judged (scope, delegation, policy) are unaffected by where
  the log lives, so the chain adds ceremony without adding clarity.

<!-- Copy this file to NNNN-<slug>.md for each irreversible decision.
     Then add a one-line pointer in implementation-notes.html "Decisions that bind". -->
