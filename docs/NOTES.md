# Notes

## AI tools used

The whole project — code, tests, ADRs, and this M9 documentation pass itself —
was built with [Claude Code](https://claude.com/claude-code) running Claude
models (Opus 5 and Sonnet 5), using a loop-based process ("genesis-kit") that
keeps two roles structurally separate: an **L1 BUILD** agent writes the code
and tests for one milestone, and a **different agent invocation** runs **L4
VERIFY** against it — reading the diff, running mutation tests, and
attacking the feature rather than reviewing the description of it. Nothing
in this project is marked done in [`.genesis/DONE.html`](../.genesis/DONE.html)
without both passes and the user's own sign-off.

This document, `docs/ARCHITECTURE.md`, and `docs/THESIS.md` started from two
drafts the user had already written. Building them meant checking every
"refuses" line in the architecture draft against a real, passing test before
committing it — and finding, in the process, one line that didn't hold up
(see below).

## Key design decisions, and why

Full reasoning lives in the ADRs; this is the two-sentence version of each.

- **`did:key` + Ed25519** ([ADR 0001](../.genesis/decisions/0001-self-certifying-identity.md)):
  the identifier is the public key, so verification needs no registry, no
  network call, and no third party — which is also what makes a 90-second,
  judge-run demo fully deterministic.
- **Authority credentials and history attestations as structurally distinct
  types** ([ADR 0002](../.genesis/decisions/0002-authority-vs-history-credentials.md)):
  the brief disqualifies a reputation score, and a score is exactly what
  reappears if a big enough pile of good history can ever be read as
  permission. Making the two types structurally unable to satisfy each
  other's position closes that path at compile time, not by convention.
- **W3C Bitstring Status List for revocation** ([ADR 0003](../.genesis/decisions/0003-bitstring-status-list-revocation.md)):
  the one check that cannot be offline gets exactly one function in `lib/`
  that performs network I/O, an injected (never owned) resolver, and a
  fail-closed default — unreachable, unverifiable, stale, or wrong-issuer
  all mean "revoked," never "fine."
- **Policies as plain JSON data, bounds combined with `Math.min` alone**
  ([ADR 0004](../.genesis/decisions/0004-declarative-policy-engine.md)):
  a policy a human can read and diff, and a narrowing rule that cannot
  structurally widen a ceiling no matter what a policy author writes into it.

## Deliberately out of scope

Named plainly, not hidden in a caveat:

- **No general signed range.** Every bound in `lib/policy` is a `maxX`-style
  ceiling. M7's fix refuses negative scope values outright rather than
  building a real lower bound (`minScope`) or a signed range — a `maxX`
  ceiling has no defined semantics for "how negative is too negative," so
  refusing any negative value is the correct narrow fix, not a substitute
  for the more general feature.
- **No non-numeric scope bounds.** A string-enum scope field (e.g. an
  allowed vendor list) is not checked by `ActionScopeRule`/`HistoryNarrowRule`
  today — only numeric fields are bounded.
- **No rate-limiting on failed proof-of-possession attempts.** Consuming a
  challenge nonce only happens on a *successful* answer; an attacker gets
  unlimited free retries against a live challenge before it expires. This is
  a deployment concern (a reverse proxy, a WAF) deliberately left outside a
  protocol library.
- **No DID method other than `did:key`.** No `did:web`, no `did:ion`, no
  resolution against a registry of any kind.
- **No delegation beyond depth-1 vouching.** `VOUCH_DEPTH_LIMIT = 1` is a
  fixed constant, not a configurable policy. A vouches-for-a-voucher chain is
  refused, not walked.
- **No shared or persistent nonce store.** Single-use challenge tracking
  lives in one `Supplier` instance's memory. See the README's "Honest
  limits" section — this is a real, load-bearing gap for a stateless
  deployment, not a rounding error.

## The genesis process: reject, fix, re-verify

Every milestone was built by one agent and verified independently by
another, and the record of that is kept in the repository itself — commit
messages, ADR amendments, and (from M5 onward) pull request bodies — rather
than only in a transcript nobody else can read.

At least **six of the eight milestones built before this one needed a real
fix in direct response to independent verification** before being marked
done. Four of those were formal rejections with their own re-verification
cycle: M3, M4, M5, and M6 (M6 twice — its second fix round introduced two
new defects of its own, caught by a *third* verification pass). The other
two, M1 and M2, each had one verifier-found finding fixed before the
mark-done commit. Two concrete examples, because "rejected for a real
defect" is a claim worth backing with specifics rather than a bare count:

- **M4 — a revocation bypass that needed no compromised key at all.**
  `checkRevocation` verified that a resolved status list was internally
  self-consistent, but never checked it actually came from the credential's
  *own* issuer. A credential correctly revoked by its real issuer was still
  **accepted** if the resolver instead returned an unrelated, throwaway-key-
  signed "clean" list for the same URL. Fixed by making the expected issuer
  a required parameter — a caller cannot forget it and have the compiler
  stay silent. (ADR 0003, "Amendment — L4 VERIFY findings.")
- **M5 — an authorization bypass hiding behind 31 passing tests.** The
  bound-checking loop iterated the fields present in the *request*, so
  `{ action: "purchase", scope: {} }` against a `maxAmount: 500` ceiling
  returned an unconditional permit — the credential's own granted scope was
  never consulted. Fixed by evaluating the union of every field named by the
  credential, the matching rule, or a triggered history rule; an omitted-but-
  bounded field now reads as unbounded and is refused. (ADR 0004, Finding 4.)

This record is treated here as a strength, not something to smooth over: the
whole point of a separate verifier is to catch what the builder's own tests
didn't, and on this project it did, repeatedly, on real defects rather than
style nits.
