# ADR 0003 — W3C Bitstring Status List v1.0 for revocation, trust anchors composed over M3

- **Date:** 2026-09-17
- **Status:** accepted
- **Phase / milestone:** M4 BUILD (`lib/trust/`)

## Context
M3's own verification chain (`lib/credentials/verify.ts`) proves a credential is internally
consistent and correctly signed, and explicitly stops there: `VerificationSuccess.revocationChecked`
is typed as the literal `false`, and `verification-result.ts`'s own comment says plainly that
`ok: true` is "NOT that the issuer is trustworthy". M3's L4 verification made this concrete with a
real attack: a fully self-consistent credential — attacker's own DID as `kid`/`iss`/`issuer`, a
real signature, granting themselves $1,000,000 — passes M3's entire chain and returns `ok: true`.
Two questions were deliberately left open for M4: **is a credential still valid** (it could have
been revoked since issuance), and **why should this issuer be believed at all** (cryptographic
self-consistency is not trustworthiness). This ADR is about the first question and the tension it
exposes; ADR 0001 already anticipated it ("revocation is not free with pure offline verification").

Revocation is fundamentally different from every other check in this project. Signature validity,
expiry, and subject binding are all statements that can be settled the moment a credential is
signed, using only bytes the verifier already has. "Has this been revoked" is a statement about
**now**, made by a party other than the verifier, and no signature produced in the past can attest
to a fact that keeps changing after it was produced. Closing this gap necessarily means asking
someone — the only question is how cheaply, and how privately.

## Decision
Implement **W3C Bitstring Status List v1.0** (`https://www.w3.org/TR/vc-bitstring-status-list/`):
an issued credential carries a `credentialStatus` entry (`type: "BitstringStatusListEntry"`,
`statusPurpose`, `statusListIndex`, `statusListCredential`) naming a single bit's position inside a
separately-published, separately-signed `BitstringStatusListCredential` whose `credentialSubject`
carries a GZIP-compressed, multibase-base64url-encoded bitstring (`encodedList`). A verifier fetches
that one shared list (via an injected, non-owned `resolver` — no real network I/O lives in `lib/`),
verifies **its own signature and its own freshness** exactly like any other credential (reusing the
same fail-closed posture, not new crypto), and reads one bit.

The offline/network tension is made structural, not just documented: `checkRevocation`
(`lib/trust/status-list.ts`) is the **only** async function anywhere under `lib/`, and the only
function that takes a network-shaped resolver callback. Every other check in this project — M1's
proof of possession, M3's signature/temporal/subject-binding/issuer-identity chain, M4's own
self-issued/anchor/vouch checks — stays synchronous. `grep -n "async" lib/` names exactly where the
network dependency lives, and nowhere else.

**Fail-closed, with an explicit, configurable staleness bound:** a status list that is unavailable
(resolver throws/rejects), unverifiable (bad signature, unresolvable issuer), malformed, or older
than `maxStatusListAgeMs` is treated as `{ outcome: "indeterminate" }` — refused, exactly like an
explicit `{ outcome: "revoked" }` bit, never as "fine, I couldn't check". `DEFAULT_MAX_STATUS_LIST_AGE_MS`
is 5 minutes: roughly 5x `lib/credentials`'s `DEFAULT_CLOCK_SKEW_MS` (60s), deliberately not reused,
because clock skew bounds disagreement between two clocks about the same instant — a much tighter
thing than "how old can a cached network resource be before it stops being evidence about now". Five
minutes tolerates ordinary fetch/verify latency and a realistic issuer refresh cadence without
tolerating a captured "everything was fine" snapshot being replayed for long. It is a parameter, not
a hardcoded constant, so a caller with different freshness needs can override it — the fail-closed
DIRECTION is not configurable, only the threshold.

## Consequences
- Positive: herd privacy is preserved by construction — fetching the shared bitstring reveals
  nothing about which single credential a verifier cared about, satisfying the brief's own framing
  of why this spec (over a plain revoked-ID list) matters. Revocation reuses M3's cryptographic
  machinery (compact JWS, Ed25519, did:key) with zero new trust primitives, so the fail-closed
  posture that already survived M3's own L4 review carries over rather than being reinvented.
  `checkRevocation`'s resolver injection keeps `lib/` deterministic and network-free in tests, the
  same offline-testability property ADR 0001 built the whole identity model around.
- Negative / cost: this milestone genuinely cannot be demoed with zero network dependency the way
  M1/M3 could — a real deployment needs somewhere to publish and fetch the status list credential
  from, and a verifier's trust in "not revoked" is only as fresh as its last successful fetch within
  `maxStatusListAgeMs`. An issuer who cannot publish (outage, compromised hosting) cannot signal
  "still fine" either — by design, since the alternative (assume fine when unreachable) is exactly
  the hole a fail-closed system must not have.
- **Invariant added to context-graph.json:** none new required — this ADR is the concrete
  implementation of the existing `every-decision-is-explainable` invariant for the one check
  (revocation) that needed a genuinely new kind of failure (network-shaped, not merely
  cryptographic) to explain.

## Alternatives rejected
- **A plain list of revoked credential IDs, fetched and matched by ID** — why not: fetching "is ID
  #94567 revoked?" (or downloading the whole ID list to check locally) tells the issuer's endpoint,
  or anyone watching the request, exactly which credential a verifier is deciding about right now.
  The Bitstring Status List's whole value proposition — fetch one shared resource, reveal nothing
  about which bit you actually needed — is precisely the property a per-ID list throws away. It is
  also not a standards-track W3C mechanism, forfeiting this project's stated bonus for extending
  W3C VC machinery rather than inventing an ad hoc one.
- **Short-lived credentials only, no revocation mechanism at all** ("just expire authority
  quickly and re-issue") — why not: it does not actually answer "is this still valid" for the
  window before expiry, it only shrinks that window. An agent granted authority for even five
  minutes that turns out to be compromised in minute one is still unrevocable under this scheme
  until it naturally expires; a real incident response need ("cut this off NOW") has no mechanism
  at all, which is a materially weaker guarantee than a status list a compromised-key holder cannot
  suppress once the issuer has published it. Shortening `validUntil` is a real, complementary
  mitigation this project already has via ADR 0002's mandatory authority expiry — but it is not a
  substitute for revocation, it is a bound on how bad "no revocation" can get.
- **Extending `lib/credentials/verification-result.ts`'s `revocationChecked` from the literal
  `false` to a real, computed status inside `verify.ts` itself** — why not: `verifyAuthorityCredential`/
  `verifyHistoryAttestation` are synchronous and all 57 of M3's existing tests call them that way;
  actually filling that field with a genuine answer needs the async resolver call this ADR's whole
  offline/network section describes, which would force those functions to become async — a breaking
  signature change, not the additive one this milestone requires. Composing a separate `lib/trust`
  result (see `trust-decision.ts`'s module comment) that WRAPS M3's unmodified, still-synchronous
  `VerificationResult` with its own real `revocation` field gets the same outcome — a real answer
  reaching a caller — without touching tested, frozen code or breaking its own stated constraints.

<!-- Copy this file to NNNN-<slug>.md for each irreversible decision.
     Then add a one-line pointer in implementation-notes.html "Decisions that bind". -->
