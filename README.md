# agent-trust-layer

A trust layer for AI agents: how one agent decides whether to act on another agent's request.

> Trust is not a number. It is a decision — about a specific counterparty, for a specific
> action, under a stated policy, from verifiable evidence.

A reputation "score" with no mechanism underneath is worthless here, because nobody can check
it, argue with it, or ask why it said what it said. This project replaces the score with a
chain anyone can verify themselves: an identifier that certifies itself, credentials that are
signed and checked rather than trusted on sight, and a policy that names the exact rule and the
exact field that decided the outcome — never a bare `true`/`false`.

_Live demo: pending deployment — link goes here_

## The distinction that organizes the design

Every claim an agent presents is one of two kinds, and the two are not interchangeable:

- **Authority credentials** are forward-looking. They answer *may you?* They are scoped,
  they expire, they can be revoked, and someone specific granted them.
- **History attestations** are backward-looking. They answer *should I?* They accumulate, and
  they are observed rather than granted.

History may tighten a decision (an agent with a record of past refunds might face a lower
limit) but it may never loosen one — an authority credential is still required for the action
to happen at all. Letting observed history grant authority on its own would quietly rebuild the
reputation score this design exists to avoid.

## Architecture

Four layers, each depending only on the one below it:

```
┌─────────────────────────────────────────────────────────────────┐
│ 4. POLICY          rules over verified claims                   │
│                     -> every decision names the rule that fired │
│                        and the credential field that decided it │
├─────────────────────────────────────────────────────────────────┤
│ 3. VERIFICATION    signature · expiry · revocation ·            │
│                     subject binding · freshness                 │
│                    -> fail closed: unverifiable == expired ==   │
│                       revoked == malformed == absent            │
├─────────────────────────────────────────────────────────────────┤
│ 2. CLAIMS          W3C Verifiable Credentials, signed           │
│                     Authority (may you?)   History (should I?)  │
├─────────────────────────────────────────────────────────────────┤
│ 1. IDENTITY        did:key + Ed25519                            │
│                     the identifier IS the public key —          │
│                     no registry, no network call, no resolution │
└─────────────────────────────────────────────────────────────────┘
```

**1. Identity.** Agents are identified by `did:key`, a DID method whose identifier is derived
directly from an Ed25519 public key. Decoding the string is the entire resolution process —
there is no registry to query and no network call to make. Possessing a DID string proves
nothing, since anyone who has ever seen it can copy and present it; only signing a fresh
challenge proves the presenter actually holds the private key behind it.

**2. Claims.** Every statement about an agent — its granted authority, its observed history —
is a signed W3C Verifiable Credential, split along the authority/history line above.

**3. Verification.** Signature, expiry, revocation, subject binding, and freshness are checked
before any claim inside a credential is read. An unverifiable, expired, revoked, or malformed
credential is treated exactly as an absent one.

**4. Policy.** Rules run over verified claims and return the rule that fired plus the
credential field it read — never a bare boolean.

## Status

Two of nine milestones are done. This is a public, honest count — milestones 3 through 9 do
not exist yet, and nothing below claims otherwise.

| # | Milestone | Status |
|---|---|---|
| M1 | Identity: `did:key` + proof of possession | **Done.** Built and independently verified (see below). |
| M2 | Deploy a live skeleton to Vercel | Built locally (health endpoint, Next.js app). Not yet deployed — no live URL exists. |
| M3 | Verifiable credentials: issue and verify | Not started. |
| M4 | Revocation and trust anchors | Not started. |
| M5 | Policy engine with explanations | Not started. |
| M6 | Cross-agent negotiation | Not started. |
| M7 | The attack suite | Not started. |
| M8 | The demo UI | Not started. |
| M9 | Deliverables (docs, thesis, clean-clone check) | Not started. |

The full milestone plan, including each milestone's exact demo command and freeze boundary,
is in [`.genesis/PLAN.md`](.genesis/PLAN.md). The design rationale for choosing self-certifying
identity over a central trust registry or an on-chain log is in
[`.genesis/decisions/0001-self-certifying-identity.md`](.genesis/decisions/0001-self-certifying-identity.md).

## Quickstart

Requires Node 24.x (`engines.node` in `package.json`).

```bash
git clone https://github.com/vladimir-mawla/agent-trust-layer.git
cd agent-trust-layer
npm ci
npm test
npm run dev
```

With the dev server running, in another terminal:

```bash
curl -s http://localhost:3000/api/health
```

Real response shape (the `commit` value is your checked-out SHA, and `elapsedMs` will vary):

```json
{"status":"ok","commit":"286af2f1e724a481548aa80f88dbf81cfb77b8d0","checks":{"identity":{"pass":true,"elapsedMs":24.28}}}
```

`/api/health` doesn't just report "up" — it runs a full keygen → `did:key` encode/decode →
challenge-response proof-of-possession round trip on every request, in the deployed process,
and returns HTTP 503 (not 200) if that round trip throws. A health check that reports healthy
while its core cryptographic primitive is broken would hide exactly the failure it exists to
catch.

## What is verifiable today

`npm test` runs 29 tests across 4 files under `lib/identity/`, all passing:

```
Test Files  4 passed (4)
     Tests  29 passed (29)
```

Specifically, the suite proves:

- **Signing with the wrong key fails verification.** `challenge.test.ts` has a test literally
  named `HEADLINE: signing a challenge with the WRONG key fails verification` — a correctly
  formed proof, signed by a key other than the one the claimed DID names, is rejected.
- **Malformed DIDs are rejected with typed errors, not silent fallbacks.** `decodeDidKey`
  throws a `MalformedDidError` carrying one of four specific reason codes (`BAD_PREFIX`,
  `BAD_MULTIBASE`, `BAD_MULTICODEC`, `BAD_KEY_LENGTH`) — never `null`, never a bare `Error`, so
  callers and tests can `instanceof`-check exactly what went wrong.
- **The spec test vector is checked against an independently-derived constant.**
  `did-key.vectors.test.ts` decodes the official `did:key` Ed25519 example from the W3C
  method spec and compares it against a 32-byte hex constant that was derived by hand with a
  from-scratch base58btc decoder, not through the `multiformats` library the code under test
  actually uses. That distinction matters: if the expected value had been produced by decoding
  the same DID with the same library being tested, a broken decoder could pass its own test by
  agreeing with itself. Checking against a value derived a different way is what makes it a
  test vector instead of a tautology.

L4 verification of M1 also included mutation testing: stubbing `ed25519.verify` to
unconditionally return `true` broke three real tests. That is the evidence that the test suite
actually constrains the implementation, rather than just exercising it.

## Project layout

```
app/                Next.js app router (M2's deploy skeleton — landing page, /api/health)
lib/identity/        M1: Ed25519 keys, did:key encode/decode, challenge-response proof of possession
.genesis/             Loop-based development process docs: the locked spec, the milestone plan,
                       architecture decision records, and per-loop checkpoints
```

`lib/` is framework-free: no file under `lib/` may import from Next.js. The same identity code
has to run unmodified in a plain Node test, inside a Next.js API route, and eventually in a
browser (planned for M8) — a Next.js import anywhere in `lib/` would break at least one of
those three.

## Development notes

**Turbopack is disabled for this app.** `lib/identity`'s internal imports use explicit `.js`
suffixes on `.ts` files, which is required by its strict NodeNext `moduleResolution` (see
`tsconfig.lib.json`). webpack resolves that correctly via `experimental.extensionAlias` in
`next.config.ts`; Turbopack (Next 16's default bundler) does not yet implement `extensionAlias`
and fails with "Module not found" on every one of `lib/identity`'s relative imports. `npm run
dev` and `npm run build` therefore pass `--webpack` explicitly. This is a documented, supported
fallback (webpack is still Next.js's other fully maintained production bundler), not a hack —
but it's a real gotcha if you ever try to drop the flag.

## Standards used

- [W3C Decentralized Identifiers (DIDs)](https://www.w3.org/TR/did-core/) — the `did:key`
  method specifically ([w3c-ccg/did-method-key](https://w3c-ccg.github.io/did-method-key/)).
- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/) — planned for M3; not yet
  implemented.
