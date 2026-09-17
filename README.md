# agent-trust-layer

[![CI](https://github.com/vladimir-mawla/agent-trust-layer/actions/workflows/ci.yml/badge.svg)](https://github.com/vladimir-mawla/agent-trust-layer/actions/workflows/ci.yml)

**Live: https://agent-trust-layer-pi.vercel.app**

```bash
curl -sf https://agent-trust-layer-pi.vercel.app/api/health
```

```json
{"status":"ok","commit":"340bd8b675efcd47b200356ff746f31a8dfb47f6","checks":{"identity":{"pass":true,"elapsedMs":82.80}}}
```

That's a real response, not a sample — `commit` is the deployed git SHA (so you can confirm what
you're talking to matches what's in this repository), and `checks.identity` is a full Ed25519
keygen → `did:key` encode/decode → challenge-response round trip, run fresh **inside the deployed
process on every request**. The endpoint returns **503, not 200**, if any of that fails.

## What this is

A trust layer for AI agents: how one agent decides whether to act on another agent's request.

> Trust is not a number. It is a decision — about a specific counterparty, for a specific
> action, under a stated policy, from verifiable evidence.

The claim this project makes: a reputation *score* is unappealable — refuse a $40,000 transfer
because trust is 0.61, and nobody (operator, counterparty, or auditor) can name the evidence or
say what would change it. This replaces the score with a chain anyone can verify themselves: a
self-certifying identifier, credentials that are cryptographically checked rather than trusted on
sight, and a policy that names the exact rule and the exact field that decided the outcome —
never a bare `true`/`false`. The [two-year thesis](docs/THESIS.md) makes the longer version of
this argument; the [architecture snapshot](docs/ARCHITECTURE.md) is the technical one.

## The four layers

Identity → claims → verification → policy, each depending only on the one below it. Full diagram,
with the real test behind every "refuses" line, in **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)**.

```
┌─────────────────────────────────────────────────────────────────┐
│ 4. POLICY          rules over verified claims                   │
│                     -> every decision names the rule that fired │
│                        and the credential field that decided it │
├─────────────────────────────────────────────────────────────────┤
│ 3. VERIFICATION    signature · expiry · revocation ·            │
│                     subject binding · issuer trust               │
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

History may tighten a decision (an agent with a record of past refunds might face a lower limit)
but may never loosen one — an authority credential is still required for the action to happen at
all. Letting observed history grant authority on its own would quietly rebuild the reputation
score this design exists to avoid.

## What is actually verifiable

`npm test` runs **388 tests**, all passing, with a drift guard (`app/milestones.test.ts`) that
fails the build if the deployed page's milestone claims and `.genesis/DONE.html`'s own build
record ever disagree — a real bug this project shipped once, on a public URL, before that guard
existed.

```
Test Files  49 passed (49)
     Tests  388 passed (388)
```

`npm test -- attacks` selects **76 tests across 20 files** under `tests/attacks/`: ten named
attacks from the project's own plan (forged signature, tampered claim, stolen credential,
replayed presentation, expired credential, revoked credential, self-issued authority, DID
impersonation, over-scope request, confused deputy), an exploratory suite that tried things
nobody had specifically planned for, and — the part worth taking seriously — **six regression
attacks that pin defects which genuinely shipped into a branch during this project and were
caught by independent verification**, not defects invented for the exercise:

| Regression | What actually happened |
|---|---|
| `11-non-json-payload-crash` | A validly-signed non-JSON payload crashed the verifier instead of failing closed (M3). |
| `12-status-list-issuer-swap` | A resolver could serve a self-signed "clean" status list and get a revoked credential accepted, with no compromise of the real issuer's key (M4). |
| `13-omitted-bounded-scope-field` | Omitting a scope field the credential itself bounded escaped every ceiling — behind 31 passing tests (M5). |
| `14-throwing-scope-accessor` | A hostile `scope` object (throwing getter, `Proxy`, self-mutating enumeration) crashed the engine instead of refusing (M6). |
| `15-nonce-comparator-boundary` | Two comparators disagreeing by one millisecond reopened the replay window the nonce cache existed to close (M6). |
| `16-nonce-consumed-before-verify` | Consuming a challenge nonce before verifying its signature let anyone burn a legitimate agent's one attempt (M6). |

An attack someone actually landed is worth more than one invented to be caught. See
**[`docs/NOTES.md`](docs/NOTES.md)** for how each of these was found — by a *different* agent
than the one who built the code, per this project's own maker/checker process.

## Quickstart

Requires Node 24.x (`engines.node` in `package.json`) and **`npm ci`, never `npm install`** — see
[Development notes](#development-notes) for why.

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

You'll get the same JSON shape shown at the top, with your own checked-out commit SHA.

Try the negotiation demo directly, no browser needed:

```bash
npm run demo:negotiation
```

It prints four beats — a real trust decision, an over-scope refusal, a spoofed-identity refusal,
and a forged-credential refusal — each self-checked to exit `0` only if every outcome matched
what was expected.

## Project layout

```
app/                 Next.js app router — the live demo UI and its two API routes
lib/identity/         did:key + Ed25519 keys, challenge-response proof of possession
lib/credentials/      W3C Verifiable Credentials as signed JWTs (authority + history)
lib/trust/            Revocation (Bitstring Status List), trust anchors, issuer vouching
lib/policy/           Declarative policy engine — structured explanations, never a boolean
lib/negotiation/      The cross-agent protocol composing all four layers above
tests/attacks/        Named, regression, and exploratory attacks against the composed system
.genesis/             Loop-based development process docs: locked spec, plan, ADRs, checkpoints
docs/                 Architecture snapshot, two-year thesis, process notes, walkthrough script
```

`lib/` is framework-free: no file under `lib/` may import from Next.js, and (with one exception)
none of it performs network I/O. The same identity code runs unmodified in a plain Node test,
inside a Next.js API route, and — since M8 — directly in a browser, client-side, with zero
`node:` imports.

## Development notes

**Turbopack is disabled for this app.** `lib/identity`'s internal imports use explicit `.js`
suffixes on `.ts` files, required by its strict NodeNext `moduleResolution` (see
`tsconfig.lib.json`). webpack resolves that via `experimental.extensionAlias` in
`next.config.ts`; Turbopack (Next 16's default bundler) does not yet implement `extensionAlias`
and fails with "Module not found" on every one of `lib/identity`'s relative imports. `npm run
dev` and `npm run build` therefore pass `--webpack` explicitly. This is a documented, supported
fallback — webpack is still Next.js's other fully maintained production bundler — not a hack, but
it's a real gotcha if you ever drop the flag.

**Use `npm ci`, never `npm install`.** npm 11.5.1 silently drops the platform-specific
`@rolldown/binding-*` and `lightningcss-*` packages when `npm install` reconciles against an
already-committed lockfile — after which `vitest` fails to start with no obviously-related error.
`npm ci` installs strictly from the lockfile and is immune. CI (`.github/workflows/ci.yml`)
asserts the rolldown binding is actually present after `npm ci` specifically so this can't
regress silently.

## Honest limits

The brief rewards "this breaks when…" over silence about it, so here is where this system's
guarantees actually end:

- **Revocation needs a network, and is the only check that does.** Signature, expiry, subject
  binding, and issuer anchoring all verify offline. "Is this still valid *right now*" cannot —
  it's a statement about the present, made by a party other than the verifier, and no signature
  produced in the past can attest to a fact that keeps changing after it was signed.
- **The single-use nonce cache is per-`Supplier`-instance and in-memory.** A stateless,
  per-request server (the common serverless pattern) builds a fresh, empty cache on every
  request and silently defeats single-use entirely — every "new" request starts with no memory
  of any nonce it has already consumed. A real deployment needs that bookkeeping moved to shared
  storage (Redis, a database row) with the same verify-before-consume ordering.
- **Failed proof-of-possession attempts are unthrottled, by design.** A challenge nonce is only
  consumed on a *successful* answer, so an attacker gets unlimited free retries against a live
  challenge before it expires. Rate-limiting is treated as a deployment concern (a proxy, a WAF),
  not something a protocol library should own.
- **Only `did:key`.** No `did:web`, no `did:ion`, no resolution against any registry. Identity in
  this project is exactly as strong, and exactly as limited, as "the identifier is the public
  key" — lose the private key and there is no recovery path, by construction.
- **Scope bounds are numeric-only, and only upper-bound-plus-non-negative.** Every bound in the
  policy engine is a `maxX`-style ceiling; a negative requested value is refused outright (fixed
  after M7's attack suite found it was silently permitted — see `docs/NOTES.md`), but there is no
  general signed range (a real `minScope`, or "a refund between −1000 and 0 is fine") and no
  bound on non-numeric scope dimensions like a string enum.
- **A vouch cannot be revoked, only expire.** Issuer-to-issuer vouching (`lib/trust/vouch.ts`)
  checks an optional `validUntil`, but there is no status-list check for a vouch the way there is
  for a credential — a compromised voucher's vouch is live until it naturally expires.
- **Vouching is depth-1 by design.** `VOUCH_DEPTH_LIMIT = 1` is a fixed constant, not a
  configurable policy. A vouches for B; B vouching for C is not walked or trusted — there is no
  chain-of-trust beyond one hop, and no cycle-detection code, because there is no chain to have a
  cycle in.

## Status

Eight of nine milestones are done; M9 (this one — documentation and verification) is in
progress. This is a public, honest count.

| # | Milestone | Status |
|---|---|---|
| M1 | Identity: `did:key` + proof of possession | **Done.** |
| M2 | Deploy a live skeleton to Vercel | **Done.** Live at https://agent-trust-layer-pi.vercel.app. |
| M3 | Verifiable credentials: issue and verify | **Done.** |
| M4 | Revocation and trust anchors | **Done.** |
| M5 | Policy engine with explanations | **Done.** |
| M6 | Cross-agent negotiation | **Done.** |
| M7 | The attack suite | **Done.** |
| M8 | The demo UI | **Done.** Live on the homepage above. |
| M9 | Deliverables (docs, thesis, clean-clone check) | In progress (this document is part of it). |

The full milestone plan, each milestone's exact demo command and freeze boundary, is in
[`.genesis/PLAN.md`](.genesis/PLAN.md). The architecture decision records — including several
milestones' own accounts of being rejected on first independent verification, and exactly why —
are in [`.genesis/decisions/`](.genesis/decisions/); see [`docs/NOTES.md`](docs/NOTES.md) for the
count and two concrete examples.

## Standards used

- [W3C Decentralized Identifiers (DIDs)](https://www.w3.org/TR/did-core/) — the `did:key`
  method specifically ([w3c-ccg/did-method-key](https://w3c-ccg.github.io/did-key-spec/)).
- [W3C Verifiable Credentials 2.0](https://www.w3.org/TR/vc-data-model-2.0/), secured as JWTs
  per [VC-JOSE-COSE](https://www.w3.org/TR/vc-jose-cose/).
- [W3C Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/) for
  revocation.

## More

- **[Architecture](docs/ARCHITECTURE.md)** — the four-layer diagram, with the real test behind
  every refusal it claims.
- **[Two-year thesis](docs/THESIS.md)** — where agent trust infrastructure is headed, in under
  300 words.
- **[Process notes](docs/NOTES.md)** — AI tooling, key design decisions, what's deliberately out
  of scope, and how the maker/checker verification process actually went (including where it
  rejected its own work and why).
- **[Walkthrough script](docs/WALKTHROUGH.md)** — a beat-by-beat 90-second script for recording a
  demo off the live page.
