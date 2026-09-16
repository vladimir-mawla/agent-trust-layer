# PLAN — agent-trust-layer

The machine-parseable implementation plan. Mirrors the milestone table in `DONE.html` (DONE.html is the
human/visual view; this is the one loops read). Sliced so each milestone ships in one L1 BUILD pass.

> Slicing rule: a milestone must have (a) a single clear outcome, (b) an exact **demo command** that
> proves it, and (c) a freeze boundary of files it may touch. If you can't write the demo command,
> the milestone is too vague — split it.

---

## Brainstorm (G0.5 — fill before slicing milestones)

> Three fundamentally different approaches to the cognitive job. Pick one. Record the rationale.
> This is the cheapest design decision — you haven't written a line of code yet.

### Approach A — Central trust registry
A service that stores agent reputations and answers "is this agent trustworthy" for anyone who queries it.
- Strengths: simple to build; easy to query.
- Weaknesses: it IS the "score with no mechanism" the brief disqualifies; a single point of trust and failure that nobody outside the registry can verify.

### Approach B — Self-certifying identity with verifiable credentials
Agents hold `did:key` identifiers whose identifier IS their public key; claims about them are W3C Verifiable Credentials signed by issuers; any party verifies offline with no registry.
- Strengths: standards-based (DIDs + VCs, the named bonus); verification needs no infrastructure or network, so the demo is deterministic.
- Weaknesses: revocation genuinely needs somewhere to look; key loss is unrecoverable by design.

### Approach C — On-chain attestations
Publish claims and revocations to a blockchain so any party can read the shared, tamper-evident log.
- Strengths: tamper-evident public log; revocation is naturally global.
- Weaknesses: cost and latency make a 90-second demo painful; the interesting parts of the brief (scope, delegation, policy) are unaffected by where the log lives, so the chain adds ceremony, not clarity.

### Chosen: B — because verification with no trusted third party is the thing that makes this a trust *layer* rather than a trust *vendor*, and it puts the engineering effort where the judging weight actually is: scope, revocation, and policy.

---

## Milestones

> M2 and M8 are the only milestones that need a Vercel account (to deploy and to hold the live
> demo URL). Every other milestone — M1, M3-M7, M9 — needs no credential at all; each runs
> against local, self-signed, deterministic key material.

### M1 — Identity: did:key and proof of possession
- **Outcome:** Ed25519 keypair generation, did:key encoding/decoding (multibase/multicodec), and a
  challenge-response handshake proving key possession.
- **Phase (swe-master):** BUILD
- **Files / freeze boundary:** `lib/identity/**`
- **Demo command:** `npm test -- identity`
- **Success criteria:** the test proves a DID round-trips to the same public key it was derived
  from, and that signing a challenge with the WRONG key fails verification.
- **Loops:** L1, L4
- **Skills:** canon + tdd + security-engineering
- **Token budget:** 150000

### M2 — Deploy a live skeleton to Vercel
- **Outcome:** A minimal Next.js app with a health endpoint, deployed, with a real public URL.
  This comes second deliberately: the live demo URL is a hard requirement of the brief, and
  leaving deployment to the end is how it fails to happen.
- **Phase:** DEPLOY
- **Files:** `app/api/health/**`, `vercel.json`, `next.config.*`, `package.json`
- **Demo command:** `curl -sf $DEPLOY_URL/api/health`
- **Success criteria:** returns HTTP 200 with a JSON body naming the deployed commit SHA.
  **Needs a Vercel account.**
- **Loops:** L1, L3 (research), L4
- **Skills:** canon + tdd + production-readiness
- **Token budget:** 150000

### M3 — Verifiable credentials: issue and verify
- **Outcome:** W3C VC data model, signed as JWTs with Ed25519. Two credential types: authority
  (forward-looking, scoped, revocable) and history attestation (backward-looking, observed). Full
  verification chain: signature, expiry, subject binding, issuer identity.
- **Phase:** BUILD
- **Files:** `lib/credentials/**`
- **Demo command:** `npm test -- credentials`
- **Success criteria:** the suite proves a tampered claim fails verification and an untampered one
  passes.
- **Loops:** L1, L4
- **Skills:** canon + tdd + security-engineering
- **Token budget:** 150000

### M4 — Revocation and trust anchors
- **Outcome:** A revocation mechanism, plus each agent's configurable set of trusted issuers.
- **Phase:** BUILD
- **Files:** `lib/trust/**`
- **Demo command:** `npm test -- trust`
- **Success criteria:** the suite proves a revoked credential is refused and a self-issued
  authority credential from an untrusted issuer is refused.
- **Loops:** L1, L4
- **Skills:** canon + tdd + security-engineering
- **Token budget:** 150000

### M5 — Policy engine with explanations
- **Outcome:** Rules over verified claims. Never a bare boolean: every decision carries the rule
  and the credential field that decided it.
- **Phase:** BUILD
- **Files:** `lib/policy/**`
- **Demo command:** `npm test -- policy`
- **Success criteria:** the suite asserts a refusal's explanation names the exact rule and the
  exact credential field.
- **Loops:** L1, L4
- **Skills:** canon + tdd + clean-architecture
- **Token budget:** 150000

### M6 — Cross-agent negotiation
- **Outcome:** Two agents, a Buyer and a Supplier, with the Supplier holding a policy. The
  four-beat narrative: accept within scope, refuse over scope, refuse a spoofed DID, refuse a
  forged credential.
- **Phase:** INTEGRATE
- **Files:** `lib/agents/**`, `scripts/demo-negotiation.ts`
- **Demo command:** `npm run demo:negotiation`
- **Success criteria:** the scripted run prints all four outcomes with their reasons, in order.
- **Loops:** L1, L4
- **Skills:** canon + tdd + distributed-systems
- **Token budget:** 150000

### M7 — The attack suite
- **Outcome:** At least these attacks, each caught by a NAMED mechanism: forged signature,
  tampered claim, stolen credential replayed by a different subject, captured presentation
  replayed later, expired, revoked, self-issued authority, DID impersonation, over-scope request,
  confused deputy (credential used for a different purpose than granted).
- **Phase:** VERIFY
- **Files:** `tests/attacks/**`
- **Demo command:** `npm test -- attacks`
- **Success criteria:** every attack in the suite is asserted to be refused for the RIGHT reason,
  not merely refused.
- **Loops:** L1, L4
- **Skills:** canon + tdd + security-engineering
- **Token budget:** 150000

### M8 — The demo UI
- **Outcome:** Make the trust decision visible and explainable in 90 seconds: the decision, the
  credential chain behind it, and the reason.
- **Phase:** BUILD
- **Files:** `app/**`, `components/**`
- **Demo command:** `curl -sf $DEPLOY_URL/ | grep -c 'data-testid="decision"'`
- **Success criteria:** the deployed URL renders the four-beat scenario from M6 and each
  decision's explanation; the grep count is 4. **Needs a Vercel account** (reuses M2's deployment).
- **Loops:** L1, L3 (research), L4
- **Skills:** canon + tdd + design-system (MANDATORY for frontend)
- **Token budget:** 150000

### M9 — Deliverables
- **Outcome:** Architecture snapshot (identity to claims to verification to policy), the
  <=300-word two-year thesis on agent identity, clean-clone verification, and walkthrough notes.
- **Phase:** RELEASE
- **Files:** `docs/**`, `.genesis/explanations/**`, `README.md`
- **Demo command:** `cd "$(mktemp -d)" && git clone https://github.com/vladimir-mawla/agent-trust-layer . && npm ci && npm run typecheck && npm test`
- **Success criteria:** a fresh clone, install, typecheck, and test run all pass with zero
  credentials configured.
- **Loops:** L1, L4
- **Skills:** canon + tdd + documentation
- **Token budget:** 150000

---

## Progress (loops append here on milestone completion — newest last)

- _(none yet — first loop fills this)_
