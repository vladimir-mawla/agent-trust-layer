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

### M1 — {{M1_NAME}}
- **Outcome:** {{M1_OUTCOME}}
- **Phase (swe-master):** {{M1_PHASE}}
- **Files / freeze boundary:** `{{M1_FILES}}`
- **Demo command:** `{{M1_DEMO}}`
- **Success criteria:** {{M1_SUCCESS}}
- **Loops:** L1, L4
- **Skills:** canon + tdd + {{M1_SKILLS}}
- **Token budget:** 50000

### M2 — {{M2_NAME}}
- **Outcome:** {{M2_OUTCOME}}
- **Phase:** {{M2_PHASE}}
- **Files:** `{{M2_FILES}}`
- **Demo command:** `{{M2_DEMO}}`
- **Success criteria:** {{M2_SUCCESS}}
- **Loops:** L1, L3 (research), L4
- **Skills:** canon + tdd + {{M2_SKILLS}}
- **Token budget:** 50000

<!-- duplicate the block per milestone -->

---

## Progress (loops append here on milestone completion — newest last)

- _(none yet — first loop fills this)_
