# KICKOFF-INTERVIEW — agent-trust-layer

> Run this BEFORE G0. The agent asks YOU questions until every assumption is explicit.
> Output goes to `decisions/decisions-manifest.md`. That file is the input to G0.
>
> Paste this file into your agent and say: "Interview me. Ask one question at a time.
> Wait for my answer before the next. When done, write decisions/decisions-manifest.md."

---

## Instructions for the agent

You are NOT coding yet. Your job is to surface the human's unknown knowns before
any milestone is sliced. Ask the questions below ONE AT A TIME. Wait for the human's
answer before asking the next. Do not skip a question — if the human says "I don't
know", write that down; that's a decision too (it means you'll need a research spike).

When all questions are answered, write `decisions/decisions-manifest.md` using the
template at the bottom of this file. Then tell the human: "Interview done. Run G0
now — your cognitive job is pre-filled in decisions-manifest.md."

---

## Question bank (ask in order, skip only if clearly irrelevant)

### Trade-offs
1. Rank these four in order of importance for this project:
   speed · maintainability · cost · reliability
   (Drives almost every architecture call — don't skip this one.)

2. What's the expected scale at launch vs. in 12 months?
   (Users, requests/day, data volume — even rough orders of magnitude help.)

3. Is this a prototype, an internal tool, or a production system?
   (Changes the tolerance for tech debt significantly.)

### Non-obvious assumptions
4. Are there any performance requirements you'd immediately notice if violated?
   e.g. "dashboard must load in < 2s", "batch job must finish overnight"
   (These are classic unknown knowns — obvious to you, invisible to the agent.)

5. Are there brand or UX constraints? Any "it must feel like X" references?
   e.g. "Apple-clean", "Notion-style", "dense terminal-like"

6. What does the unhappy path look like? What should happen on failure?
   e.g. "show a friendly error", "retry silently", "alert on-call"

### Integration points
7. What existing systems does this touch?
   List every API, database, service, or CLI it needs to read from or write to.

8. Are there auth requirements? Who can do what?
   e.g. "only admins can delete", "all writes require 2FA"

9. Are there compliance or legal constraints?
   e.g. GDPR, SOC2, data residency, no PII in logs

### Risk & failure modes
10. What's the single most likely way this project fails?
    (Honest answer here is worth 10 architecture diagrams.)

11. What's the one thing you'd be embarrassed to ship?
    (Surfaces implicit quality bar — what "good enough" actually means to you.)

12. Any known unknowns? Things you know you don't know yet?
    (These become L3 RESEARCH spikes before M1 starts.)

---

## decisions-manifest.md template (write this when interview is done)

```markdown
# decisions-manifest — agent-trust-layer
Generated: 2026-09-16 via KICKOFF-INTERVIEW.md

## Trade-off ranking
1. A coherent trust model that is not a score — trust as a decision about a specific counterparty, for a specific action, under a stated policy, from verifiable evidence.
2. Real cryptography — genuine Ed25519 signing and verification, where tampering actually breaks the signature rather than tripping a simulated check.
3. A live, openable demo URL where a trust-gated decision and its reason are visible inside 90 seconds.
4. Named attacks, each refused for a named reason — the failure thinking has to be demonstrated, not asserted.

## Scale
Launch: Demo scale — two agents, a handful of credentials, single-digit concurrent viewers. Correctness and explainability matter; throughput does not.
12 months: Not applicable — this is a demonstrator, not a service. If the model were adopted, the scaling question would be issuer discovery and revocation distribution, not request volume.

## Project type
prototype  <!-- prototype / internal / production -->

## Performance constraints (non-negotiable)
- A full verification — signature, expiry, subject binding, revocation, policy — completes in under 100ms locally, so the demo feels immediate rather than loading.
- The deployed page renders its first trust decision without any configuration, credential, or sign-in by the viewer.

## UX / brand constraints
One page must tell the whole story in 90 seconds: the request, the decision, and the reason behind it. Every decision surfaces the rule that fired and the credential field it read. No login, no setup, no configuration.

## Failure behaviour
Fail closed. A credential that is unverifiable, expired, revoked, out of scope, or simply malformed is treated exactly as an absent one: the request is refused, with the reason stated.

## Integration points
None required. Vercel for hosting only. Deliberately no external identity provider, trust registry, blockchain, or LLM — verification is offline and deterministic by design, which is also what makes the demo reproducible.

## Auth requirements
Agents authenticate to one another with did:key plus an Ed25519 challenge-response proving key possession. There are no human user accounts; the public demo is anonymous and read-only.

## Compliance constraints
No binding regulatory regime. Follows the W3C DID and Verifiable Credentials data models by choice, so that credentials issued here are legible to other implementations.

## Primary failure mode (the honest one)
The worst case is a wrong accept: an action allowed on a credential that was forged, tampered with, replayed by the wrong subject, expired, revoked, self-issued, or outside its granted scope. Each of those gets its own named test in M7.

## Quality bar ("embarrassed to ship if...")
Real cryptography, not simulated — actual Ed25519 signatures, with verification actually failing on a tampered byte. Every attack must be refused for the RIGHT reason, asserted by test, not merely refused.

## Known unknowns → research spikes needed
- Why do I trust the issuer? Explicit trust anchors (each agent configures which issuers count) is the honest, simple answer. Transitive vouching (A is vouched by B whom I trust) is richer but needs a depth limit and cycle handling. Current plan: anchors first in M4, then one level of vouching, since the brief names vouches explicitly.
- Whether history attestations should influence the policy decision or only inform the human reading it. Letting observed history grant authority quietly recreates the reputation score the brief disqualifies, so the current lean is that history is displayed and may tighten a decision, but never loosens one.

## Assumptions never stated aloud (agent-inferred from answers above)
<!-- Agent fills this: list 3-5 implicit assumptions it drew from the answers. -->
- Judges will open the live URL rather than clone the repo, so the deployed demo has to carry the explanation on its own, without a README beside it.
- Key distribution is out of scope: did:key means the identifier IS the public key, so there is no resolution step to get wrong and no registry to stand up.
- Deterministic agents are a feature, not a shortcut. Putting an LLM in the trust path would make the demo non-reproducible and would weaken exactly the claim being made — that the decision follows from evidence and policy.
```
