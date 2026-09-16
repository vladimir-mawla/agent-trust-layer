# Wiki Index — agent-trust-layer

The project knowledge base. Same schema as the agentic-swe-kit wiki: concept pages in `concepts/`,
each with frontmatter and ≥2 `[[wikilinks]]`. The L3 RESEARCH loop writes here; G0 reads here first.

> **Read this file before any milestone (G0 step 1).** Pick candidate pages by name-matching the
> milestone's nouns, then drill in. The wiki is what prevents rebuilding work that already exists.

## Entities (the things this system has)
<!-- - [[concepts/Agent]] — a counterparty that presents credentials and requests actions -->
<!-- - [[concepts/DID]] — a did:key identifier whose identifier is its own public key -->
<!-- - [[concepts/KeyPair]] — an Ed25519 signing key and its public verification key -->
<!-- - [[concepts/VerifiableCredential]] — a W3C VC signed as a JWT by an issuer -->
<!-- - [[concepts/Presentation]] — a signed bundle of credentials answering a freshness challenge -->
<!-- - [[concepts/Challenge]] — a fresh nonce a verifier requires the presenter to sign -->
<!-- - [[concepts/AuthorityCredential]] — a forward-looking, scoped, revocable grant of authority -->
<!-- - [[concepts/HistoryAttestation]] — a backward-looking, observed claim about past behavior -->
<!-- - [[concepts/Issuer]] — the DID that signed a credential -->
<!-- - [[concepts/TrustAnchor]] — an agent's configured set of issuers it is willing to trust -->
<!-- - [[concepts/RevocationList]] — the mechanism an issuer uses to disown a credential it signed -->

## Concepts (how it works)
<!-- - [[concepts/Policy]] — the human-authored rules a verifier evaluates over verified claims -->
<!-- - [[concepts/Rule]] — one clause of a policy, named in every explanation it produces -->
<!-- - [[concepts/Decision]] — the accept/refuse output of the policy engine -->
<!-- - [[concepts/Explanation]] — the structured record naming the rule and credential field that decided it -->

## Sources (research distilled by L3)
<!-- - [[concepts/<source-slug>]] — one-line summary | filed <date> -->

## Seeded from agentic-swe-kit
Relevant global concept pages for this project's phases (pointers only — read on demand):
- $AGENTIC_SWE_WIKI_ROOT/security-engineering/concepts/Cryptography.md — when implementing Ed25519 signing and verification for credentials and the challenge-response handshake (M1, M3)
- $AGENTIC_SWE_WIKI_ROOT/security-engineering/concepts/Protocol-Security.md — when designing the freshness challenge that proves proof-of-possession of a DID's key (M1)
- $AGENTIC_SWE_WIKI_ROOT/security-engineering/concepts/Access-Control.md — when writing policy rules that check an authority credential's granted scope against the requested action (M5)
- $AGENTIC_SWE_WIKI_ROOT/security-engineering/concepts/Threat-Modeling.md — when building the attack suite of forged, tampered, replayed, and spoofed credentials (M7)
- $AGENTIC_SWE_WIKI_ROOT/security-engineering/concepts/Distributed-Architecture-Security.md — when the Buyer and Supplier agents negotiate trust with no shared trusted third party (M6)
- $AGENTIC_SWE_WIKI_ROOT/security-engineering/concepts/Secure-Development-and-Assurance.md — when verifying no private key material escapes into a response, log, or committed file (G2 invariant, M9)
- $AGENTIC_SWE_WIKI_ROOT/security-engineering/concepts/Metering-and-Token-Security.md — when scoping an authority credential so it cannot be replayed for a purpose it was not granted for (M5, confused-deputy attack in M7)
- $AGENTIC_SWE_WIKI_ROOT/security-engineering/concepts/Critical-Systems-Security.md — when deciding to fail closed on any unverifiable, expired, or revoked credential (M4, M5)
- $AGENTIC_SWE_WIKI_ROOT/clean-architecture/concepts/Dependency-Rule.md — when keeping the policy engine dependent only on verified claims, never on raw or self-asserted credential data (G2 invariant no-unverified-claim-reaches-policy)
- $AGENTIC_SWE_WIKI_ROOT/clean-architecture/concepts/Boundary-Lines.md — when drawing the identity to claims to verification to policy layers for the architecture snapshot (M9)
- $AGENTIC_SWE_WIKI_ROOT/clean-architecture/concepts/Humble-Object-Pattern.md — when keeping the demo UI a thin renderer of decisions the policy engine already computed (M8)
- $AGENTIC_SWE_WIKI_ROOT/distributed-systems/concepts/Security-in-Distributed-Systems.md — when two independent agents must each verify the other with no central registry to ask (M6, ADR 0001)
