# Architecture

Four layers. Each answers one question, and each refuses independently of the others.

```
  a counterparty asks to do something
                │
                ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ 1  IDENTITY          who is asking?                                       │
│                                                                           │
│    did:key + Ed25519. The identifier IS the public key, so resolving it   │
│    is decoding a string — no registry, no network, nothing to spoof at    │
│    the resolution step because there is no resolution step.               │
│                                                                           │
│    Holding a DID proves nothing. Signing a fresh challenge does.          │
│                                                                           │
│    refuses ▸ a copied DID the presenter cannot sign for                   │
│    refuses ▸ a tampered challenge, an expired one                         │
│    refuses ▸ a captured proof replayed later — one level up, by the       │
│              counterparty's own session tracking already-answered         │
│              nonces, not by this layer alone (see Limits)                 │
└───────────────────────────────────────────────────────────────────────────┘
                │  a DID whose private key the presenter demonstrably holds
                ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ 2  CLAIMS            what is being asserted, and by whom?                 │
│                                                                           │
│    W3C Verifiable Credentials 2.0, secured as JWTs (VC-JOSE-COSE), signed │
│    with Ed25519. Two kinds, structurally distinct and not interchangeable:│
│                                                                           │
│      AUTHORITY      forward-looking   "may you?"   scoped, expiring,      │
│                                                     revocable, granted    │
│      HISTORY        backward-looking  "should I?"  observed, accumulates  │
│                                                                           │
│    The type system forbids using one where the other is required.         │
└───────────────────────────────────────────────────────────────────────────┘
                │  signed assertions, not yet believed
                ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ 3  VERIFICATION      is any of it true?                                   │
│                                                                           │
│    An ordered chain. No claim field is read before the signature verifies.│
│    Fail closed at every step: unverifiable, expired, revoked or malformed │
│    is treated exactly as absent.                                          │
│                                                                           │
│      signature       ▸ EdDSA only, hardcoded — never read from the header │
│      structure       ▸ required fields, well-formed                       │
│      temporal        ▸ validFrom / validUntil, explicit clock skew        │
│      subject binding ▸ the credential's subject must be the proven DID    │
│      issuer identity ▸ the claimed issuer must be the actual signer       │
│      issuer trust    ▸ a configured anchor, or vouched by one (depth 1)   │
│      revocation      ▸ W3C Bitstring Status List — checked last, because  │
│                        there is no reason to spend a network call asking  │
│                        an issuer you have already decided not to trust    │
│                                                                           │
│    refuses ▸ forged signature, tampered claim, alg confusion, alg:none    │
│    refuses ▸ agent B presenting agent A's valid credential                │
│    refuses ▸ a credential claiming an issuer that did not sign it         │
│    refuses ▸ self-issued authority — always, even from a configured anchor│
│    refuses ▸ a status list whose issuer is not the credential's issuer    │
└───────────────────────────────────────────────────────────────────────────┘
                │  verified claims, with the reason each is trusted
                ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ 4  POLICY            given all that, may this happen?                     │
│                                                                           │
│    Declarative rules over verified claims. The permitted envelope comes   │
│    from authority credentials alone; history rules can only narrow it.    │
│    Every bound combines with Math.min and nothing else.                   │
│                                                                           │
│    refuses ▸ no authority credential at all                               │
│    refuses ▸ wrong action  ·  no matching rule  ·  over scope             │
│    refuses ▸ negative scope value                                         │
│    refuses ▸ a history constraint that narrows below the request          │
│    refuses ▸ revocation not checked, unless a human signed off by name    │
└───────────────────────────────────────────────────────────────────────────┘
                │
                ▼
      a decision, naming the rule that fired and the field that decided it
```

Every refusal named above corresponds to a real, passing test — mostly in
[`tests/attacks/`](../tests/attacks/), the rest in the unit suites next to
the code they describe (`lib/identity/challenge.test.ts`,
`lib/credentials/jws.test.ts` and `verify.test.ts`, `lib/policy/engine.test.ts`
and `history-constraints.test.ts`). None of it is asserted here without a
test behind it.

## The one place the offline claim breaks

Signature, expiry, subject binding and anchoring all verify with no network:
`did:key` needs no resolution and expiry is arithmetic. **Revocation cannot.**
It asserts something about *now*, and *now* cannot be signed in advance.

So it is one clearly-labelled step whose own freshness is an input to the
decision, taking an injected resolver rather than performing I/O itself.
`lib/trust/status-list.ts`'s `checkRevocation` is the only function anywhere
under `lib/` that actually calls that resolver — `grep -rn "resolver(" lib/
--include="*.ts" | grep -v test` names exactly one call site. (Several other
functions are *declared* `async` merely because they `await` a call chain
that eventually reaches it; "declared async" and "performs network I/O" are
different properties, and only the second one is true of just one function.)
A status list that is unreachable, unverifiable, stale, or issued by anyone
other than the credential's own issuer is treated as **revoked**, not as
fine.

## Why no score

A reputation number is unappealable. Refuse a $40,000 transfer because trust
is 0.61 and nobody — operator, counterparty, or auditor — can name the
evidence or say what would change it.

Every decision here instead returns the rule that fired and the credential
field that satisfied or failed it: *`scope.amount` requested 5000, permitted
500*, not *"insufficient authority"*. A bare boolean is a violation of the
project's own invariants, enforced by type and by test.

And history may tighten a decision but never loosen one. Letting observed
behaviour grant authority is how a score gets rebuilt by the back door — so
history rules return constraints, never grants, and cannot structurally do
otherwise.

## Limits this diagram doesn't show

See the README's own "Honest limits" section for the full list — the
single-use nonce cache being per-`Supplier`-instance and in-memory is the one
most relevant to the "replayed challenge" line above: a stateless per-request
server would build a fresh, empty cache on every request and defeat it
entirely.
