# Two years out: identity is solved, authority isn't

Identity is nearly finished. Ed25519 and `did:key` give you an identifier that *is* its own
public key — verification needs no registry, no network call, no permission. That part works
today.

Authority is unsolved, and authority is what anyone actually asks about. Not "who are you," but
"may you do this, and who says so."

**Reputation scores will be built, adopted, and abandoned.** A score is unappealable. When an
agent is refused a $40,000 transfer because its trust rating is 0.61, nobody — not the operator,
not the counterparty, not an auditor — can say which evidence produced that number or what would
change it. Scores will lose to scoped, expiring, attributable grants for the same reason credit
*decisions* are regulated while credit *scores* are merely disputed.

**Revocation latency becomes the binding constraint.** Revocation is the only check that cannot
be offline, because it asserts something about *now*, and *now* cannot be signed in advance.
Status lists are a workaround, not an answer. The durable answer is credentials short-lived
enough that revoking them is unnecessary — which turns trust infrastructure from a distribution
problem into an issuance-rate problem, and moves the hard engineering to where keys are held
rather than where lists are hosted.

**Delegation is where implementations break.** Every real deployment wants agent A to
sub-delegate to agent B. Depth limits, scope intersection and cycle handling are unglamorous and
load-bearing, and when they are wrong, authority widens silently — the one failure mode nobody
notices.

The thing worth building is not a trust score. It is a decision that names the rule it applied
and the signed claim it read, so that when an agent refuses, a human can read the refusal and
argue with it.
