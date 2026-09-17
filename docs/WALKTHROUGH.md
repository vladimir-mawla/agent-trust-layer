# 90-second walkthrough script

For recording a Loom (or any screen capture) off the live deployment:
**https://agent-trust-layer-pi.vercel.app**

Do a dry run once with no recording — the page needs no login, no setup,
and no clicking through a demo mode; everything below is already on screen
at rest except the two interactive moments called out explicitly. Refresh
before you actually record, since Beat 3's DIDs regenerate on every request
and you want a clean run.

Total: ~90 seconds. Timings are cumulative, not durations — "0:20" means
"you should be starting this beat at the 20-second mark," not "wait 20
seconds here."

---

### 0:00–0:10 — The claim (open on the live page, don't scroll yet)

**Say:** "This is a trust layer for AI agents — one agent deciding whether
to act on another agent's request. The whole argument is in the subtitle:"

**Do:** Let the camera sit on the hero for a beat so the viewer can read it
themselves — *"who asked, what they asked for, what a real policy engine
decided, and the exact rule and field that decided it — never a bare
accept/refuse."*

**Say (while it's on screen):** "Not a trust score. A decision you can
argue with."

### 0:10–0:22 — An accepted request (scroll to Beat 1)

**Do:** Scroll to the cast (issuer/buyer/attacker DIDs and the policy
line), then to Beat 1.

**Say:** "Two independent agents, each holding their own key. The Supplier's
policy permits office-supply purchases up to 500. Beat 1: the buyer asks
for 150 — within scope — and it's permitted, citing the rule that fired."

### 0:22–0:38 — An over-scope refusal, naming the field (scroll to Beat 2)

**Do:** Scroll to Beat 2. Point at (or zoom into, if your recorder supports
it) the `field` line: `scope.amount requested 5000 permitted 500`.

**Say:** "Same buyer, same credential, asks for 5000 instead. Refused — and
look at *how* it's refused: not 'insufficient authority,' but the exact
field, the exact number requested, and the exact number permitted. Every
decision on this page reads like this."

### 0:38–1:16 — THE CLIMAX: the spoofed identity (scroll to Beat 3)

This is the beat the whole demo is built around. Take the extra time here.

**Do:** Scroll to Beat 3 ("refused — spoofed identity"). Let the two DID
strings — "Claimed identity" and "Buyer's real DID" — sit on screen next to
each other.

**Say:** "Here's the interesting one. An impostor presents the buyer's own
real, valid, unexpired credential — not a forgery — while *claiming* the
buyer's DID. Look at these two strings."

**Do:** Point at both DID strings, or read the callout aloud: *"Character-
for-character identical."*

**Say:** "Identical. Copying a public identifier is free — anyone who's
ever seen it can paste it. What isn't free is proving you hold the private
key behind it. This impostor signs the challenge with its *own* key while
claiming someone else's identity, and that signature simply doesn't verify
against the claimed DID's public key. It's refused at proof-of-possession —
before the system has even looked at the credential it's holding. The
credential is completely genuine. It never gets read."

### 1:16–1:24 — Why there's no score (scroll to the footer / milestone ledger, or just hold on Beat 3)

**Say:** "There's no trust score anywhere on this page, on purpose. A
number like 'trust: 0.61' can't be argued with — nobody can point to what
produced it. Every refusal here instead names a rule and a field, which is
the entire design bet this project makes."

### 1:24–1:30 — Close

**Do:** Scroll to (or just gesture at) the health-endpoint line at the
bottom of the page.

**Say:** "It's live, it's real cryptography running server-side on every
request, and the code and the argument are both in the repo."

**End on:** the live URL on screen, or the GitHub link at the page footer.

---

## If you have an extra 20–30 seconds

Two optional beats to insert after 1:16, before the close, if the recording
is running short of 90 seconds:

- **Beat 4 (forged credential):** the attacker mints itself a *genuinely,
  validly signed* credential and is still refused — because the signature
  being valid and the issuer being trusted are different questions. Good
  follow-up to Beat 3 since it's the other half of "a real cryptographic
  artifact that still doesn't help you."
- **The interactive panel** ("Make your own decision"): pick the `−500`
  amount preset and click Evaluate live, to show the negative-scope-value
  refusal is a real decision computed on the spot, not a canned transcript.
  This is the one moment on the page that requires an actual click during
  recording — everything else above is already rendered at rest.
