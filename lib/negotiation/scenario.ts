/**
 * The M6 four-beat scenario: a fixed, deterministic cast and story,
 * built entirely from real `lib/` code (no pre-baked results anywhere)
 * so it can be reused, unchanged, by `scripts/demo-negotiation.ts` (the
 * presentation layer) AND by `scenario.test.ts` (the actual proof that
 * each beat behaves as claimed). Framework-free, like every other module
 * under `lib/` — M8's UI is expected to import this directly.
 *
 * ## The cast
 * - **`issuer`** — a trust-anchor identity (e.g. "Acme Procurement")
 *   the Supplier is configured to trust directly. Issues the Buyer's
 *   authority credential and publishes the revocation status list both
 *   real beats resolve against.
 * - **`buyer`** — an independent `KeyHolder` the Supplier has never met
 *   before this negotiation. Holds ITS OWN keypair and a real,
 *   `issuer`-signed `AuthorityCredential`.
 * - **`attacker`** — a second independent `KeyHolder`, with no
 *   relationship to `issuer` or `buyer` beyond what it can observe
 *   publicly (a DID string, a credential JWT — both are, by design,
 *   public: see ADR 0001).
 * - **`supplier`** — holds the policy and the trust anchors; never holds
 *   any of the above three identities' private keys.
 *
 * ## The four beats, and the REAL mechanism behind each
 * 1. **Accepted** — Buyer requests `amount: 150` against a credential
 *    granting up to `GRANTED_MAX_AMOUNT` (500); within scope, revocation
 *    checked and clean (a real `BitstringStatusListCredential` is
 *    resolved). Permitted.
 * 2. **Refused: over scope** — Buyer requests `amount: 5000` against
 *    the SAME credential. `lib/policy`'s `over-scope` refusal names the
 *    field and both numbers.
 * 3. **Refused: spoofed identity** — the Attacker signs this session's
 *    fresh challenge with ITS OWN key while claiming the Buyer's real
 *    DID, then presents the Buyer's real, valid, unexpired credential
 *    (freely available to copy — DIDs and credentials are not secrets;
 *    only private keys are). Refused at proof-of-possession, before the
 *    Supplier ever examines that credential.
 * 4. **Refused: forged credential** — the Attacker mints itself an
 *    `AuthorityCredential` for a huge amount, signs it with its own key
 *    (genuinely valid: `issuer === subject === attacker.did`), and
 *    proves possession of its own DID honestly. Refused by `lib/trust`'s
 *    self-issuance check (`untrusted-issuer`, reason `self-issued`) —
 *    a valid signature and a trusted issuer are different questions.
 */
import type { Policy } from "../policy/index.js";
import { TrustAnchorSet, type CredentialStatusEntry, type StatusListResolver } from "../trust/index.js";
import { KeyHolder } from "./agent.js";
import type { NegotiationDecision } from "./decision.js";
import type { NegotiationRequest, Presentation } from "./messages.js";
import { Supplier } from "./supplier.js";

/** The one action this scenario's policy governs. Free text, per
 *  `lib/policy`'s own design — the vocabulary of actions belongs to the
 *  policy author, not to any data model. */
export const ACTION = "purchase-office-supplies";

/** The ceiling the Buyer's real credential (and the policy's own
 *  `action-scope` rule) grants for `scope.amount`. Beat 1 requests under
 *  it; Beat 2 requests far over it. */
export const GRANTED_MAX_AMOUNT = 500;

/** Opaque URL naming where the issuer's status list is "published" —
 *  never actually fetched over a network; `buildFourBeatFixture`'s
 *  injected `resolver` is what `lib/trust`'s `checkRevocation` calls
 *  instead (see `status-list.ts`'s module comment on why that injection
 *  point is what keeps `lib/` network-free and deterministic). */
export const STATUS_LIST_URL = "https://issuer.example/status-lists/acme-procurement-1";

/** A fixed "now" so a recording of the demo is reproducible even though
 *  keys are freshly generated every run — 2026-09-17T00:00:00.000Z. */
export const DEFAULT_SCENARIO_NOW = Date.parse("2026-09-17T00:00:00.000Z");

const ONE_YEAR_MS = 365 * 24 * 60 * 60 * 1000;

export interface FourBeatFixture {
  readonly now: number;
  readonly issuer: KeyHolder;
  readonly buyer: KeyHolder;
  readonly attacker: KeyHolder;
  readonly supplier: Supplier;
  readonly anchors: TrustAnchorSet;
  readonly policy: Policy;
  readonly buyerAuthorityJwt: string;
  readonly buyerCredentialStatus: CredentialStatusEntry;
  readonly resolver: StatusListResolver;
}

/**
 * Build the fixed cast, credentials, and Supplier configuration. Every
 * credential and status list below is issued and signed by real `lib/`
 * code (`issueAuthorityCredential`, `issueStatusListCredential`) — none
 * of this is a literal/mocked JWT string.
 */
export function buildFourBeatFixture(now: number = DEFAULT_SCENARIO_NOW): FourBeatFixture {
  const issuer = new KeyHolder();
  const buyer = new KeyHolder();
  const attacker = new KeyHolder();

  const anchors = new TrustAnchorSet([issuer.did]);

  // A real, signed, empty (nothing revoked) status list — small
  // `sizeBits` here only for demo/test speed, the same trade-off
  // `lib/trust`'s own test suite makes (see `bitstring.ts`'s comment on
  // `createEmptyEncodedList`'s default).
  const statusListJwt = issuer.issueStatusListCredential({
    statusPurpose: "revocation",
    sizeBits: 128,
    now,
  });
  const resolver: StatusListResolver = (url: string) => {
    if (url !== STATUS_LIST_URL) {
      return Promise.reject(new Error(`no status list is published at ${url}`));
    }
    return Promise.resolve(statusListJwt);
  };
  const buyerCredentialStatus: CredentialStatusEntry = {
    type: "BitstringStatusListEntry",
    statusPurpose: "revocation",
    statusListIndex: 0,
    statusListCredential: STATUS_LIST_URL,
  };

  const buyerAuthorityJwt = issuer.issueAuthorityCredentialTo({
    subjectDid: buyer.did,
    action: ACTION,
    scope: { amount: GRANTED_MAX_AMOUNT },
    validFrom: new Date(now).toISOString(),
    validUntil: new Date(now + ONE_YEAR_MS).toISOString(),
    now,
  });

  const policy: Policy = {
    id: "supplier-default-policy",
    version: "1.0.0",
    revocationHandling: { requireChecked: true },
    rules: [
      {
        kind: "action-scope",
        id: "R-purchase-office-supplies",
        description: `office-supply purchases are permitted up to a ceiling of ${GRANTED_MAX_AMOUNT} (the credential's own granted scope already matches this ceiling)`,
        action: ACTION,
        maxScope: { amount: GRANTED_MAX_AMOUNT },
      },
    ],
  };

  const supplier = new Supplier({ policy, anchors, statusListResolver: resolver, now });

  return { now, issuer, buyer, attacker, supplier, anchors, policy, buyerAuthorityJwt, buyerCredentialStatus, resolver };
}

/** One beat of the four-beat story: who asked, for what, what the
 *  Supplier decided, and whether that decision matches what this beat
 *  is supposed to demonstrate. `expected` is checked by the CALLER
 *  (`scripts/demo-negotiation.ts`, `scenario.test.ts`) — this module
 *  only reports what actually happened, never asserts on its own
 *  behalf, so a wrong outcome is never silently smoothed over here. */
export interface Beat {
  readonly id: "accepted" | "over-scope" | "spoofed-identity" | "forged-credential";
  readonly title: string;
  readonly asker: string;
  readonly askedFor: string;
  readonly expected: "permitted" | "refused";
  readonly decision: NegotiationDecision;
}

async function presentAndEvaluate(
  fixture: FourBeatFixture,
  buildPresentation: (challenge: ReturnType<Supplier["issueChallenge"]>) => Presentation,
  request: NegotiationRequest,
): Promise<NegotiationDecision> {
  const challenge = fixture.supplier.issueChallenge();
  const presentation = buildPresentation(challenge);
  return fixture.supplier.evaluatePresentation(challenge, presentation, request);
}

/** Run all four beats in order against a fresh fixture, using only real
 *  `lib/negotiation` + `lib/trust` + `lib/policy` code paths. */
export async function runFourBeats(fixture: FourBeatFixture): Promise<readonly Beat[]> {
  const beats: Beat[] = [];

  // --- Beat 1: accepted -------------------------------------------------
  {
    const request: NegotiationRequest = { action: ACTION, scope: { amount: 150 } };
    const decision = await presentAndEvaluate(
      fixture,
      (challenge) => ({
        proof: fixture.buyer.provePossession(challenge),
        credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
      }),
      request,
    );
    beats.push({
      id: "accepted",
      title: "Beat 1 — accepted (within granted authority)",
      asker: `Buyer ${fixture.buyer.did}`,
      askedFor: `${ACTION}, amount=${request.scope["amount"]}`,
      expected: "permitted",
      decision,
    });
  }

  // --- Beat 2: refused, over scope --------------------------------------
  {
    const request: NegotiationRequest = { action: ACTION, scope: { amount: 5000 } };
    const decision = await presentAndEvaluate(
      fixture,
      (challenge) => ({
        proof: fixture.buyer.provePossession(challenge),
        credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
      }),
      request,
    );
    beats.push({
      id: "over-scope",
      title: "Beat 2 — refused (over scope)",
      asker: `Buyer ${fixture.buyer.did}`,
      askedFor: `${ACTION}, amount=${request.scope["amount"]}`,
      expected: "refused",
      decision,
    });
  }

  // --- Beat 3: refused, spoofed identity ---------------------------------
  {
    const request: NegotiationRequest = { action: ACTION, scope: { amount: 100 } };
    const decision = await presentAndEvaluate(
      fixture,
      (challenge) => ({
        proof: fixture.attacker.attemptProofOfPossessionFor(fixture.buyer.did, challenge),
        credentials: { authorityJwt: fixture.buyerAuthorityJwt, credentialStatus: fixture.buyerCredentialStatus },
      }),
      request,
    );
    beats.push({
      id: "spoofed-identity",
      title: "Beat 3 — refused (spoofed identity)",
      asker: `Impostor claiming ${fixture.buyer.did} (Attacker's real DID is ${fixture.attacker.did})`,
      askedFor: `${ACTION}, amount=${request.scope["amount"]}, presenting the Buyer's real credential`,
      expected: "refused",
      decision,
    });
  }

  // --- Beat 4: refused, forged credential --------------------------------
  {
    const forgedJwt = fixture.attacker.issueAuthorityCredentialTo({
      subjectDid: fixture.attacker.did,
      action: ACTION,
      scope: { amount: 1_000_000 },
      validFrom: new Date(fixture.now).toISOString(),
      validUntil: new Date(fixture.now + ONE_YEAR_MS).toISOString(),
      now: fixture.now,
    });
    const request: NegotiationRequest = { action: ACTION, scope: { amount: 1000 } };
    const decision = await presentAndEvaluate(
      fixture,
      (challenge) => ({
        proof: fixture.attacker.provePossession(challenge),
        credentials: { authorityJwt: forgedJwt },
      }),
      request,
    );
    beats.push({
      id: "forged-credential",
      title: "Beat 4 — refused (forged credential)",
      asker: `Attacker ${fixture.attacker.did}`,
      askedFor: `${ACTION}, amount=${request.scope["amount"]}, presenting a credential it minted for itself`,
      expected: "refused",
      decision,
    });
  }

  return beats;
}

/** Convenience for callers that just want the whole scenario in one
 *  call — used by `scripts/demo-negotiation.ts`. */
export async function runFourBeatScenario(now: number = DEFAULT_SCENARIO_NOW): Promise<{ readonly fixture: FourBeatFixture; readonly beats: readonly Beat[] }> {
  const fixture = buildFourBeatFixture(now);
  const beats = await runFourBeats(fixture);
  return { fixture, beats };
}
