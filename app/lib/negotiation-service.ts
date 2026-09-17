/**
 * M8's server-side composition root: turns lib/negotiation's real
 * four-beat scenario, plus one extra "try it yourself" negotiation, into
 * plain, JSON-serialisable data for `app/api/negotiate/route.ts` and for
 * `app/page.tsx`'s server-rendered first frame.
 *
 * WHY THIS RUNS ONLY ON THE SERVER: `lib/negotiation` composes
 * `lib/trust`, and `lib/trust/bitstring.ts` imports `node:zlib` to
 * (de)compress the W3C Bitstring Status List — see that file's own
 * module comment. `node:zlib` has no browser build, so anything that
 * transitively imports it (this module included) can only run in a
 * Node.js environment: a Next.js Route Handler or Server Component,
 * never a "use client" component or anything bundled for the browser.
 * That is the whole reason M8's negotiation logic lives behind
 * `app/api/negotiate/route.ts` (runtime = "nodejs") instead of running
 * in the viewer's browser the way `lib/identity` (M1, zero `node:`
 * imports) safely can — see `app/components/IdentityPanel.tsx`.
 *
 * Nothing in this file invents a decision, a rule, or a number: every
 * value below is read off real `Beat` / `NegotiationDecision` /
 * `Explanation` objects produced by actually running
 * `lib/negotiation`'s protocol (`runFourBeatScenario`, and — for the
 * interactive control — the same `KeyHolder` + `Supplier` primitives
 * `scenario.ts` itself is built from). This file only shapes that real
 * output into a small, stable JSON contract and NEVER serialises a
 * private key: every `KeyHolder`'s `#privateKey` is a true JS private
 * class field (see `lib/negotiation/agent.ts`'s module comment) that is
 * structurally invisible to `JSON.stringify`/property access from
 * outside the class, and this module in any case only ever reads `.did`
 * off a `KeyHolder`, never anything else.
 */
import {
  ACTION,
  DEFAULT_SCENARIO_NOW,
  GRANTED_MAX_AMOUNT,
  STATUS_LIST_URL,
  KeyHolder,
  Supplier,
  buildFourBeatFixture,
  runFourBeatScenario,
  type Beat,
  type NegotiationRequest,
  type Presentation,
} from "../../lib/negotiation/index.js";
import { TrustAnchorSet, type CredentialStatusEntry, type StatusListResolver } from "../../lib/trust/index.js";
import type { Policy } from "../../lib/policy/index.js";

const ONE_YEAR_MS = 365 * 24 * 60 * 60 * 1000;

/** The bit index of the SAME status list that is deliberately left
 *  revoked, so the interactive control's "revoked credential" option can
 *  demonstrate a real `checkRevocation` refusal — index 0 (the clean
 *  bit) is never touched. */
const REVOKED_STATUS_INDEX = 1;

export interface CastDto {
  readonly issuerDid: string;
  readonly buyerDid: string;
  readonly attackerDid: string;
}

export interface PolicyDto {
  readonly id: string;
  readonly version: string;
  readonly action: string;
  readonly grantedMaxAmount: number;
}

/** One beat, JSON-shaped for the wire — `decision` is `Beat["decision"]`
 *  verbatim (already plain, serialisable data; see `decision.ts`'s
 *  module comment), never re-derived or re-worded here. */
export interface BeatDto {
  readonly id: Beat["id"];
  readonly title: string;
  readonly asker: string;
  readonly askedFor: string;
  readonly expected: "permitted" | "refused";
  readonly decision: Beat["decision"];
}

export interface FixedScenarioDto {
  readonly cast: CastDto;
  readonly policy: PolicyDto;
  readonly beats: readonly BeatDto[];
}

function toBeatDto(beat: Beat): BeatDto {
  return {
    id: beat.id,
    title: beat.title,
    asker: beat.asker,
    askedFor: beat.askedFor,
    expected: beat.expected,
    decision: beat.decision,
  };
}

/**
 * The fixed, at-rest four-beat story from `lib/negotiation/scenario.ts`,
 * reused unchanged (`runFourBeatScenario`) — the same function
 * `scripts/demo-negotiation.ts` calls for the terminal. Fresh Ed25519
 * keys are generated on every call (same as that script — see its own
 * module comment on why the DIDs differ run to run while the
 * RELATIONSHIP between them, e.g. Beat 3's identical DIDs, never does).
 */
export async function getFixedFourBeats(): Promise<FixedScenarioDto> {
  const { fixture, beats } = await runFourBeatScenario();
  return {
    cast: { issuerDid: fixture.issuer.did, buyerDid: fixture.buyer.did, attackerDid: fixture.attacker.did },
    policy: {
      id: fixture.policy.id,
      version: fixture.policy.version,
      action: ACTION,
      grantedMaxAmount: GRANTED_MAX_AMOUNT,
    },
    beats: beats.map(toBeatDto),
  };
}

/** The one interactive control M8 requires: a viewer picks a requested
 *  amount and, optionally, which attack to mount, and gets back a REAL
 *  decision from the REAL protocol — never a canned lookup table keyed
 *  by amount. */
export type AttackKind = "none" | "spoof-did" | "forge-credential" | "revoked-credential";

export const ATTACK_KINDS: readonly AttackKind[] = ["none", "spoof-did", "forge-credential", "revoked-credential"];

export interface CustomNegotiationInput {
  readonly amount: number;
  readonly attack: AttackKind;
}

export interface CustomNegotiationDto {
  readonly cast: CastDto;
  readonly asker: string;
  readonly askedFor: string;
  readonly attack: AttackKind;
  readonly decision: import("../../lib/negotiation/index.js").NegotiationDecision;
}

/**
 * Build a fresh, self-contained cast (issuer/buyer/attacker, a policy
 * identical in shape to the fixed scenario's, and a status list with one
 * clean and one already-revoked entry) and run ONE presentation through
 * a real `Supplier`, exactly the way `scenario.ts`'s own `runFourBeats`
 * does internally — this function only composes the SAME public
 * `lib/negotiation` + `lib/trust` primitives that module exports, never
 * anything private to `lib/`.
 *
 * A fresh cast per call (rather than one long-lived `Supplier` shared
 * across requests) is deliberate for this stateless demo endpoint: each
 * call is its own one-shot "session" — a challenge is issued and
 * consumed within the same function call, never round-tripped to the
 * client — so there is no cross-request nonce state for `Supplier`'s own
 * single-use tracking to need (see `supplier.ts`'s own deployment
 * warning about instance lifetime, which is about a MULTI-request
 * session, not this one-shot shape).
 */
export async function runCustomNegotiation(input: CustomNegotiationInput): Promise<CustomNegotiationDto> {
  const now = DEFAULT_SCENARIO_NOW;
  const issuer = new KeyHolder();
  const buyer = new KeyHolder();
  const attacker = new KeyHolder();
  const anchors = new TrustAnchorSet([issuer.did]);

  const statusListJwt = issuer.issueStatusListCredential({
    statusPurpose: "revocation",
    sizeBits: 128,
    revokedIndices: [REVOKED_STATUS_INDEX],
    now,
  });
  const resolver: StatusListResolver = (url: string) => {
    if (url !== STATUS_LIST_URL) {
      return Promise.reject(new Error(`no status list is published at ${url}`));
    }
    return Promise.resolve(statusListJwt);
  };

  const cleanStatus: CredentialStatusEntry = {
    type: "BitstringStatusListEntry",
    statusPurpose: "revocation",
    statusListIndex: 0,
    statusListCredential: STATUS_LIST_URL,
  };
  const revokedStatus: CredentialStatusEntry = { ...cleanStatus, statusListIndex: REVOKED_STATUS_INDEX };

  const validFrom = new Date(now).toISOString();
  const validUntil = new Date(now + ONE_YEAR_MS).toISOString();

  const buyerCleanJwt = issuer.issueAuthorityCredentialTo({
    subjectDid: buyer.did,
    action: ACTION,
    scope: { amount: GRANTED_MAX_AMOUNT },
    validFrom,
    validUntil,
    now,
  });
  const buyerRevokedJwt = issuer.issueAuthorityCredentialTo({
    subjectDid: buyer.did,
    action: ACTION,
    scope: { amount: GRANTED_MAX_AMOUNT },
    validFrom,
    validUntil,
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
  const challenge = supplier.issueChallenge();

  let presentation: Presentation;
  let asker: string;

  switch (input.attack) {
    case "spoof-did": {
      presentation = {
        proof: attacker.attemptProofOfPossessionFor(buyer.did, challenge),
        credentials: { authorityJwt: buyerCleanJwt, credentialStatus: cleanStatus },
      };
      asker = `Impostor claiming ${buyer.did} (real DID: ${attacker.did})`;
      break;
    }
    case "forge-credential": {
      const forgedJwt = attacker.issueAuthorityCredentialTo({
        subjectDid: attacker.did,
        action: ACTION,
        scope: { amount: 1_000_000 },
        validFrom,
        validUntil,
        now,
      });
      presentation = { proof: attacker.provePossession(challenge), credentials: { authorityJwt: forgedJwt } };
      asker = `Attacker ${attacker.did}`;
      break;
    }
    case "revoked-credential": {
      presentation = {
        proof: buyer.provePossession(challenge),
        credentials: { authorityJwt: buyerRevokedJwt, credentialStatus: revokedStatus },
      };
      asker = `Buyer ${buyer.did}`;
      break;
    }
    case "none":
    default: {
      presentation = {
        proof: buyer.provePossession(challenge),
        credentials: { authorityJwt: buyerCleanJwt, credentialStatus: cleanStatus },
      };
      asker = `Buyer ${buyer.did}`;
      break;
    }
  }

  const request: NegotiationRequest = { action: ACTION, scope: { amount: input.amount } };
  const decision = await supplier.evaluatePresentation(challenge, presentation, request);

  return {
    cast: { issuerDid: issuer.did, buyerDid: buyer.did, attackerDid: attacker.did },
    asker,
    askedFor: `${ACTION}, amount=${input.amount}`,
    attack: input.attack,
    decision,
  };
}

/** Re-exported purely so callers (the route handler, tests) can build a
 *  fixture-shaped sanity check without importing `lib/negotiation`
 *  directly a second time. Not used by the UI. */
export { buildFourBeatFixture };
