/**
 * Trust anchors — PART 2 of M4: each verifying agent's own configurable
 * set of issuer DIDs it accepts, plus (PART 3) exactly one level of
 * vouching on top of that set.
 *
 * ## Why this exists at all
 *
 * `lib/credentials/verify.ts`'s own doc comment says it plainly:
 * "`ok: true` means the credential is internally consistent and
 * correctly signed — NOT that the issuer is trustworthy... Deciding
 * whether that issuer should be believed is M4's job." A perfectly
 * self-consistent credential — real signature, real `did:key`, correct
 * subject binding — proves only that SOMEONE who controls that key
 * signed it. Nothing about cryptographic self-consistency says that
 * someone should be believed. This file is where "should be believed"
 * gets decided, and it is decided per VERIFYING AGENT (an anchor set is
 * a parameter, not a global), because two agents can reasonably trust
 * different issuers for the same kind of claim.
 *
 * ## Self-issued authority is refused unconditionally
 *
 * `evaluateIssuerTrust` checks self-issuance BEFORE consulting the
 * anchor set at all, and refuses it regardless of whether the DID in
 * question happens to also be a configured anchor. This is a deliberate
 * choice, not an accident of check ordering — see "Alternatives
 * rejected" in ADR 0003. The anchor model's entire meaning is "someone
 * ELSE vouches for this issuer's authority to act on a third party"; an
 * issuer minting authority over itself collapses that to "I say I may,
 * therefore I may", which is exactly the self-consistency-reads-as-
 * trustworthiness hole M3's own L4 finding 1 named. Letting a coincidence
 * of anchor-set membership carve out an exception would reopen that hole
 * for precisely the DID an operator most needs it closed for (their own
 * root anchor is exactly the identity a compromised or careless
 * configuration would use to self-issue with an air of legitimacy).
 *
 * ## Anchors apply to AUTHORITY, not history
 *
 * `evaluateIssuerTrust` is only ever called for authority credentials
 * (see `trust-decision.ts`). History attestations are deliberately NOT
 * gated by this module: ADR 0002 already decided that history "may
 * tighten a decision but never loosen one" and is structurally
 * incapable of granting authority (`HistoryAttestation` has no
 * `action`/`scope`). An observation from an issuer nobody vouches for is
 * not worthless — "agent X completed 12 transactions with agent Y" can
 * still be true and still be worth recording, and a future M5 policy
 * might reasonably discount it rather than discard it. What matters is
 * that it can NEVER expand what an already-granted authority credential
 * allows, and that guarantee comes from ADR 0002's type separation, not
 * from gatekeeping who is allowed to observe things. Gatekeeping issuers
 * of history the same way as issuers of authority would suggest history
 * needs "vetting" to be meaningful at all — but its meaning (an
 * observation) doesn't depend on the observer being pre-approved the way
 * a GRANT of power does. So: no anchor check for history, by design.
 */
import type { Did } from "../identity/index.js";
import { verifyVouch } from "./vouch.js";

/** A verifying agent's own configurable set of directly-trusted issuer
 *  DIDs. Deliberately just a `ReadonlySet<Did>` wrapper — an anchor set
 *  is per-agent configuration data, not something this module computes;
 *  callers build one however they like (a config file, an env var, a
 *  hardcoded demo list) and hand it in. */
export class TrustAnchorSet {
  private readonly anchors: ReadonlySet<Did>;

  constructor(anchors: Iterable<Did>) {
    this.anchors = new Set(anchors);
  }

  has(did: Did): boolean {
    return this.anchors.has(did);
  }

  /** For explanations/tests that want to enumerate the configured set. */
  list(): readonly Did[] {
    return [...this.anchors];
  }
}

/** Depth limit for vouching, enforced structurally — see the module
 *  comment in `vouch.ts`. A real constant, not merely "no recursion
 *  happens to be implemented": raising it later means adding actual
 *  chain-walking logic, a deliberate code change this constant exists
 *  to make visible. */
export const VOUCH_DEPTH_LIMIT = 1;

export type IssuerTrustResult =
  | { readonly trusted: true; readonly issuer: Did; readonly reason: { readonly kind: "direct-anchor" } }
  | { readonly trusted: true; readonly issuer: Did; readonly reason: { readonly kind: "vouched"; readonly voucher: Did } }
  | { readonly trusted: false; readonly issuer: Did; readonly reason: { readonly kind: "self-issued" } }
  | { readonly trusted: false; readonly issuer: Did; readonly reason: { readonly kind: "untrusted-issuer" } }
  | { readonly trusted: false; readonly issuer: Did; readonly reason: { readonly kind: "vouch-depth-exceeded" } };

export interface EvaluateIssuerTrustOptions {
  /** The authority credential's own subject DID — used ONLY to detect
   *  self-issuance (`issuer === subject`). */
  readonly subject: Did;
  readonly anchors: TrustAnchorSet;
  /** Candidate vouch JWTs available to consult — e.g. ones the
   *  presenting agent bundled alongside its credential. Each is
   *  independently signature-verified; an invalid one is silently
   *  skipped (not treated as a fatal error for the whole evaluation —
   *  it simply cannot establish trust), matching "a vouch whose own
   *  signature fails -> refused [for THAT vouch]" rather than aborting
   *  the whole check over one bad candidate among possibly several. */
  readonly vouches?: readonly string[];
  /** Override "now" for deterministic tests (vouch expiry). */
  readonly now?: number;
}

/**
 * Decide whether `issuer` (an authority credential's cryptographically
 * confirmed issuer — see `lib/credentials/verification-result.ts`'s
 * `verifiedIssuer`) should be trusted to have granted that authority.
 *
 * Order of checks, each one explained in the module comment above:
 *   1. self-issued -> always refused, unconditionally.
 *   2. direct anchor membership -> accepted, explanation names it.
 *   3. exactly one level of vouching: a vouch whose OWN issuer is a
 *      direct anchor, whose subject is `issuer`, and whose own signature
 *      and expiry check out -> accepted, explanation NAMES the voucher.
 *      A vouch whose issuer is itself only vouched-for (not a direct
 *      anchor) is never consulted — see `VOUCH_DEPTH_LIMIT`'s comment
 *      for why that alone is what refuses a depth-2 chain.
 *   4. otherwise -> untrusted-issuer.
 */
export function evaluateIssuerTrust(issuer: Did, options: EvaluateIssuerTrustOptions): IssuerTrustResult {
  if (issuer === options.subject) {
    return { trusted: false, issuer, reason: { kind: "self-issued" } };
  }

  if (options.anchors.has(issuer)) {
    return { trusted: true, issuer, reason: { kind: "direct-anchor" } };
  }

  const now = options.now ?? Date.now();
  for (const vouchJwt of options.vouches ?? []) {
    const verified = verifyVouch(vouchJwt, { now });
    if (!verified.ok) {
      // This one candidate vouch doesn't check out — keep looking rather
      // than failing the whole evaluation; see EvaluateIssuerTrustOptions.
      continue;
    }
    // VOUCH_DEPTH_LIMIT enforcement: only a vouch issued DIRECTLY by an
    // anchor counts. A vouch issued by anyone else — including someone
    // who is themselves only vouched-for — is exactly a depth-2 chain,
    // and this `if` is the whole enforcement: there is no recursive
    // lookup to walk it, by construction (`vouch-depth.test.ts` proves
    // both that a depth-2 chain is refused and that `VOUCH_DEPTH_LIMIT`
    // is the literal `1` this check assumes).
    if (!options.anchors.has(verified.voucher)) {
      continue;
    }
    if (verified.vouch.credentialSubject.id === issuer) {
      return { trusted: true, issuer, reason: { kind: "vouched", voucher: verified.voucher } };
    }
  }

  return { trusted: false, issuer, reason: { kind: "untrusted-issuer" } };
}
