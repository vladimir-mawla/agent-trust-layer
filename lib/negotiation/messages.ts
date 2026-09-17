/**
 * The M6 protocol's message shapes, named explicitly so the exchange is
 * legible as a protocol rather than an ad hoc function call:
 *
 *   1. **request**  — `NegotiationRequest`: what the counterparty wants
 *      to do. Reuses `lib/policy`'s own `PolicyRequest` verbatim — it is
 *      the identical message, not a lookalike this module redefines.
 *   2. **challenge** — `Challenge`: the Supplier's freshness challenge.
 *      Reuses `lib/identity`'s own type verbatim, same reasoning.
 *   3. **presentation** — `Presentation`: the requester's response —
 *      a signed `ProofOfPossession` over that exact challenge, plus the
 *      credentials it offers as evidence for the request. This is new
 *      at this layer: M1-M5 never needed a single envelope bundling a
 *      proof with a credential set, because M6 is the first place two
 *      independent agents actually exchange one over a "wire".
 *   4. **decision** — `NegotiationDecision` (`decision.ts`): the
 *      Supplier's answer, always a structured explanation, never a bare
 *      boolean — see that module's own comment.
 *
 * Deliberately absent from `NegotiationRequest`/`Presentation`: any
 * "who is asking" field the Supplier is expected to just believe. The
 * ONLY way the Supplier learns who it's talking to is by verifying
 * `presentation.proof` (`supplier.ts`) — the resulting `Did` is read off
 * cryptographic proof, never off a claimed field on the message.
 */
import type { Challenge, ProofOfPossession } from "../identity/index.js";
import type { PolicyRequest } from "../policy/index.js";
import type { CredentialStatusEntry } from "../trust/index.js";

export type { Challenge, ProofOfPossession };

/** What the counterparty wants to do — identical in shape to
 *  `lib/policy`'s `PolicyRequest`, re-exported under this protocol's own
 *  name because from the negotiation's point of view this is a message
 *  a counterparty sends, not merely an engine input. */
export type NegotiationRequest = PolicyRequest;

/** The credentials a presenter offers as evidence for its request. Every
 *  field here is exactly what M3/M4 already know how to verify — this
 *  type adds no new credential machinery, only bundles references to
 *  what exists. */
export interface PresentedCredentials {
  /** A compact VC-JWT `AuthorityCredential` (`lib/credentials`). */
  readonly authorityJwt: string;
  /** How to check `authorityJwt`'s own revocation status (`lib/trust`).
   *  Omitted entirely means revocation is honestly reported
   *  "not-checked" — see `lib/trust/trust-decision.ts`'s
   *  `RevocationNotChecked` and the mandatory policy gate M5 built for
   *  exactly that omission. */
  readonly credentialStatus?: CredentialStatusEntry;
  /** Compact VC-JWT `HistoryAttestation`s accompanying the request, if
   *  any. Never itself capable of granting authority — ADR 0002. */
  readonly historyJwts?: readonly string[];
  /** Candidate `Vouch` JWTs (`lib/trust/vouch.ts`) the presenter offers
   *  as evidence that `authorityJwt`'s own issuer — even if it is not
   *  one of the Supplier's configured trust anchors directly — is
   *  vouched for by one, per M4's exactly-one-level-of-delegation model
   *  (`lib/trust/anchors.ts`'s `evaluateIssuerTrust`,
   *  `VOUCH_DEPTH_LIMIT`). Omitted entirely (or empty) means "no vouches
   *  offered" — an issuer that is not itself a direct anchor is then
   *  refused as `untrusted-issuer`, exactly as before this field
   *  existed. Before this field, M4's `vouched` trust path existed in
   *  `lib/trust` but was structurally unreachable through this
   *  protocol — see `supplier.ts`'s own comment on why this array is
   *  capped before being forwarded. */
  readonly vouches?: readonly string[];
}

/**
 * The requester's response to a `Challenge`: a signed proof of
 * possession over that exact challenge, plus the credentials it offers.
 * This is the ONLY message shape through which a Supplier ever receives
 * anything about a counterparty — see this module's own comment.
 */
export interface Presentation {
  readonly proof: ProofOfPossession;
  readonly credentials: PresentedCredentials;
}
