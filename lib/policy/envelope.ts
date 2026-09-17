/**
 * TIGHTEN_NEVER_LOOSEN, part 1: the one function in this whole module
 * allowed to ORIGINATE a permitted envelope (an action + a scope), and
 * why its own parameter type makes it structurally impossible to call
 * with anything derived from history.
 *
 * `computeAuthorityEnvelope` takes `TrustDecision<AuthorityCredential> &
 * { accepted: true }` — never `HistoryTrustDecision`, never a union of
 * the two, never `unknown`. That type distinction is not cosmetic: ADR
 * 0002 already made `AuthorityCredential` and `HistoryAttestation`
 * structurally distinct (different `credentialSubject` shapes, no
 * common supertype either could satisfy), and `TrustDecision<C>`/
 * `HistoryTrustDecision` (`lib/trust/trust-decision.ts`) each wrap
 * M3's own `VerificationSuccess<C>` — generic over that same `C`. The
 * net effect: `HistoryTrustDecision`'s accepted variant has
 * `credentialVerification: VerificationSuccess<HistoryAttestation>`,
 * which cannot structurally satisfy this function's required
 * `VerificationSuccess<AuthorityCredential>` — there is no field
 * renaming or widening away from that, short of editing ADR 0002's own
 * frozen type split. `type-boundary.test.ts` proves this compiles to a
 * `@ts-expect-error`, and separately proves at RUNTIME that even a
 * maximally generous, unrelated history attestation sitting alongside a
 * real authority credential changes nothing about the computed
 * envelope — see that file for both.
 *
 * `engine.ts` is the only caller, and calls this ONLY after confirming
 * `authority !== null && authority.accepted === true` — if no authority
 * credential was ever presented and accepted, this function is simply
 * never invoked, and the engine refuses under `GATE_AUTHORITY_REQUIRED`
 * before it would even have anything to call this with. That is how
 * "history attestations present but no authority -> still refused" and
 * "an authority credential is always required" hold structurally,
 * not merely by the engine choosing to check in the right order.
 */
import type { Did } from "../identity/index.js";
import type { AuthorityCredential } from "../credentials/index.js";
import type { TrustDecision } from "../trust/index.js";

export interface AuthorityEnvelope {
  readonly action: string;
  readonly scope: Readonly<Record<string, unknown>>;
  readonly issuer: Did;
}

export function computeAuthorityEnvelope(decision: TrustDecision<AuthorityCredential> & { readonly accepted: true }): AuthorityEnvelope {
  const credential = decision.credentialVerification.credential;
  return {
    action: credential.credentialSubject.action,
    scope: credential.credentialSubject.scope,
    issuer: decision.credentialVerification.verifiedIssuer,
  };
}
