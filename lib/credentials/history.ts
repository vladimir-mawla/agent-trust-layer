/**
 * Issuance of history attestations — the "should I?" claim. See ADR 0002
 * and `vc-types.ts` for why this is a distinct type and function from
 * `authority.ts`'s `issueAuthorityCredential`.
 */
import type { Did } from "../identity/index.js";
import { verificationMethodId } from "./credential.js";
import { signCompactJws } from "./jws.js";
import {
  HISTORY_ATTESTATION_TYPE,
  VC_BASE_TYPE,
  VC_CONTEXT_V2,
  type HistoryAttestation,
  type HistoryClaim,
} from "./vc-types.js";

export interface IssueHistoryAttestationInput {
  /** The issuer's private key. Used only in-process to produce the
   *  signature and never written into the resulting credential. */
  readonly issuerPrivateKey: Uint8Array;
  readonly issuerDid: Did;
  readonly subjectDid: Did;
  readonly observationType: string;
  readonly metrics: HistoryClaim["metrics"];
  readonly observationPeriod?: HistoryClaim["observationPeriod"];
  /** Unlike `AuthorityCredential`, a history attestation has no
   *  obligation to expire — it is a record of what was observed, not a
   *  grant. Both remain optional; pass `validUntil` if this particular
   *  attestation should stop being presentable after some point. */
  readonly validFrom?: string;
  readonly validUntil?: string;
  readonly id?: string;
  /** Override "now" for deterministic tests. */
  readonly now?: number;
}

/** Issue and sign a `HistoryAttestation` as a compact VC-JWT. Returns the
 *  JWS string, ready to hand to `verifyHistoryAttestation`. */
export function issueHistoryAttestation(input: IssueHistoryAttestationInput): string {
  const now = input.now ?? Date.now();
  const validFrom = input.validFrom ?? new Date(now).toISOString();

  const credential: HistoryAttestation = {
    "@context": [VC_CONTEXT_V2],
    ...(input.id !== undefined ? { id: input.id } : {}),
    type: [VC_BASE_TYPE, HISTORY_ATTESTATION_TYPE],
    issuer: input.issuerDid,
    validFrom,
    ...(input.validUntil !== undefined ? { validUntil: input.validUntil } : {}),
    credentialSubject: {
      id: input.subjectDid,
      observationType: input.observationType,
      metrics: input.metrics,
      ...(input.observationPeriod !== undefined ? { observationPeriod: input.observationPeriod } : {}),
    },
  };

  // `iss` mirrors `issuer` — see the identical note in `authority.ts`.
  const payload = { ...credential, iss: input.issuerDid };

  return signCompactJws(payload, verificationMethodId(input.issuerDid), input.issuerPrivateKey);
}
