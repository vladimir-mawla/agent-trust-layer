/**
 * Issuance of authority credentials — the "may you?" claim. See ADR 0002
 * and `vc-types.ts` for why this is a distinct type and a distinct
 * function from `history.ts`'s `issueHistoryAttestation`, not a shared
 * `issueCredential(kind, ...)` with a string flag: a flag is something a
 * caller can get wrong at the call site with no compiler help; two
 * differently-typed functions are not.
 */
import type { Did } from "../identity/index.js";
import { verificationMethodId } from "./credential.js";
import { signCompactJws } from "./jws.js";
import {
  AUTHORITY_CREDENTIAL_TYPE,
  VC_BASE_TYPE,
  VC_CONTEXT_V2,
  type AuthorityClaim,
  type AuthorityCredential,
} from "./vc-types.js";

export interface IssueAuthorityCredentialInput {
  /** The issuer's private key. Used only in-process to produce the
   *  signature and never written into the resulting credential — see
   *  the repo's key-hygiene gate. */
  readonly issuerPrivateKey: Uint8Array;
  readonly issuerDid: Did;
  readonly subjectDid: Did;
  readonly action: string;
  readonly scope: AuthorityClaim["scope"];
  /**
   * REQUIRED, with no default. This is the API-level enforcement of "an
   * authority credential always expires" (the type-level enforcement is
   * `AuthorityCredential.validUntil` being non-optional) — there is
   * deliberately no fallback TTL a caller could forget to override and
   * silently get a non-expiring grant of authority.
   */
  readonly validUntil: string;
  /** Defaults to `now`. */
  readonly validFrom?: string;
  /** Opaque correlation id. Omitted by default — see `vc-types.ts`'s
   *  note on `id` and privacy. */
  readonly id?: string;
  /** Override "now" for deterministic tests. */
  readonly now?: number;
}

/** Issue and sign an `AuthorityCredential` as a compact VC-JWT. Returns
 *  the JWS string, ready to hand to `verifyAuthorityCredential`. */
export function issueAuthorityCredential(input: IssueAuthorityCredentialInput): string {
  const now = input.now ?? Date.now();
  const validFrom = input.validFrom ?? new Date(now).toISOString();

  const credential: AuthorityCredential = {
    "@context": [VC_CONTEXT_V2],
    ...(input.id !== undefined ? { id: input.id } : {}),
    type: [VC_BASE_TYPE, AUTHORITY_CREDENTIAL_TYPE],
    issuer: input.issuerDid,
    validFrom,
    validUntil: input.validUntil,
    credentialSubject: {
      id: input.subjectDid,
      action: input.action,
      scope: input.scope,
    },
  };

  // `iss` mirrors `issuer` rather than omitting or diverging from it —
  // VC-JOSE-COSE (§3.2) says implementers SHOULD avoid a JWT claim and a
  // VC property conflicting when they refer to the same thing; making
  // them identical satisfies that by construction. See `verify.ts`'s
  // issuer-identity step for what happens when a JWT claims a different
  // `iss` than its `issuer`, or is signed by neither.
  const payload = { ...credential, iss: input.issuerDid };

  return signCompactJws(payload, verificationMethodId(input.issuerDid), input.issuerPrivateKey);
}
