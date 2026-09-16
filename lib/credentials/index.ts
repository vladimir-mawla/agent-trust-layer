/**
 * Public API of the credentials module (M3): W3C Verifiable Credentials
 * (targeting VC Data Model 2.0 — see `vc-types.ts`), signed and verified
 * as compact VC-JWTs with Ed25519, split into two structurally distinct
 * claim kinds (`AuthorityCredential`, `HistoryAttestation` — see ADR
 * 0002) and a fail-closed, ordered verification chain (see `verify.ts`).
 *
 * Framework-free by design, same as `lib/identity` — nothing here may
 * import from Next.js or React.
 */

export {
  VC_CONTEXT_V2,
  VC_BASE_TYPE,
  AUTHORITY_CREDENTIAL_TYPE,
  HISTORY_ATTESTATION_TYPE,
  type CredentialSubjectBase,
  type VerifiableCredentialShape,
  type AuthorityClaim,
  type AuthorityCredentialSubject,
  type AuthorityCredential,
  type HistoryClaim,
  type HistoryAttestationSubject,
  type HistoryAttestation,
  type AnyCredential,
} from "./vc-types.js";

export { issueAuthorityCredential, type IssueAuthorityCredentialInput } from "./authority.js";
export { issueHistoryAttestation, type IssueHistoryAttestationInput } from "./history.js";

export {
  verifyAuthorityCredential,
  verifyHistoryAttestation,
  type VerifyCredentialOptions,
} from "./verify.js";

export {
  isVerified,
  type VerificationFailure,
  type VerificationSuccess,
  type VerificationResult,
} from "./verification-result.js";

export type { VerificationStep } from "./errors.js";
export {
  MalformedJwsError,
  AlgorithmNotAllowedError,
  UnresolvableSigningKeyError,
  SignatureVerificationFailedError,
  CredentialStructureError,
  CredentialNotYetValidError,
  CredentialExpiredError,
  SubjectBindingError,
  IssuerIdentityMismatchError,
} from "./errors.js";

export { verificationMethodId, DEFAULT_CLOCK_SKEW_MS } from "./credential.js";

// Low-level JWS primitives are exported for tests (including the jose
// interop suite) and any future module that needs to inspect a compact
// JWS's shape directly — but the trust-sensitive ordering itself
// (parse -> verify signature -> only then decode payload) lives entirely
// in `jws.ts` and `verify.ts`, not in whatever imports these.
export { ALLOWED_ALG, VC_JWT_TYP, MAX_JWS_LENGTH, parseCompactJws, type JwsHeader, type ParsedJws } from "./jws.js";
export { encodeBase64Url, decodeBase64Url } from "./base64url.js";
