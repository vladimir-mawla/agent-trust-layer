/**
 * Public API of the trust module (M4): revocation (W3C Bitstring Status
 * List v1.0) and trust anchors + one level of issuer vouching, composed
 * with M3's credential verification into an explainable accept/refuse
 * decision. See `trust-decision.ts`'s module comment for why this
 * composes over `lib/credentials` rather than editing it, and
 * `status-list.ts`'s module comment for the offline/network tension
 * this whole module exists to make explicit.
 *
 * Framework-free by design, same as `lib/identity` and `lib/credentials`
 * — nothing here may import from Next.js or React. The one deliberate
 * departure from those two modules' fully-synchronous style is
 * `checkRevocation` (and everything that calls it): revocation is the
 * one check that cannot be done offline, so it is the one async
 * function in this package — see `status-list.ts`.
 */

export {
  BITSTRING_STATUS_LIST_CREDENTIAL_TYPE,
  BITSTRING_STATUS_LIST_TYPE,
  BITSTRING_STATUS_LIST_ENTRY_TYPE,
  DEFAULT_MAX_STATUS_LIST_AGE_MS,
  type CredentialStatusEntry,
  type BitstringStatusListCredential,
  type IssueStatusListCredentialInput,
  issueStatusListCredential,
  type StatusListResolver,
  type CheckRevocationOptions,
  type RevocationStatus,
  checkRevocation,
} from "./status-list.js";

export {
  MINIMUM_BITSTRING_BITS,
  createEmptyEncodedList,
  encodeList,
  withBitSet,
  decodeEncodedList,
  getStatusBit,
} from "./bitstring.js";

export {
  VOUCH_TYPE,
  VOUCHED_CAPABILITY_IDENTITY,
  type VouchSubject,
  type Vouch,
  type IssueVouchInput,
  issueVouch,
  type VerifiedVouch,
  type VerifyVouchOptions,
  verifyVouch,
} from "./vouch.js";

export {
  TrustAnchorSet,
  VOUCH_DEPTH_LIMIT,
  type IssuerTrustResult,
  type EvaluateIssuerTrustOptions,
  evaluateIssuerTrust,
} from "./anchors.js";

export {
  type EvaluateAuthorityTrustInput,
  type RevocationNotChecked,
  type TrustDecision,
  evaluateAuthorityCredentialTrust,
  type HistoryTrustDecision,
  type EvaluateHistoryTrustInput,
  evaluateHistoryAttestationTrust,
} from "./trust-decision.js";

export {
  StatusListUnavailableError,
  StatusListMalformedError,
  StatusListSignatureInvalidError,
  StatusListIssuerUnresolvableError,
  StatusListIssuerMismatchError,
  StatusListStaleError,
  StatusListPurposeMismatchError,
  BitstringIndexError,
  type RevocationFailureKind,
  type RevocationError,
  VouchMalformedError,
  VouchSignatureInvalidError,
  VouchIssuerUnresolvableError,
  VouchExpiredError,
  type VouchFailureKind,
} from "./errors.js";
