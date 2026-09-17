/**
 * The composition root of M4: combines M3's credential verification
 * (`lib/credentials`), PART 1's revocation check (`status-list.ts`), and
 * PART 2/3's issuer trust (`anchors.ts`) into one explainable
 * accept/refuse decision — closing M3's own finding 1 ("cryptographic
 * self-consistency currently reads as trustworthiness").
 *
 * ## Compose, don't edit M3 — and why that's not just a style choice
 *
 * M3's `verification-result.ts` deliberately types `revocationChecked`
 * as the literal `false` and says M4 "is expected to widen this to
 * `boolean` (or a richer status type)". This module does NOT do that by
 * editing `lib/credentials/verification-result.ts` in place. Two
 * independent reasons, not just a style preference:
 *
 *   1. **It would have to change more than a type.** `verify.ts`'s
 *      `verifyAuthorityCredential`/`verifyHistoryAttestation` are
 *      synchronous, and all 57 of M3's existing credential tests call
 *      them synchronously. A "real status" for `revocationChecked`
 *      requires asking a resolver — genuinely async I/O (see
 *      `status-list.ts`'s module comment on the offline/network
 *      tension) — so actually filling that field with a real value
 *      inside `verify.ts` would force `verifyAuthorityCredential` itself
 *      to become async, which is a breaking signature change, not an
 *      additive one. That fails this milestone's own constraint ("the
 *      change must be ADDITIVE... all 86 existing tests must still
 *      pass") before a single test is even run.
 *   2. **Even a same-shape extra field would be silently dropped.**
 *      `verify.ts`'s `verifyCredentialOfKind` builds its returned
 *      `credential` object by explicit field-by-field reconstruction
 *      from validated data, not by passing through whatever the JWT
 *      payload happened to contain. Any information not already
 *      threaded through that reconstruction (a `credentialStatus`
 *      field, say) never reaches a caller no matter how the TYPE is
 *      widened — see `status-list.ts`'s `CredentialStatusEntry` comment,
 *      which found the identical dead end for the spec's
 *      `credentialStatus` field and made the same choice for the same
 *      reason.
 *
 * So instead: `evaluateAuthorityCredentialTrust` below WRAPS a
 * `VerificationResult` (M3's own, completely unmodified, still
 * literally reporting `revocationChecked: false` because M3's own
 * chain still doesn't check revocation — that remains true) with its
 * OWN, separate `revocation` field carrying the real answer. Nothing
 * under `lib/credentials/` needed to change; `git diff -- lib/credentials/`
 * for this milestone is empty, exceeding the M1-freeze gate's bar by
 * choice, not by luck.
 */
import type { Did, ProofOfPossession } from "../identity/index.js";
import type { AuthorityCredential, HistoryAttestation, VerificationFailure, VerificationResult, VerificationSuccess } from "../credentials/index.js";
import { isVerified, verifyAuthorityCredential, verifyHistoryAttestation } from "../credentials/index.js";
import { evaluateIssuerTrust, type EvaluateIssuerTrustOptions, type IssuerTrustResult, type TrustAnchorSet } from "./anchors.js";
import { checkRevocation, type CredentialStatusEntry, type RevocationStatus, type StatusListResolver } from "./status-list.js";

export interface EvaluateAuthorityTrustInput {
  readonly jwt: string;
  readonly presenterProof: ProofOfPossession;
  readonly anchors: TrustAnchorSet;
  /** Candidate vouch JWTs available to consult — see `anchors.ts`. */
  readonly vouches?: readonly string[];
  /** If provided, revocation is checked via `statusListResolver`. If
   *  omitted, revocation is honestly reported as not-checked (see
   *  `RevocationStatus`'s sibling type below) rather than silently
   *  assumed clean — the same "never claim a check happened when it
   *  didn't" posture `revocationChecked: false` models in M3. */
  readonly credentialStatus?: CredentialStatusEntry;
  readonly statusListResolver?: StatusListResolver;
  readonly now?: number;
  readonly clockSkewMs?: number;
  readonly maxStatusListAgeMs?: number;
}

/** Reported when no `credentialStatus`/`statusListResolver` pair was
 *  supplied at all — distinct from every `RevocationStatus` outcome in
 *  `status-list.ts`, all of which imply a check was actually attempted. */
export interface RevocationNotChecked {
  readonly outcome: "not-checked";
  readonly reason: string;
}

export type TrustDecision<C extends AuthorityCredential | HistoryAttestation> =
  | {
      readonly accepted: false;
      readonly stage: "credential-verification";
      readonly reason: string;
      readonly credentialVerification: VerificationFailure;
    }
  | {
      readonly accepted: false;
      readonly stage: "issuer-trust";
      readonly reason: string;
      readonly credentialVerification: VerificationSuccess<C>;
      readonly issuerTrust: IssuerTrustResult & { readonly trusted: false };
    }
  | {
      readonly accepted: false;
      readonly stage: "revocation";
      readonly reason: string;
      readonly credentialVerification: VerificationSuccess<C>;
      readonly issuerTrust: IssuerTrustResult & { readonly trusted: true };
      readonly revocation: RevocationStatus & { readonly outcome: "revoked" | "indeterminate" };
    }
  | {
      readonly accepted: true;
      readonly reason: string;
      readonly credentialVerification: VerificationSuccess<C>;
      readonly issuerTrust: IssuerTrustResult & { readonly trusted: true };
      readonly revocation: (RevocationStatus & { readonly outcome: "active" }) | RevocationNotChecked;
    };

interface RevocationInputs {
  readonly credentialStatus?: CredentialStatusEntry;
  readonly statusListResolver?: StatusListResolver;
  readonly now?: number;
  readonly maxStatusListAgeMs?: number;
}

/**
 * `expectedIssuer` is threaded through as its own required parameter
 * (never folded into `RevocationInputs`, and never optional) so that
 * every call site here is forced, by the compiler, to supply the
 * credential's own M3-VERIFIED issuer — `verification.verifiedIssuer`,
 * never a claimed/unverified field — as the identity `checkRevocation`
 * requires the resolved status list to actually match. See
 * `status-list.ts`'s `checkRevocation` module comment for why that
 * parameter exists and is required there too.
 */
async function resolveRevocation(
  input: RevocationInputs,
  expectedIssuer: Did,
): Promise<(RevocationStatus & { readonly outcome: "active" }) | RevocationNotChecked | (RevocationStatus & { readonly outcome: "revoked" | "indeterminate" })> {
  if (input.credentialStatus === undefined || input.statusListResolver === undefined) {
    return { outcome: "not-checked", reason: "no credentialStatus/statusListResolver was supplied for this evaluation" };
  }
  const status = await checkRevocation(input.credentialStatus, input.statusListResolver, expectedIssuer, {
    ...(input.now !== undefined ? { now: input.now } : {}),
    ...(input.maxStatusListAgeMs !== undefined ? { maxStatusListAgeMs: input.maxStatusListAgeMs } : {}),
  });
  return status;
}

/**
 * Evaluate a presented `AuthorityCredential` end to end: verify it (M3),
 * decide whether its issuer should be believed (anchors + one level of
 * vouching), and check revocation. Every branch names a `stage` and a
 * `reason`, and carries the full structured detail behind that reason —
 * never a bare boolean, satisfying `every-decision-is-explainable` for
 * exactly the gap M3's finding 1 identified.
 */
export async function evaluateAuthorityCredentialTrust(input: EvaluateAuthorityTrustInput): Promise<TrustDecision<AuthorityCredential>> {
  const verification = verifyAuthorityCredential(input.jwt, input.presenterProof, {
    ...(input.now !== undefined ? { now: input.now } : {}),
    ...(input.clockSkewMs !== undefined ? { clockSkewMs: input.clockSkewMs } : {}),
  });

  if (!isVerified(verification)) {
    return {
      accepted: false,
      stage: "credential-verification",
      reason: `credential failed verification at step "${verification.step}": ${verification.reason}`,
      credentialVerification: verification,
    };
  }

  const issuerTrustOptions: EvaluateIssuerTrustOptions = {
    subject: verification.verifiedSubject,
    anchors: input.anchors,
    ...(input.vouches !== undefined ? { vouches: input.vouches } : {}),
    ...(input.now !== undefined ? { now: input.now } : {}),
  };
  const issuerTrust = evaluateIssuerTrust(verification.verifiedIssuer, issuerTrustOptions);

  if (!issuerTrust.trusted) {
    return {
      accepted: false,
      stage: "issuer-trust",
      reason: describeUntrustedIssuer(issuerTrust),
      credentialVerification: verification,
      issuerTrust,
    };
  }

  // The status list must be issued by THIS credential's own verified
  // issuer — `verification.verifiedIssuer` is M3's cryptographically
  // checked value, never `input`'s unverified/claimed data. See
  // `resolveRevocation`'s and `checkRevocation`'s comments for why this
  // is a required argument, not an optional one a caller could forget.
  const revocation = await resolveRevocation(input, verification.verifiedIssuer);
  if (revocation.outcome === "revoked" || revocation.outcome === "indeterminate") {
    return {
      accepted: false,
      stage: "revocation",
      reason: revocation.outcome === "revoked" ? `credential is revoked: ${revocation.reason}` : `revocation could not be confirmed (fail closed): ${revocation.reason}`,
      credentialVerification: verification,
      issuerTrust,
      revocation,
    };
  }

  return {
    accepted: true,
    reason:
      issuerTrust.reason.kind === "direct-anchor"
        ? `issuer ${verification.verifiedIssuer} is a direct trust anchor; ${revocationSummary(revocation)}`
        : `issuer ${verification.verifiedIssuer} is vouched for by anchor ${issuerTrust.reason.voucher}; ${revocationSummary(revocation)}`,
    credentialVerification: verification,
    issuerTrust,
    revocation,
  };
}

function revocationSummary(revocation: (RevocationStatus & { readonly outcome: "active" }) | RevocationNotChecked): string {
  return revocation.outcome === "active" ? "revocation checked and clean" : `revocation not checked (${revocation.reason})`;
}

function describeUntrustedIssuer(issuerTrust: IssuerTrustResult & { readonly trusted: false }): string {
  switch (issuerTrust.reason.kind) {
    case "self-issued":
      return `issuer ${issuerTrust.issuer} is the credential's own subject — self-issued authority is always refused`;
    case "untrusted-issuer":
      return `issuer ${issuerTrust.issuer} is neither a direct trust anchor nor vouched for by one`;
    case "vouch-depth-exceeded":
      return `issuer ${issuerTrust.issuer} is only reachable through a vouch chain deeper than the depth-1 limit`;
    default: {
      // Exhaustiveness guard: if `IssuerTrustResult`'s untrusted reason
      // union ever grows a new case, this fails to compile instead of
      // silently returning `undefined` from a "reason" that is supposed
      // to always be a concrete, explaining string.
      const exhaustive: never = issuerTrust.reason;
      return exhaustive;
    }
  }
}

/**
 * History attestations are never gated by trust anchors — see
 * `anchors.ts`'s module comment for why. This still runs M3's
 * verification and (if supplied) a revocation check, but there is no
 * `issuerTrust` stage to fail: an untrusted issuer's observation is
 * merely an unvetted observation, not a security hole, because
 * `HistoryAttestation` structurally cannot grant authority (ADR 0002).
 */
export type HistoryTrustDecision =
  | { readonly accepted: false; readonly stage: "credential-verification"; readonly reason: string; readonly credentialVerification: VerificationFailure }
  | {
      readonly accepted: false;
      readonly stage: "revocation";
      readonly reason: string;
      readonly credentialVerification: VerificationSuccess<HistoryAttestation>;
      readonly revocation: RevocationStatus & { readonly outcome: "revoked" | "indeterminate" };
    }
  | {
      readonly accepted: true;
      readonly reason: string;
      readonly credentialVerification: VerificationSuccess<HistoryAttestation>;
      readonly revocation: (RevocationStatus & { readonly outcome: "active" }) | RevocationNotChecked;
    };

export interface EvaluateHistoryTrustInput {
  readonly jwt: string;
  readonly presenterProof: ProofOfPossession;
  readonly credentialStatus?: CredentialStatusEntry;
  readonly statusListResolver?: StatusListResolver;
  readonly now?: number;
  readonly clockSkewMs?: number;
  readonly maxStatusListAgeMs?: number;
}

export async function evaluateHistoryAttestationTrust(input: EvaluateHistoryTrustInput): Promise<HistoryTrustDecision> {
  const verification = verifyHistoryAttestation(input.jwt, input.presenterProof, {
    ...(input.now !== undefined ? { now: input.now } : {}),
    ...(input.clockSkewMs !== undefined ? { clockSkewMs: input.clockSkewMs } : {}),
  });

  if (!isVerified(verification)) {
    return {
      accepted: false,
      stage: "credential-verification",
      reason: `credential failed verification at step "${verification.step}": ${verification.reason}`,
      credentialVerification: verification,
    };
  }

  // Same requirement as the authority-credential path above: the status
  // list must match THIS attestation's own verified issuer, not a
  // claimed one.
  const revocation = await resolveRevocation(
    {
      ...(input.credentialStatus !== undefined ? { credentialStatus: input.credentialStatus } : {}),
      ...(input.statusListResolver !== undefined ? { statusListResolver: input.statusListResolver } : {}),
      ...(input.now !== undefined ? { now: input.now } : {}),
      ...(input.maxStatusListAgeMs !== undefined ? { maxStatusListAgeMs: input.maxStatusListAgeMs } : {}),
    },
    verification.verifiedIssuer,
  );

  if (revocation.outcome === "revoked" || revocation.outcome === "indeterminate") {
    return {
      accepted: false,
      stage: "revocation",
      reason: revocation.outcome === "revoked" ? `credential is revoked: ${revocation.reason}` : `revocation could not be confirmed (fail closed): ${revocation.reason}`,
      credentialVerification: verification,
      revocation,
    };
  }

  return {
    accepted: true,
    reason: `history attestation verified; ${revocationSummary(revocation)}`,
    credentialVerification: verification,
    revocation,
  };
}
