/**
 * The verification chain — the heart of M3.
 *
 * Runs in this fixed order, failing closed at each step, with every
 * subsequent step allowed to trust a little more of the credential than
 * the one before it:
 *
 *   1. **parse**            — is this even a well-formed compact JWS?
 *   2. **signature**        — verified against the public key recovered
 *                              from the JWS header's `kid` (a `did:key`).
 *                              `decodeVerifiedPayload` (in `jws.ts`) is
 *                              structurally impossible to call before
 *                              this step succeeds — see that module's
 *                              comment. NOTHING inside the credential is
 *                              read before this passes.
 *   3. **structure**        — now that the bytes are trusted, does the
 *                              decoded JSON actually have the required
 *                              W3C VC fields, well-formed, and of the
 *                              expected credential kind?
 *   4. **temporal**         — not used before `validFrom`, not used
 *                              after `validUntil`, with explicit clock
 *                              skew (`DEFAULT_CLOCK_SKEW_MS`).
 *   5. **subject-binding**  — `credentialSubject.id` must equal the DID
 *                              the PRESENTER actually proved possession
 *                              of, via `lib/identity`'s `verifyPossession`.
 *                              This is what stops agent B replaying agent
 *                              A's credential: B can prove possession of
 *                              B's own key, never A's.
 *   6. **issuer-identity**  — the credential's claimed issuer must be the
 *                              SAME key that produced the signature (not
 *                              merely "a signature that verifies against
 *                              *something*" — step 2 already established
 *                              that; this step asks whether the signer is
 *                              who the payload says it is).
 *
 * **Revocation is a named, deliberately-unimplemented step for M4.** It
 * is NOT a member of `VerificationStep` (see `errors.ts`), and every
 * successful result's `revocationChecked` field is the typed literal
 * `false` — see `verification-result.ts` for why that's typed as `false`
 * and not `boolean`. There is no code below that silently treats an
 * unrevoked-but-unchecked credential as revocation-clean.
 */
import { decodeDidKey, encodeDidKey, verifyPossession, type Did, type ProofOfPossession } from "../identity/index.js";
import { didFromKid, DEFAULT_CLOCK_SKEW_MS } from "./credential.js";
import {
  CredentialExpiredError,
  CredentialNotYetValidError,
  CredentialStructureError,
  IssuerIdentityMismatchError,
  SubjectBindingError,
  UnresolvableSigningKeyError,
  type VerificationStep,
} from "./errors.js";
import { decodeVerifiedPayload, parseCompactJws, verifySignature, type ParsedJws, type SignatureVerified } from "./jws.js";
import {
  AUTHORITY_CREDENTIAL_TYPE,
  HISTORY_ATTESTATION_TYPE,
  VC_BASE_TYPE,
  VC_CONTEXT_V2,
  type AnyCredential,
  type AuthorityClaim,
  type AuthorityCredential,
  type HistoryAttestation,
  type HistoryClaim,
} from "./vc-types.js";
import type { VerificationFailure, VerificationResult } from "./verification-result.js";

export interface VerifyCredentialOptions {
  /** Override "now" for deterministic tests. Defaults to `Date.now()`. */
  readonly now?: number;
  /** Override the default clock-skew tolerance (`DEFAULT_CLOCK_SKEW_MS`). */
  readonly clockSkewMs?: number;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Map a thrown error to a `VerificationFailure`, preferring the step the
 *  error itself names (every typed error in `errors.ts` carries one) and
 *  falling back to `fallbackStep` for anything else (e.g. a native
 *  `SyntaxError` this module didn't anticipate) so a truly unexpected
 *  throw still becomes a structured, named-step failure instead of
 *  propagating as an unhandled exception. */
function failureFrom(error: unknown, fallbackStep: VerificationStep): VerificationFailure {
  const step =
    error instanceof Error && "step" in error && typeof (error as { step: unknown }).step === "string"
      ? ((error as { step: string }).step as VerificationStep)
      : fallbackStep;
  return { ok: false, step, reason: errorMessage(error), cause: error };
}

/** Everything the base VC shape needs, once validated. Kept apart from
 *  the raw claim (`AuthorityClaim`/`HistoryClaim`) so the same function
 *  validates both credential kinds' shared fields. */
interface ValidatedBase {
  readonly context: readonly string[];
  readonly id?: string;
  readonly type: readonly string[];
  readonly issuer: Did;
  readonly validFrom: string;
  readonly validUntil?: string;
  readonly subjectId: Did;
  readonly subjectRecord: Record<string, unknown>;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validateBaseStructure(payload: unknown, expectedKind: string): ValidatedBase {
  if (!isPlainObject(payload)) {
    throw new CredentialStructureError("payload is not a JSON object");
  }

  const context = payload["@context"];
  if (!Array.isArray(context) || context[0] !== VC_CONTEXT_V2) {
    throw new CredentialStructureError(`"@context" must be an array whose first entry is "${VC_CONTEXT_V2}"`);
  }

  const type = payload["type"];
  if (!Array.isArray(type) || type[0] !== VC_BASE_TYPE) {
    throw new CredentialStructureError(`"type" must be an array whose first entry is "${VC_BASE_TYPE}"`);
  }
  if (type[1] !== expectedKind) {
    throw new CredentialStructureError(`expected credential type "${expectedKind}", got ${JSON.stringify(type[1] ?? null)}`);
  }

  const issuer = payload["issuer"];
  if (typeof issuer !== "string") {
    throw new CredentialStructureError('"issuer" must be a string did:key');
  }
  try {
    decodeDidKey(issuer);
  } catch (cause) {
    throw new CredentialStructureError(`"issuer" is not a well-formed did:key: ${errorMessage(cause)}`);
  }

  const iss = payload["iss"];
  if (iss !== undefined && iss !== issuer) {
    throw new CredentialStructureError(
      `JWT "iss" (${JSON.stringify(iss)}) conflicts with credential "issuer" (${JSON.stringify(issuer)})`,
    );
  }

  const validFrom = payload["validFrom"];
  if (typeof validFrom !== "string" || Number.isNaN(Date.parse(validFrom))) {
    throw new CredentialStructureError('"validFrom" must be a valid ISO 8601 date-time string');
  }

  const validUntilRaw = payload["validUntil"];
  if (validUntilRaw !== undefined) {
    if (typeof validUntilRaw !== "string" || Number.isNaN(Date.parse(validUntilRaw))) {
      throw new CredentialStructureError('"validUntil" must be a valid ISO 8601 date-time string when present');
    }
  } else if (expectedKind === AUTHORITY_CREDENTIAL_TYPE) {
    throw new CredentialStructureError('AuthorityCredential requires "validUntil" (authority must always expire)');
  }

  const credentialSubject = payload["credentialSubject"];
  if (!isPlainObject(credentialSubject)) {
    throw new CredentialStructureError('"credentialSubject" must be an object');
  }
  const subjectId = credentialSubject["id"];
  if (typeof subjectId !== "string") {
    throw new CredentialStructureError('"credentialSubject.id" must be a string did:key');
  }
  try {
    decodeDidKey(subjectId);
  } catch (cause) {
    throw new CredentialStructureError(`"credentialSubject.id" is not a well-formed did:key: ${errorMessage(cause)}`);
  }

  const id = payload["id"];
  if (id !== undefined && typeof id !== "string") {
    throw new CredentialStructureError('"id" must be a string when present');
  }

  return {
    context: context as readonly string[],
    ...(id !== undefined ? { id } : {}),
    type: type as readonly string[],
    issuer: issuer as Did,
    validFrom,
    ...(validUntilRaw !== undefined ? { validUntil: validUntilRaw as string } : {}),
    subjectId: subjectId as Did,
    subjectRecord: credentialSubject,
  };
}

function validateAuthorityClaim(subjectRecord: Record<string, unknown>): AuthorityClaim {
  const action = subjectRecord["action"];
  if (typeof action !== "string" || action.length === 0) {
    throw new CredentialStructureError('"credentialSubject.action" must be a non-empty string');
  }
  const scope = subjectRecord["scope"];
  if (!isPlainObject(scope)) {
    throw new CredentialStructureError('"credentialSubject.scope" must be an object');
  }
  return { action, scope };
}

function validateHistoryClaim(subjectRecord: Record<string, unknown>): HistoryClaim {
  const observationType = subjectRecord["observationType"];
  if (typeof observationType !== "string" || observationType.length === 0) {
    throw new CredentialStructureError('"credentialSubject.observationType" must be a non-empty string');
  }
  const metrics = subjectRecord["metrics"];
  if (!isPlainObject(metrics)) {
    throw new CredentialStructureError('"credentialSubject.metrics" must be an object');
  }
  for (const [key, value] of Object.entries(metrics)) {
    if (typeof value !== "number") {
      throw new CredentialStructureError(`"credentialSubject.metrics.${key}" must be a number`);
    }
  }

  const observationPeriodRaw = subjectRecord["observationPeriod"];
  if (observationPeriodRaw === undefined) {
    return { observationType, metrics: metrics as HistoryClaim["metrics"] };
  }
  if (!isPlainObject(observationPeriodRaw)) {
    throw new CredentialStructureError('"credentialSubject.observationPeriod" must be an object when present');
  }
  const { from, until } = observationPeriodRaw;
  if (typeof from !== "string" || Number.isNaN(Date.parse(from))) {
    throw new CredentialStructureError('"credentialSubject.observationPeriod.from" must be a valid date-time string');
  }
  if (typeof until !== "string" || Number.isNaN(Date.parse(until))) {
    throw new CredentialStructureError('"credentialSubject.observationPeriod.until" must be a valid date-time string');
  }
  return { observationType, metrics: metrics as HistoryClaim["metrics"], observationPeriod: { from, until } };
}

/** The shared engine both `verifyAuthorityCredential` and
 *  `verifyHistoryAttestation` are thin, precisely-typed wrappers around.
 *  Not exported: callers always ask for one kind or the other, never
 *  "a credential of whatever kind this turns out to be". */
function verifyCredentialOfKind<Kind extends string, Claim extends object, C extends AnyCredential>(
  jwt: string,
  expectedKind: Kind,
  validateClaim: (subjectRecord: Record<string, unknown>) => Claim,
  presenterProof: ProofOfPossession,
  options: VerifyCredentialOptions,
): VerificationResult<C> {
  const now = options.now ?? Date.now();
  const clockSkewMs = options.clockSkewMs ?? DEFAULT_CLOCK_SKEW_MS;

  // --- Step 1: parse -----------------------------------------------
  let parsed: ParsedJws;
  try {
    parsed = parseCompactJws(jwt);
  } catch (error) {
    return failureFrom(error, "parse");
  }

  // --- Step 2: signature ---------------------------------------------
  // `kid` is JWS transport metadata, inspected here only to select which
  // public key to check the signature against — never to decide *how*
  // to check it (see `jws.ts`'s `verifySignature`, which hardcodes the
  // one algorithm it accepts regardless of what the header claims).
  const signingDidCandidate = didFromKid(parsed.header.kid);
  let signingPublicKey: Uint8Array;
  try {
    signingPublicKey = decodeDidKey(signingDidCandidate);
  } catch (cause) {
    const wrapped = new UnresolvableSigningKeyError(parsed.header.kid, { cause });
    return { ok: false, step: wrapped.step, reason: wrapped.message, cause: wrapped };
  }
  const signingDid = signingDidCandidate as Did;

  let verifiedToken: SignatureVerified;
  try {
    verifiedToken = verifySignature(parsed, signingPublicKey);
  } catch (error) {
    return failureFrom(error, "signature");
  }

  // Only NOW is the payload decoded to JSON — `decodeVerifiedPayload`
  // requires `verifiedToken`, which could only be produced by the
  // successful `verifySignature` call above. A signature can be
  // perfectly valid over bytes that still aren't valid JSON (an attacker
  // signing arbitrary non-JSON bytes with their OWN real key), so this
  // can throw `MalformedJwsError` exactly like `parseCompactJws` above
  // does for the header segment — same failure class ("the wire format
  // can't be parsed at all"), just discovered one step later because the
  // payload, unlike the header, isn't inspected until after the
  // signature check. `failureFrom` picks up `MalformedJwsError`'s own
  // `step: "parse"` here, so this is labeled identically to step 1.
  let payload: unknown;
  try {
    payload = decodeVerifiedPayload(parsed, verifiedToken);
  } catch (error) {
    return failureFrom(error, "parse");
  }

  // --- Step 3: structure -----------------------------------------------
  let base: ValidatedBase;
  let claim: Claim;
  try {
    base = validateBaseStructure(payload, expectedKind);
    claim = validateClaim(base.subjectRecord);
  } catch (error) {
    return failureFrom(error, "structure");
  }

  // --- Step 4: temporal, with explicit clock skew ---------------------
  const validFromMs = Date.parse(base.validFrom);
  if (now + clockSkewMs < validFromMs) {
    const cause = new CredentialNotYetValidError(base.validFrom, now);
    return { ok: false, step: "temporal", reason: cause.message, cause };
  }
  if (base.validUntil !== undefined) {
    const validUntilMs = Date.parse(base.validUntil);
    if (now - clockSkewMs > validUntilMs) {
      const cause = new CredentialExpiredError(base.validUntil, now);
      return { ok: false, step: "temporal", reason: cause.message, cause };
    }
  }

  // --- Step 5: subject binding, wired to M1's verifyPossession --------
  let presenterPublicKey: Uint8Array;
  try {
    presenterPublicKey = verifyPossession(presenterProof, { now });
  } catch (cause) {
    const wrapped = new SubjectBindingError(`presenter did not prove possession of any DID: ${errorMessage(cause)}`, { cause });
    return { ok: false, step: "subject-binding", reason: wrapped.message, cause: wrapped };
  }
  const presenterDid = encodeDidKey(presenterPublicKey);
  if (presenterDid !== base.subjectId) {
    const cause = new SubjectBindingError(
      `credential is bound to ${base.subjectId}, but the presenter proved possession of ${presenterDid}`,
    );
    return { ok: false, step: "subject-binding", reason: cause.message, cause };
  }

  // --- Step 6: issuer identity -----------------------------------------
  // Step 2 proved "the key `kid` named did sign this" — a self-consistent
  // fact about ANY key, proving nothing about identity (same lesson as
  // M1: holding/naming a DID proves nothing by itself). This step is
  // what actually ties the signature to the credential's claimed issuer.
  if (base.issuer !== signingDid) {
    const cause = new IssuerIdentityMismatchError(`credential claims issuer ${base.issuer} but was signed by ${signingDid}`);
    return { ok: false, step: "issuer-identity", reason: cause.message, cause };
  }

  const credential = {
    "@context": base.context,
    ...(base.id !== undefined ? { id: base.id } : {}),
    type: base.type,
    issuer: base.issuer,
    validFrom: base.validFrom,
    ...(base.validUntil !== undefined ? { validUntil: base.validUntil } : {}),
    credentialSubject: { id: base.subjectId, ...claim },
  } as unknown as C;

  return {
    ok: true,
    credential,
    verifiedIssuer: signingDid,
    verifiedSubject: presenterDid,
    verifiedAt: now,
    revocationChecked: false,
  };
}

/** Verify a compact VC-JWT as an `AuthorityCredential`. Rejects (at the
 *  "structure" step) a syntactically valid credential of the WRONG kind —
 *  e.g. a `HistoryAttestation` — because history can never satisfy an
 *  authority requirement; see ADR 0002. */
export function verifyAuthorityCredential(
  jwt: string,
  presenterProof: ProofOfPossession,
  options: VerifyCredentialOptions = {},
): VerificationResult<AuthorityCredential> {
  return verifyCredentialOfKind<typeof AUTHORITY_CREDENTIAL_TYPE, AuthorityClaim, AuthorityCredential>(
    jwt,
    AUTHORITY_CREDENTIAL_TYPE,
    validateAuthorityClaim,
    presenterProof,
    options,
  );
}

/** Verify a compact VC-JWT as a `HistoryAttestation`. */
export function verifyHistoryAttestation(
  jwt: string,
  presenterProof: ProofOfPossession,
  options: VerifyCredentialOptions = {},
): VerificationResult<HistoryAttestation> {
  return verifyCredentialOfKind<typeof HISTORY_ATTESTATION_TYPE, HistoryClaim, HistoryAttestation>(
    jwt,
    HISTORY_ATTESTATION_TYPE,
    validateHistoryClaim,
    presenterProof,
    options,
  );
}
