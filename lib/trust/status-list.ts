/**
 * W3C Bitstring Status List v1.0 — the credential shape, issuance, and
 * (most importantly) `checkRevocation`: the one check in this whole
 * project that cannot be done offline.
 *
 * ## The offline/network tension, named explicitly
 *
 * ADR 0001 chose `did:key` + self-certifying VCs precisely because
 * signature verification, expiry, and subject binding need no network
 * call — `lib/identity` and `lib/credentials` are both offline-
 * deterministic by construction, and that determinism is what makes a
 * 90-second judge-run demo possible at all. Revocation breaks that
 * property, and no amount of clever engineering removes the reason it
 * breaks: **whether a credential is still valid is a statement about
 * *now*, and "now" cannot be signed in advance.** An issuer can sign "I
 * grant X authority until date D" the moment X is trustworthy, entirely
 * offline — but "I have NOT revoked this since I signed it" is a fact
 * that keeps changing after the signature is produced, so checking it
 * requires asking someone (the issuer, or whoever they delegate
 * publishing to) what is true right now. There is no cryptographic
 * trick that makes that ask free; `credentialStatus` just makes the ask
 * as cheap and privacy-preserving as this spec can manage (fetch a
 * shared bitstring, not "is credential #94567 revoked?").
 *
 * This module makes that boundary structural, not just a comment:
 * `checkRevocation` is the ONLY function anywhere in `lib/` that actually
 * INVOKES the injected, network-shaped `StatusListResolver` callback —
 * i.e. the only function that performs I/O — and every other check in
 * this project (signature, temporal, subject-binding, issuer-identity,
 * self-issued, anchor/vouch trust) stays synchronous and does no I/O at
 * all. `grep -rn "resolver(" lib/ --include="*.ts" | grep -v test` names
 * exactly one call site: `status-list.ts`'s own call, below. (`grep -n
 * "async" lib/` is a DIFFERENT, broader question — it also matches
 * `trust-decision.ts`'s `resolveRevocation`, `evaluateAuthorityCredentialTrust`,
 * and `evaluateHistoryAttestationTrust`, none of which touch the network
 * themselves; they are `async` only because they `await` a call chain
 * that eventually reaches `checkRevocation`. An earlier version of this
 * comment — and of ADR 0003 — conflated "is declared `async`" with "does
 * I/O", which is why that grep was wrongly advertised as returning one
 * match. The precise, verifiable claim is the "who calls the resolver"
 * one above.)
 *
 * ## Fail-closed, and how stale is too stale
 *
 * A status list that is unavailable, unverifiable (bad signature), or
 * too old to trust is treated as REVOKED — never as "fine, I just
 * couldn't check". See `RevocationStatus` below: every non-"active"
 * outcome refuses the credential; the only distinction kept is WHY
 * ("revoked" vs. "indeterminate"), which matters for triage but never
 * for the accept/refuse decision itself.
 *
 * `DEFAULT_MAX_STATUS_LIST_AGE_MS` (5 minutes) is this project's
 * documented default for "how old can a status list be before it stops
 * counting as evidence about now": long enough that an issuer
 * publishing a fresh list every minute or so (a realistic small-scale
 * cadence) doesn't cause spurious refusals from ordinary fetch/verify
 * latency, short enough that a captured "everything was fine" snapshot
 * from a while ago can't be replayed indefinitely to keep a revoked
 * credential looking clean. It is five times `lib/credentials`'s
 * `DEFAULT_CLOCK_SKEW_MS` (60s) deliberately: clock skew bounds
 * disagreement between two clocks about the same instant, a much
 * tighter thing than "how stale is a cached network resource allowed to
 * be", so reusing the smaller constant here would be a coincidence, not
 * a reason. The threshold is a parameter (`maxStatusListAgeMs`), not a
 * hardcoded constant, precisely so a caller with different freshness
 * needs (a slower-moving issuer, or a stricter one) can override it —
 * but the fail-closed DIRECTION (older-than-threshold ⇒ refuse) is not
 * configurable.
 */
import { decodeDidKey, type Did } from "../identity/index.js";
import { VC_CONTEXT_V2, parseCompactJws, verificationMethodId } from "../credentials/index.js";
import { createEmptyEncodedList, decodeEncodedList, getStatusBit, withBitSet } from "./bitstring.js";
import {
  StatusListIssuerMismatchError,
  StatusListIssuerUnresolvableError,
  StatusListMalformedError,
  StatusListPurposeMismatchError,
  StatusListResolverTimeoutError,
  StatusListSignatureInvalidError,
  StatusListStaleError,
  StatusListUnavailableError,
  BitstringIndexError,
  type RevocationError,
} from "./errors.js";
import { signCompact, verifyCompactAndDecode, SyntaxErrorAsPayloadError } from "./jws-lite.js";

/** §1.1: the type entry a Bitstring Status List credential's `type`
 *  array must include (alongside the base `"VerifiableCredential"`). */
export const BITSTRING_STATUS_LIST_CREDENTIAL_TYPE = "BitstringStatusListCredential" as const;
/** §2: `credentialSubject.type` for a bitstring status list. */
export const BITSTRING_STATUS_LIST_TYPE = "BitstringStatusList" as const;
/** §1.2: the `credentialStatus.type` an issued credential's status
 *  entry carries. */
export const BITSTRING_STATUS_LIST_ENTRY_TYPE = "BitstringStatusListEntry" as const;

/** Default freshness threshold — see the module comment. */
export const DEFAULT_MAX_STATUS_LIST_AGE_MS = 5 * 60 * 1000;

/**
 * Default upper bound on how long `checkRevocation` will wait for the
 * injected `resolver` to settle (resolve OR reject) before giving up on
 * it and failing closed. Without this, a resolver that never settles —
 * a hostile implementation, or just a hung socket with no timeout of its
 * own — hangs `checkRevocation` (and therefore the whole trust decision
 * built on top of it) forever, since `await`ing a promise that never
 * settles never returns control to the fail-closed logic that would
 * otherwise refuse the credential.
 *
 * 5 seconds, chosen the same deliberate, not-reused-by-coincidence way
 * `DEFAULT_MAX_STATUS_LIST_AGE_MS` was: it answers a genuinely different
 * question ("how long is one fetch+verify attempt allowed to take" vs.
 * "how old is a successfully-fetched list allowed to be") and needs a
 * different order of magnitude. Five seconds is generous for a resolver
 * that is a real (if slow) network fetch — well beyond ordinary
 * fetch/verify latency — while still being short enough that a hung
 * resolver fails a single trust decision fast rather than stalling a
 * caller (or, worse, an interactive demo) indefinitely. Like
 * `maxStatusListAgeMs`, this is a parameter (`resolverTimeoutMs`), not a
 * hardcoded constant, so a caller with different latency expectations
 * (a slower resolver, or a stricter one for a latency-sensitive path)
 * can override it — the fail-closed DIRECTION (timeout ⇒ indeterminate
 * ⇒ refuse) is not configurable.
 */
export const DEFAULT_RESOLVER_TIMEOUT_MS = 5_000;

/**
 * The `credentialStatus` object §1.2 says an issued credential carries,
 * naming where and how to check ITS OWN revocation status.
 *
 * Deliberately NOT threaded through `lib/credentials/vc-types.ts`'s
 * `AuthorityCredential`/`HistoryAttestation` types as an embedded JWT
 * field — see `evaluate.ts`'s module comment for why that turned out to
 * be a dead end even before touching M3 was a question of style: M3's
 * own `verify.ts` reconstructs its returned `credential` object field-
 * by-field from validated data (`@context`/`id`/`type`/`issuer`/
 * `validFrom`/`validUntil`/`credentialSubject` — see `verifyCredentialOfKind`'s
 * final `credential = {...}` literal), so ANY extra top-level JWT claim,
 * `credentialStatus` included, would be silently dropped before a
 * caller ever saw it — surviving that round trip would require editing
 * M3's verification chain itself, not just widening a type. This
 * project's M4 slice instead threads `CredentialStatusEntry` as an
 * explicit sibling parameter alongside the credential JWT wherever it's
 * needed (`checkRevocation`, `evaluateAuthorityCredentialTrust`) — the
 * same information the spec's embedded JSON would carry, just handed
 * to the verifier out of band instead of smuggled through a pipe that
 * (today) purifies it away.
 */
export interface CredentialStatusEntry {
  readonly type: typeof BITSTRING_STATUS_LIST_ENTRY_TYPE;
  /** e.g. `"revocation"` — must match one of the resolved status list
   *  credential's own `statusPurpose` values (§8.1 step 3). */
  readonly statusPurpose: string;
  /** Non-negative integer. Spec transmits this as a base-10 string on
   *  the wire; this project keeps it a `number` at the API boundary
   *  (never serialised to JSON itself — see the note above) and
   *  validates integer-ness/range in `checkRevocation`. */
  readonly statusListIndex: number;
  /** URL (as far as this module's types are concerned, an opaque string
   *  handed to the injected `StatusListResolver` — see below) naming
   *  which status list credential to fetch. */
  readonly statusListCredential: string;
  /** Bits per entry. Defaults to 1 (a plain revoked/not-revoked flag) —
   *  this project never uses a `statusSize > 1` multi-bit status
   *  message, so `statusMessage` (spec §1.2) is out of scope; see
   *  DELIBERATE_OMISSIONS in the M4 report. */
  readonly statusSize?: number;
}

/** The signed VC this project fetches to answer "is index N set?" —
 *  shape traced to spec §2 (`credentialSubject.type`, `.statusPurpose`,
 *  `.encodedList`, optional `.ttl`) and §4.4/§4.7 for the base VC
 *  envelope fields it shares with `lib/credentials/vc-types.ts`'s
 *  `VerifiableCredentialShape` (duplicated here, not imported, because
 *  importing it would pull in M3's `Kind extends string` /
 *  `Subject extends CredentialSubjectBase` generic machinery for a
 *  shape with a structurally different subject —
 *  `credentialSubject.id` is OPTIONAL here per spec §2, unlike every
 *  M3 credential kind, which always names a specific subject DID). */
export interface BitstringStatusListCredential {
  readonly "@context": readonly [typeof VC_CONTEXT_V2, ...ReadonlyArray<string>];
  readonly id?: string;
  readonly type: readonly ["VerifiableCredential", typeof BITSTRING_STATUS_LIST_CREDENTIAL_TYPE];
  readonly issuer: Did;
  readonly validFrom: string;
  readonly validUntil?: string;
  readonly credentialSubject: {
    readonly id?: string;
    readonly type: typeof BITSTRING_STATUS_LIST_TYPE;
    readonly statusPurpose: string;
    readonly encodedList: string;
    /** §2: "OPTIONAL... time to live in milliseconds before a refresh
     *  SHOULD be attempted." Advisory only — per spec it "does not
     *  override or replace the validity period" and this project
     *  likewise never treats it as a security control; the authoritative
     *  staleness bound is `maxStatusListAgeMs`, always enforced by
     *  `checkRevocation` regardless of what `ttl` says. Recorded here
     *  purely for spec fidelity / a future caller that wants the hint. */
    readonly ttl?: number;
  };
}

export interface IssueStatusListCredentialInput {
  readonly issuerPrivateKey: Uint8Array;
  readonly issuerDid: Did;
  readonly statusPurpose: string;
  /** Bit positions already known to be revoked at issuance time — a
   *  convenience for tests/fixtures; real deployments would call
   *  `withBitSet` again each time a NEW credential is revoked and
   *  re-sign, but that publishing workflow is out of scope for this
   *  module (see DELIBERATE_OMISSIONS). */
  readonly revokedIndices?: readonly number[];
  /** Bitstring size in bits. Defaults to the spec's herd-privacy floor
   *  (`MINIMUM_BITSTRING_BITS`); tests override it smaller for speed —
   *  see `bitstring.ts`'s `createEmptyEncodedList`. */
  readonly sizeBits?: number;
  readonly validFrom?: string;
  readonly validUntil?: string;
  readonly ttl?: number;
  readonly now?: number;
}

/** Issue and sign a `BitstringStatusListCredential` as a compact JWS.
 *  Mirrors `lib/credentials/authority.ts`'s issuance shape (same `iss`/
 *  `issuer` mirroring rationale) using this module's own `jws-lite.ts`
 *  — see that file's comment for why. */
export function issueStatusListCredential(input: IssueStatusListCredentialInput): string {
  const now = input.now ?? Date.now();
  const validFrom = input.validFrom ?? new Date(now).toISOString();

  let encodedList = createEmptyEncodedList(input.sizeBits);
  for (const bitIndex of input.revokedIndices ?? []) {
    encodedList = withBitSet(encodedList, bitIndex);
  }

  const credential: BitstringStatusListCredential = {
    "@context": [VC_CONTEXT_V2],
    type: ["VerifiableCredential", BITSTRING_STATUS_LIST_CREDENTIAL_TYPE],
    issuer: input.issuerDid,
    validFrom,
    ...(input.validUntil !== undefined ? { validUntil: input.validUntil } : {}),
    credentialSubject: {
      type: BITSTRING_STATUS_LIST_TYPE,
      statusPurpose: input.statusPurpose,
      encodedList,
      ...(input.ttl !== undefined ? { ttl: input.ttl } : {}),
    },
  };

  const payload = { ...credential, iss: input.issuerDid };
  return signCompact(payload, verificationMethodId(input.issuerDid), input.issuerPrivateKey);
}

/**
 * Fetch (via the injected, non-network-owning `resolver`) the raw
 * compact-JWS string of a `BitstringStatusListCredential`. `lib/trust`
 * (like every other module under `lib/`) does no I/O itself — the
 * caller decides HOW `statusListCredential` URLs resolve to bytes
 * (fetch, filesystem, an in-memory fixture in tests), which is what
 * keeps this module framework-free, synchronous-by-default except here,
 * and deterministic in tests with no network stub required.
 */
export type StatusListResolver = (statusListCredentialUrl: string) => Promise<string>;

export interface CheckRevocationOptions {
  /** Override "now" for deterministic tests. Defaults to `Date.now()`. */
  readonly now?: number;
  /** Override the freshness threshold. Defaults to
   *  `DEFAULT_MAX_STATUS_LIST_AGE_MS`. */
  readonly maxStatusListAgeMs?: number;
  /** Override how long the injected `resolver` is allowed to take before
   *  `checkRevocation` gives up on it and fails closed. Defaults to
   *  `DEFAULT_RESOLVER_TIMEOUT_MS`. See that constant's comment for why
   *  this exists and how the default was chosen. */
  readonly resolverTimeoutMs?: number;
}

export type RevocationStatus =
  | { readonly outcome: "active"; readonly checkedAt: number; readonly statusListIssuer: Did }
  | { readonly outcome: "revoked"; readonly reason: string }
  | { readonly outcome: "indeterminate"; readonly reason: string; readonly cause: RevocationError };

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Inverse of `verificationMethodId`: recover the `did:key` portion of a
 *  `kid`. Also accepts a bare DID with no `#fragment`. Mirrors
 *  `lib/credentials/credential.ts`'s own (unexported) `didFromKid` —
 *  reimplemented here as a two-line pure function rather than importing
 *  a symbol that module's public barrel deliberately withholds (same
 *  reasoning as `jws-lite.ts`'s module comment). */
function didFromKid(kid: string): string {
  const hashIndex = kid.indexOf("#");
  return hashIndex === -1 ? kid : kid.slice(0, hashIndex);
}

/** Validate the resolved payload really is a `BitstringStatusListCredential`
 *  of the expected shape, throwing `StatusListMalformedError` (never a
 *  native error) for any structural problem. Mirrors
 *  `lib/credentials/verify.ts`'s `validateBaseStructure` in spirit —
 *  every failure names the exact field. */
function validateStatusListCredential(payload: unknown): {
  readonly issuer: Did;
  readonly validFrom: string;
  readonly statusPurposes: readonly string[];
  readonly encodedList: string;
} {
  if (!isPlainObject(payload)) {
    throw new StatusListMalformedError("payload is not a JSON object");
  }
  const context = payload["@context"];
  if (!Array.isArray(context) || context[0] !== VC_CONTEXT_V2) {
    throw new StatusListMalformedError(`"@context" must be an array whose first entry is "${VC_CONTEXT_V2}"`);
  }
  const type = payload["type"];
  if (!Array.isArray(type) || !type.includes(BITSTRING_STATUS_LIST_CREDENTIAL_TYPE)) {
    throw new StatusListMalformedError(`"type" must include "${BITSTRING_STATUS_LIST_CREDENTIAL_TYPE}"`);
  }
  const issuer = payload["issuer"];
  if (typeof issuer !== "string") {
    throw new StatusListMalformedError('"issuer" must be a string did:key');
  }
  const validFrom = payload["validFrom"];
  if (typeof validFrom !== "string" || Number.isNaN(Date.parse(validFrom))) {
    throw new StatusListMalformedError('"validFrom" must be a valid ISO 8601 date-time string');
  }
  const subject = payload["credentialSubject"];
  if (!isPlainObject(subject)) {
    throw new StatusListMalformedError('"credentialSubject" must be an object');
  }
  if (subject["type"] !== BITSTRING_STATUS_LIST_TYPE) {
    throw new StatusListMalformedError(`"credentialSubject.type" must be "${BITSTRING_STATUS_LIST_TYPE}"`);
  }
  const statusPurposeRaw = subject["statusPurpose"];
  const statusPurposes: readonly string[] =
    typeof statusPurposeRaw === "string"
      ? [statusPurposeRaw]
      : Array.isArray(statusPurposeRaw) && statusPurposeRaw.every((entry) => typeof entry === "string")
        ? (statusPurposeRaw as readonly string[])
        : (() => {
            throw new StatusListMalformedError('"credentialSubject.statusPurpose" must be a string or array of strings');
          })();
  const encodedList = subject["encodedList"];
  if (typeof encodedList !== "string" || encodedList.length === 0) {
    throw new StatusListMalformedError('"credentialSubject.encodedList" must be a non-empty string');
  }
  return { issuer: issuer as Did, validFrom, statusPurposes, encodedList };
}

/**
 * Race `promise` (the injected resolver's call, already in flight)
 * against a timer. Whichever settles first determines the outcome — but
 * unlike a bare `Promise.race`, this ALWAYS clears the timer once either
 * side settles, so a resolver that resolves/rejects promptly leaves no
 * dangling `setTimeout` behind it (which would otherwise keep a Node
 * process alive until the timer fires, or leak across many calls in a
 * long-running server). The timer is also `unref()`d as a second,
 * independent layer of defence: even if some caller path ever managed to
 * skip the `clearTimeout` below, an unref'd timer still cannot by itself
 * keep the process from exiting.
 */
function withResolverTimeout<T>(promise: Promise<T>, timeoutMs: number, onTimeout: () => Error): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(onTimeout()), timeoutMs);
    if (typeof timer.unref === "function") {
      timer.unref();
    }
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (cause: unknown) => {
        clearTimeout(timer);
        reject(cause);
      },
    );
  });
}

/**
 * The one genuinely networked check in this project. Resolves, verifies
 * (signature, ISSUER, AND freshness), and consults a Bitstring Status
 * List for a single credential's status. Fails closed for every failure
 * mode: unavailable, unverifiable, wrong issuer, stale, purpose-
 * mismatched, or malformed all become `{ outcome: "indeterminate" }`,
 * and an explicit "1" bit becomes `{ outcome: "revoked" }` — both refuse
 * a credential; only "active" (a verified, fresh, correctly-issued,
 * correctly-purposed list with the bit unset) accepts one. See the
 * module comment for why this is async and nothing else in `lib/trust`
 * (or `lib/` at all) needs to be.
 *
 * `expectedIssuer` is REQUIRED, not optional, and deliberately so. Before
 * this parameter existed, this function verified only that the resolved
 * status list credential was internally self-consistent (its `issuer`
 * claim matched the key that actually signed it) — it never checked that
 * THAT issuer was the right one to be speaking for THIS credential at
 * all. That gap meant anyone who could influence what `resolver` returns
 * for a given URL (and ADR 0003's own threat model already names the
 * status-list host as only semi-trusted) could substitute a "clean"
 * status list signed by an unrelated, throwaway keypair and have it
 * accepted — no compromise of the real issuer's key required. Making
 * `expectedIssuer` a required parameter means that bug class cannot
 * recur by a caller merely forgetting an optional argument: the compiler
 * refuses to build any call site that omits it, rather than relying on a
 * reviewer to notice the omission the way the original bug went
 * unnoticed. `trust-decision.ts` passes the credential's own
 * `verification.verifiedIssuer` — M3's cryptographically VERIFIED
 * issuer, never a claimed/unverified field — as this argument.
 *
 * Design note on the match rule itself: this function requires an EXACT
 * match between `expectedIssuer` and the resolved list's `issuer`. A real
 * deployment might want an issuer to delegate status-list HOSTING to a
 * separate, dedicated identity (so a compromised hosting key can't be
 * used to forge authority credentials, say) — exact match forecloses
 * that without an explicit design for delegation (e.g. an issuer signing
 * a "publisher X may speak for my status lists" statement, verified here
 * the same way a `Vouch` is). Exact match is chosen as the default
 * because it is the simplest rule that closes the bypass above with zero
 * new trust machinery, and because this project has no delegation
 * primitive for status-list hosting today — inventing one silently,
 * inside this one check, would be exactly the kind of undocumented trust
 * expansion this project's whole design argues against elsewhere. If a
 * caller needs delegation, the honest shape is: the caller resolves (and
 * itself verifies) which publisher DID an issuer has delegated to, and
 * passes THAT resolved DID as `expectedIssuer` explicitly — an explicit
 * act by the caller, never a silent fallback inside this function.
 */
export async function checkRevocation(
  entry: CredentialStatusEntry,
  resolver: StatusListResolver,
  expectedIssuer: Did,
  options: CheckRevocationOptions = {},
): Promise<RevocationStatus> {
  const now = options.now ?? Date.now();
  const maxAgeMs = options.maxStatusListAgeMs ?? DEFAULT_MAX_STATUS_LIST_AGE_MS;
  const resolverTimeoutMs = options.resolverTimeoutMs ?? DEFAULT_RESOLVER_TIMEOUT_MS;

  // Validate the entry itself before doing any I/O — an invalid index
  // is a caller/issuer bug, not something a network round trip can fix.
  const statusSize = entry.statusSize ?? 1;
  if (!Number.isInteger(statusSize) || statusSize < 1) {
    return { outcome: "indeterminate", reason: `invalid statusSize: ${JSON.stringify(entry.statusSize)}`, cause: new BitstringIndexError(`statusSize must be a positive integer, got ${JSON.stringify(entry.statusSize)}`) };
  }
  if (!Number.isInteger(entry.statusListIndex) || entry.statusListIndex < 0) {
    const cause = new BitstringIndexError(`statusListIndex must be a non-negative integer, got ${JSON.stringify(entry.statusListIndex)}`);
    return { outcome: "indeterminate", reason: cause.message, cause };
  }
  const bitPosition = entry.statusListIndex * statusSize;

  let jws: string;
  try {
    jws = await withResolverTimeout(
      resolver(entry.statusListCredential),
      resolverTimeoutMs,
      () => new StatusListResolverTimeoutError(entry.statusListCredential, resolverTimeoutMs),
    );
  } catch (cause) {
    if (cause instanceof StatusListResolverTimeoutError) {
      return { outcome: "indeterminate", reason: cause.message, cause };
    }
    const err = new StatusListUnavailableError(entry.statusListCredential, { cause });
    return { outcome: "indeterminate", reason: err.message, cause: err };
  }
  if (typeof jws !== "string" || jws.length === 0) {
    const err = new StatusListUnavailableError(entry.statusListCredential);
    return { outcome: "indeterminate", reason: `resolver returned a non-string/empty result: ${err.message}`, cause: err };
  }

  // --- Signature: parse the wire format first (transport-only — header
  //     and segment shape, never the payload's claims), then decide
  //     WHOSE key to check the signature against using the HEADER's
  //     `kid` — the exact same two-pass shape lib/credentials/verify.ts
  //     uses (`kid` is transport metadata used to select a key, never
  //     the payload's own unverified `issuer` claim, and never used to
  //     change HOW verification runs).
  let candidateIssuer: string;
  try {
    candidateIssuer = didFromKid(parseCompactJws(jws).header.kid);
  } catch (cause) {
    const err = new StatusListMalformedError("status list JWS is not a well-formed compact JWS", { cause });
    return { outcome: "indeterminate", reason: err.message, cause: err };
  }
  let issuerPublicKey: Uint8Array;
  try {
    issuerPublicKey = decodeDidKey(candidateIssuer);
  } catch (cause) {
    const err = new StatusListIssuerUnresolvableError(candidateIssuer, { cause });
    return { outcome: "indeterminate", reason: err.message, cause: err };
  }

  let payload: unknown;
  try {
    ({ payload } = verifyCompactAndDecode(jws, issuerPublicKey));
  } catch (cause) {
    // Same bug class M3 was once rejected for leaving unguarded (a REAL
    // signature, by the ACTUAL claimed issuer's key, over bytes that
    // simply aren't valid JSON): label it as malformed content, not a
    // signature failure, since the signature genuinely verified — see
    // `jws-lite.ts`'s `SyntaxErrorAsPayloadError`.
    const err =
      cause instanceof SyntaxErrorAsPayloadError
        ? new StatusListMalformedError("status list JWS signature verified but its payload is not valid JSON", { cause })
        : new StatusListSignatureInvalidError({ cause });
    return { outcome: "indeterminate", reason: err.message, cause: err };
  }

  let validated: ReturnType<typeof validateStatusListCredential>;
  try {
    validated = validateStatusListCredential(payload);
  } catch (cause) {
    const err = cause instanceof StatusListMalformedError ? cause : new StatusListMalformedError(String(cause), { cause });
    return { outcome: "indeterminate", reason: err.message, cause: err };
  }

  // The credential's OWN claimed issuer must be the key that actually
  // signed it — same issuer-identity check verify.ts makes for M3
  // credentials, applied here to the status list credential itself.
  if (validated.issuer !== candidateIssuer) {
    const err = new StatusListMalformedError(`credential claims issuer ${validated.issuer} but was signed by ${candidateIssuer}`);
    return { outcome: "indeterminate", reason: err.message, cause: err };
  }

  // The status list is internally self-consistent (checked immediately
  // above) AND was issued by the identity the caller actually expects —
  // see this function's module-comment note on `expectedIssuer` for why
  // this second, independent check is the whole point: without it, a
  // status list signed by ANY self-consistent key (not just the real
  // issuer's) passes every check above.
  if (validated.issuer !== expectedIssuer) {
    const err = new StatusListIssuerMismatchError(expectedIssuer, validated.issuer);
    return { outcome: "indeterminate", reason: err.message, cause: err };
  }

  if (!validated.statusPurposes.includes(entry.statusPurpose)) {
    const err = new StatusListPurposeMismatchError(entry.statusPurpose, validated.statusPurposes);
    return { outcome: "indeterminate", reason: err.message, cause: err };
  }

  // --- Freshness: a verified-but-stale list is worthless for a
  //     statement about "now" -- see the module comment.
  const issuedAtMs = Date.parse(validated.validFrom);
  if (Number.isNaN(issuedAtMs)) {
    const err = new StatusListMalformedError('"validFrom" must be a valid ISO 8601 date-time string');
    return { outcome: "indeterminate", reason: err.message, cause: err };
  }
  if (now - issuedAtMs > maxAgeMs) {
    const err = new StatusListStaleError(issuedAtMs, now, maxAgeMs);
    return { outcome: "indeterminate", reason: err.message, cause: err };
  }

  let bytes: Uint8Array;
  let bitSet: boolean;
  try {
    bytes = decodeEncodedList(validated.encodedList);
    bitSet = getStatusBit(bytes, bitPosition);
  } catch (cause) {
    const err = cause instanceof StatusListMalformedError || cause instanceof BitstringIndexError ? cause : new StatusListMalformedError(String(cause), { cause });
    return { outcome: "indeterminate", reason: err.message, cause: err };
  }

  if (bitSet) {
    return { outcome: "revoked", reason: `bit ${bitPosition} is set in status list ${entry.statusListCredential} (purpose "${entry.statusPurpose}")` };
  }
  return { outcome: "active", checkedAt: now, statusListIssuer: validated.issuer };
}
