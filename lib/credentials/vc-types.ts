/**
 * The W3C Verifiable Credentials Data Model — types only, no signing or
 * verification logic (that's `jws.ts` and `verify.ts`).
 *
 * ## Which VC version, and why
 *
 * This project targets **VC Data Model v2.0** (`https://www.w3.org/TR/vc-data-model-2.0/`,
 * a W3C Recommendation), not 1.1, for three concrete reasons, in order of
 * how much they actually shaped the code below:
 *
 *   1. **`validFrom`/`validUntil` (2.0) instead of `issuanceDate`/
 *      `expirationDate` (1.1)** — 2.0 explicitly separates "when this
 *      credential is valid" from "when it was issued". That distinction
 *      is not cosmetic for this project: an `AuthorityCredential` is
 *      forward-looking authority granted for a window that need not start
 *      at issuance, and a `HistoryAttestation` records an *observation
 *      period* that has nothing to do with when the JSON happened to get
 *      signed. Modeling that with 1.1's `issuanceDate` would either be a
 *      lie (claiming validity started at issuance when it didn't) or
 *      require inventing a non-standard field 2.0 already standardises.
 *   2. **2.0 separates the data model from how a credential is secured.**
 *      1.1 described a JWT encoding inline, as an appendix, coupled to
 *      the base spec. 2.0 moved securing mechanisms out to companion
 *      specs (VC-JOSE-COSE for JOSE/JWT, Data Integrity for embedded
 *      proofs), which is exactly this codebase's own separation: this
 *      file has zero knowledge of JWS, and `jws.ts` has zero knowledge of
 *      what a `VerifiableCredential` is.
 *   3. It is the current spec as of this writing (2026) — 1.1 is
 *      superseded, and a project explicitly judged on "real signing, not
 *      vibes" and standards conformance should target the standard that
 *      is actually current, not the one that was current when a given
 *      library or blog post was written.
 *
 * Securing mechanism: **VC-JOSE-COSE** (`https://www.w3.org/TR/vc-jose-cose/`),
 * the JOSE profile, using `alg: "EdDSA"` compact JWS. Per that spec, the
 * VC's own properties (not a `vc`-wrapped envelope — the spec explicitly
 * forbids a `vc`/`vp` claim name in this profile) ARE the JWT Claims Set;
 * see `credential.ts` for the exact payload shape this produces and how
 * it maps `iss`/`kid` onto the issuer's `did:key`.
 *
 * ## A deliberate, documented gap: no JSON-LD processing
 *
 * `@context` is present because the spec requires it, but nothing in this
 * codebase runs a real JSON-LD processor against it. The base VC 2.0
 * context (`https://www.w3.org/ns/credentials/v2`) is the only context
 * entry — there is no second, project-specific context document
 * published anywhere that would define terms like `scope` or `metrics`,
 * so this codebase does not claim one exists by inventing a URL that
 * wouldn't resolve. A production system extending this data model with
 * custom vocabulary would need to publish and reference a real JSON-LD
 * context; this project checks structural/JWT conformance, not full
 * JSON-LD term-definition conformance. Called out here rather than
 * silently glossed over — see the M3 report's DELIBERATE_OMISSIONS.
 */
import type { Did } from "../identity/index.js";

/** The one context entry this codebase ever emits or accepts as the
 *  first `@context` element — see the module comment. */
export const VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2" as const;

/** Every credential's base `type` entry (VC Data Model §4.4). */
export const VC_BASE_TYPE = "VerifiableCredential" as const;

/** The second `type` entry that distinguishes the two claim kinds this
 *  project's whole design turns on — see ADR 0002. */
export const AUTHORITY_CREDENTIAL_TYPE = "AuthorityCredential" as const;
export const HISTORY_ATTESTATION_TYPE = "HistoryAttestation" as const;

/** `credentialSubject` always names *who* the claim is about, by DID. */
export interface CredentialSubjectBase {
  readonly id: Did;
}

/**
 * Shared shape of both credential kinds. Generic over `Kind` (the
 * discriminating second `type` entry) and `Subject` (the claim-specific
 * `credentialSubject` fields) so that `AuthorityCredential` and
 * `HistoryAttestation` below are structurally distinct types — not just
 * distinguishable by a runtime tag a caller could ignore, but genuinely
 * unable to satisfy each other's type, in both directions. See ADR 0002
 * and `type-boundary.test.ts` for why that is the point of this file.
 */
export interface VerifiableCredentialShape<Kind extends string, Subject extends CredentialSubjectBase> {
  readonly "@context": readonly [typeof VC_CONTEXT_V2, ...ReadonlyArray<string>];
  /** OPTIONAL per spec (§4.2); omitted here by default (see `credential.ts`)
   *  because a dereferenceable identifier for an ephemeral agent-to-agent
   *  credential has no obvious owner-controlled resolution endpoint, and
   *  the spec asks implementers to weigh privacy before adding one. When
   *  present it's an opaque `urn:uuid:` correlation id, not a claim. */
  readonly id?: string;
  readonly type: readonly [typeof VC_BASE_TYPE, Kind, ...ReadonlyArray<string>];
  /** The issuer's `did:key`. VC Data Model §4.7 also allows an object
   *  form (`{ id, name, ... }`); this project only ever needs the bare
   *  identifier, so it uses the string form the spec permits. */
  readonly issuer: Did;
  /** ISO 8601 / XML Schema `dateTime`. */
  readonly validFrom: string;
  /** ISO 8601 / XML Schema `dateTime`. OPTIONAL on the base shape;
   *  `AuthorityCredential` narrows this to required — see below. */
  readonly validUntil?: string;
  readonly credentialSubject: Subject;
}

/**
 * The "may you?" claim: forward-looking, scoped, granted by a specific
 * issuer, and — this is `validUntil` moving from optional to REQUIRED —
 * always expiring. An authority credential with no expiry isn't a
 * stricter grant, it's a design bug: ADR 0002 requires every authority
 * credential to expire, and this requirement is enforced both here (a
 * caller cannot construct the TYPE without an expiry) and at the API
 * boundary in `authority.ts` (there is no default `validUntil` to fall
 * back on).
 */
export interface AuthorityClaim {
  /** The action this authority permits, e.g. `"purchase"`. Free text by
   *  design — M5's policy engine, not this data model, owns the
   *  vocabulary of actions and how they're matched. */
  readonly action: string;
  /** Bounds on the permitted action. Deliberately an open, extensible
   *  bag (via the index signature) rather than a fixed set of fields:
   *  M3 does not know every scope dimension a future policy (M5) will
   *  need to constrain on, and closing this off here would force a
   *  breaking change to the data model for every new scope dimension. */
  readonly scope: { readonly [key: string]: unknown };
}

export interface AuthorityCredentialSubject extends CredentialSubjectBase, AuthorityClaim {}

export interface AuthorityCredential
  extends VerifiableCredentialShape<typeof AUTHORITY_CREDENTIAL_TYPE, AuthorityCredentialSubject> {
  readonly validUntil: string;
}

/**
 * The "should I?" claim: backward-looking, observed rather than granted,
 * and — critically — never itself a grant of permission. Nothing in this
 * type has a `scope` or an `action` field for a verifier to mistake for
 * authority; see ADR 0002 for the design rule this enforces
 * (`history may tighten a decision but never loosen one`) and
 * `type-boundary.test.ts` for the compile-time proof that a
 * `HistoryAttestation` cannot satisfy anywhere an `AuthorityCredential`
 * is required.
 */
export interface HistoryClaim {
  /** What kind of thing was observed, e.g. `"transactions-completed"`. */
  readonly observationType: string;
  /** Observed counts/measurements. Like `AuthorityClaim.scope`, an open
   *  bag: M3 records observations, M5 decides how they're weighed. */
  readonly metrics: { readonly [key: string]: number };
  /** The window the observation covers, distinct from the credential's
   *  own `validFrom`/`validUntil` (which is about the ATTESTATION's
   *  validity, not the observed events' timing). Optional: not every
   *  attestation is about a bounded period (e.g. "0 disputes, ever"). */
  readonly observationPeriod?: { readonly from: string; readonly until: string };
}

export interface HistoryAttestationSubject extends CredentialSubjectBase, HistoryClaim {}

export interface HistoryAttestation
  extends VerifiableCredentialShape<typeof HISTORY_ATTESTATION_TYPE, HistoryAttestationSubject> {}

/** The union `verify.ts` accepts internally; nothing outside this module
 *  should need it — external callers ask for one kind or the other. */
export type AnyCredential = AuthorityCredential | HistoryAttestation;
