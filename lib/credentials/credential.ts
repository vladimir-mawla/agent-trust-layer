/**
 * Small shared helpers used by both issuance (`authority.ts`/`history.ts`)
 * and verification (`verify.ts`) — kept here instead of duplicated so the
 * `kid` convention and clock-skew constant have exactly one definition.
 */
import type { Did } from "../identity/index.js";

const DID_KEY_METHOD_PREFIX = "did:key:";

/**
 * `did:key`'s own spec convention: a DID with no separate DID document
 * still has an implicit default verification method, whose id is
 * `<did>#<multibase-value>` (the multibase value repeated as the
 * fragment). Used as this project's JWS `kid` — a verifier resolves it
 * back to a public key with plain string-splitting and
 * `decodeDidKey`, no registry or network call.
 */
export function verificationMethodId(did: Did): string {
  return `${did}#${did.slice(DID_KEY_METHOD_PREFIX.length)}`;
}

/**
 * Inverse of `verificationMethodId`: recover the `did:key` portion of a
 * `kid`. Also accepts a bare DID with no `#fragment`, leniently. This
 * does NOT itself validate that the result is a well-formed `did:key` —
 * that's `decodeDidKey`'s job (called separately in `verify.ts`), kept
 * apart so a malformed DID is reported with `decodeDidKey`'s own precise,
 * typed reason instead of a generic string-parsing failure here.
 */
export function didFromKid(kid: string): string {
  const hashIndex = kid.indexOf("#");
  return hashIndex === -1 ? kid : kid.slice(0, hashIndex);
}

/**
 * Clock skew tolerated on both edges of a credential's validity window
 * (`validFrom`/`validUntil`), applied explicitly rather than left
 * implicit. 60 seconds: generous enough to absorb ordinary unsynchronised-
 * clock drift between an issuer's and a verifier's machines (this
 * project has no NTP-guaranteed infrastructure — see ADR 0001, everything
 * runs offline with no shared server), short enough that it cannot
 * meaningfully extend a captured credential's useful life. Same
 * short-window-not-zero-window reasoning as M1's challenge TTL.
 */
export const DEFAULT_CLOCK_SKEW_MS = 60_000;
