/**
 * Shared fixtures and byte-level attack primitives for the M7 attack
 * suite (`tests/attacks/**`).
 *
 * Per the M7 brief, every test in this suite reuses `lib/negotiation`'s
 * own `Supplier`, `KeyHolder`, and `buildFourBeatFixture` wherever a
 * two-party negotiation fixture is needed — this file does NOT re-derive
 * a second harness. What it adds on top is a small set of byte-level
 * forgery primitives (corrupting a signature, tampering a payload after
 * signing, hand-crafting a JWS over non-JSON bytes) that no `lib/`
 * module exposes publicly on purpose — an attacker needs exactly these
 * primitives, and a test suite that wants to prove "the RIGHT mechanism
 * catches this" has to be able to construct the attack precisely rather
 * than only exercise it indirectly.
 *
 * Nothing here imports a private/internal export from `lib/` — every
 * primitive below is built from each module's own public barrel
 * (`index.ts`) plus `@noble/curves/ed25519.js`, an actual project
 * dependency, exactly the tools a real external attacker would have.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  encodeDidKey,
  generateKeyPair,
  type Did,
} from "../../lib/identity/index.js";
import {
  ALLOWED_ALG,
  VC_JWT_TYP,
  decodeBase64Url,
  encodeBase64Url,
  verificationMethodId,
} from "../../lib/credentials/index.js";
import type { Policy, RevocationRequirement } from "../../lib/policy/index.js";

/** A raw, unmanaged Ed25519 identity — used when a test needs to sign
 *  bytes directly (rather than through `KeyHolder`, which deliberately
 *  keeps its private key un-exportable — see `lib/negotiation/agent.ts`).
 *  Attack fixtures that need to forge or hand-craft a JWS need the raw
 *  key material a real attacker would have. */
export interface RawIdentity {
  readonly did: Did;
  readonly privateKey: Uint8Array;
}

export function makeIdentity(): RawIdentity {
  const { publicKey, privateKey } = generateKeyPair();
  return { did: encodeDidKey(publicKey), privateKey };
}

export const ONE_YEAR_MS = 365 * 24 * 60 * 60 * 1000;

const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * Attack primitive: flip one character of a compact JWS's signature
 * segment, leaving the header and payload completely untouched. Models
 * "a credential whose signature does not verify" in its purest form —
 * nothing about the credential's CONTENT is forged or altered, only the
 * bytes that are supposed to prove who signed it. The result is still a
 * well-formed, 3-segment, valid-base64url JWS (it must PARSE cleanly),
 * so any refusal it causes is attributable to signature verification,
 * never to `"parse"`.
 */
export function corruptSignatureSegment(jwt: string): string {
  const segments = jwt.split(".");
  if (segments.length !== 3) {
    throw new Error(`expected a 3-segment compact JWS, got ${segments.length} segments`);
  }
  const [headerB64, payloadB64, signatureB64] = segments as [string, string, string];
  const firstChar = signatureB64[0] as string;
  const replacement = BASE64URL_ALPHABET[(BASE64URL_ALPHABET.indexOf(firstChar) + 1) % BASE64URL_ALPHABET.length];
  const corruptedSignature = `${replacement}${signatureB64.slice(1)}`;
  return `${headerB64}.${payloadB64}.${corruptedSignature}`;
}

/**
 * Attack primitive: decode a JWS's payload, apply `mutate`, re-encode,
 * and reassemble the JWS with the ORIGINAL, now-stale signature. Models
 * "a byte changed in the payload after signing" — a captured-in-transit
 * tamper, not a forger with their own key. The signature was produced
 * over the pre-mutation bytes, so it necessarily fails to verify over
 * the mutated ones; this primitive does not (and structurally cannot)
 * produce a new valid signature.
 */
export function tamperPayload(jwt: string, mutate: (payload: Record<string, unknown>) => Record<string, unknown>): string {
  const segments = jwt.split(".");
  if (segments.length !== 3) {
    throw new Error(`expected a 3-segment compact JWS, got ${segments.length} segments`);
  }
  const [headerB64, payloadB64, signatureB64] = segments as [string, string, string];
  const payload = JSON.parse(new TextDecoder().decode(decodeBase64Url(payloadB64))) as Record<string, unknown>;
  const mutated = mutate(payload);
  const newPayloadB64 = encodeBase64Url(new TextEncoder().encode(JSON.stringify(mutated)));
  return `${headerB64}.${newPayloadB64}.${signatureB64}`;
}

/**
 * Attack primitive for regression #11 (the M3 non-JSON-payload crash):
 * hand-craft a compact JWS exactly the way a real attacker would —
 * `kid` naming the attacker's OWN, genuinely-controlled DID, a REAL
 * Ed25519 signature produced with the attacker's OWN private key — but
 * over payload bytes that are not JSON at all. This only uses
 * `lib/credentials/index.ts`'s public, documented-for-this-purpose
 * exports (`ALLOWED_ALG`, `VC_JWT_TYP`, `encodeBase64Url`,
 * `verificationMethodId`) plus `@noble/curves` directly — never a
 * private signing helper `lib/credentials` withholds on purpose.
 */
export function craftSignedNonJsonJws(identity: RawIdentity, rawPayloadBytes: string): string {
  const header = { alg: ALLOWED_ALG, kid: verificationMethodId(identity.did), typ: VC_JWT_TYP };
  const headerB64 = encodeBase64Url(new TextEncoder().encode(JSON.stringify(header)));
  const payloadB64 = encodeBase64Url(new TextEncoder().encode(rawPayloadBytes));
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = ed25519.sign(signingInput, identity.privateKey);
  return `${headerB64}.${payloadB64}.${encodeBase64Url(signature)}`;
}

/** A minimal, single-`action-scope`-rule policy for tests that don't
 *  need the full four-beat fixture's policy shape. */
export function singleActionPolicy(
  action: string,
  maxAmount: number,
  revocationHandling: RevocationRequirement = { requireChecked: true },
): Policy {
  return {
    id: "attack-suite-policy",
    version: "1.0.0",
    revocationHandling,
    rules: [
      {
        kind: "action-scope",
        id: "R-attack-suite",
        description: `${action} permitted up to a ceiling of ${maxAmount}`,
        action,
        maxScope: { amount: maxAmount },
      },
    ],
  };
}
