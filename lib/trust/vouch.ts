/**
 * Issuer vouches — PART 3 of M4: exactly one level of "I vouch for this
 * OTHER issuer" delegation, and no more.
 *
 * ## The rule that stops this becoming a reputation score
 *
 * A vouch conveys IDENTITY trust ("B is a real, distinct issuer I have
 * chosen to stand behind") and NEVER authority ("B may therefore grant
 * whatever authority it likes"). Collapsing those two is exactly the
 * "score with no mechanism" ADR 0001/0002 already disqualify — a big
 * enough pile of vouches would otherwise quietly become a substitute for
 * an actual grant of permission. This file enforces the distinction
 * STRUCTURALLY, not just by convention:
 *
 *   - `Vouch.credentialSubject` has exactly one claim field,
 *     `vouchedCapability`, typed as the SINGLE LITERAL `"identity"` —
 *     not `"identity" | "authority"`. There is no value that type
 *     accepts other than `"identity"`; `vouch.test.ts` and
 *     `type-boundary.test.ts` both prove (one at runtime, one at compile
 *     time via `@ts-expect-error`) that assigning `"authority"` there is
 *     rejected before the program even compiles, not merely rejected by
 *     a runtime check a caller could skip.
 *   - `Vouch`'s subject shape has no `action` or `scope` field at all —
 *     unlike `AuthorityCredentialSubject`
 *     (`lib/credentials/vc-types.ts`), which REQUIRES both. A `Vouch`
 *     therefore cannot structurally satisfy anywhere an
 *     `AuthorityCredentialSubject` is required, in either direction,
 *     the same "distinct types, not a shared shape with a runtime tag"
 *     pattern ADR 0002 uses for `AuthorityCredential` vs.
 *     `HistoryAttestation`.
 *   - The function that actually turns a vouch into a trust decision
 *     (`anchors.ts`'s `evaluateIssuerTrust`) returns an `IssuerTrustResult`
 *     whose `"vouched"` case names the voucher and nothing else — no
 *     scope, no action, no expanded authority. What authority the
 *     vouched-for issuer's OWN credentials grant is decided entirely by
 *     THOSE credentials' own `scope`/`action` fields (validated by M3),
 *     never inflated by the vouch.
 *
 * ## Depth limit 1, enforced explicitly, not merely implied
 *
 * `VOUCH_DEPTH_LIMIT = 1` is a real, tested constant (see `anchors.ts`).
 * At depth 1, A vouches directly for B; a cycle (A vouches B vouches A)
 * is structurally impossible to even ask about, because
 * `evaluateIssuerTrust` never looks at anything BUT vouches whose own
 * `issuer` is a member of the caller's anchor set — it does not walk a
 * chain of vouches at all, so there is no graph to have a cycle in, and
 * no cycle-detection code to write (writing it would be dead code for a
 * depth this shallow). Raising the depth limit later would require
 * actually adding chain-walking logic — a deliberate code change, not a
 * constant flip — which is the point of naming it as a constant instead
 * of leaving "we just don't recurse" implicit in the code's shape.
 */
import { decodeDidKey, type Did } from "../identity/index.js";
import { VC_CONTEXT_V2, parseCompactJws, verificationMethodId } from "../credentials/index.js";
import {
  VouchExpiredError,
  VouchIssuerUnresolvableError,
  VouchMalformedError,
  VouchSignatureInvalidError,
} from "./errors.js";
import { signCompact, verifyCompactAndDecode, SyntaxErrorAsPayloadError } from "./jws-lite.js";

export const VOUCH_TYPE = "IssuerVouch" as const;

/** The one and only value `credentialSubject.vouchedCapability` can
 *  hold — see the module comment. There is deliberately no
 *  `"authority"` sibling for this literal to widen into. */
export const VOUCHED_CAPABILITY_IDENTITY = "identity" as const;

export interface VouchSubject {
  /** The DID being vouched for (the OTHER issuer). */
  readonly id: Did;
  /** Always `"identity"` — see module comment. Not a `boolean` or a
   *  free string, specifically so there is exactly one inhabitant of
   *  this type and no way to construct a `Vouch` that claims to convey
   *  anything else. */
  readonly vouchedCapability: typeof VOUCHED_CAPABILITY_IDENTITY;
}

/** A signed statement, by `issuer` (the voucher — expected to be a
 *  trust anchor, though this type alone does not enforce that; see
 *  `anchors.ts`, which only ever consults a vouch whose `issuer` is
 *  already in the caller's anchor set), that `credentialSubject.id` is
 *  a real, distinct issuer worth trusting for IDENTITY purposes. */
export interface Vouch {
  readonly "@context": readonly [typeof VC_CONTEXT_V2, ...ReadonlyArray<string>];
  readonly type: readonly ["VerifiableCredential", typeof VOUCH_TYPE];
  readonly issuer: Did;
  readonly validFrom: string;
  readonly validUntil?: string;
  readonly credentialSubject: VouchSubject;
}

export interface IssueVouchInput {
  readonly voucherPrivateKey: Uint8Array;
  readonly voucherDid: Did;
  readonly vouchedIssuerDid: Did;
  readonly validFrom?: string;
  readonly validUntil?: string;
  readonly now?: number;
}

/** Issue and sign a `Vouch` as a compact JWS, using this module's own
 *  minimal JWS layer (`jws-lite.ts`) — see that file's comment for why
 *  this doesn't reuse `lib/credentials`'s private signing internals. */
export function issueVouch(input: IssueVouchInput): string {
  const now = input.now ?? Date.now();
  const validFrom = input.validFrom ?? new Date(now).toISOString();

  const vouch: Vouch = {
    "@context": [VC_CONTEXT_V2],
    type: ["VerifiableCredential", VOUCH_TYPE],
    issuer: input.voucherDid,
    validFrom,
    ...(input.validUntil !== undefined ? { validUntil: input.validUntil } : {}),
    credentialSubject: { id: input.vouchedIssuerDid, vouchedCapability: VOUCHED_CAPABILITY_IDENTITY },
  };

  const payload = { ...vouch, iss: input.voucherDid };
  return signCompact(payload, verificationMethodId(input.voucherDid), input.voucherPrivateKey);
}

export type VerifiedVouch = { readonly ok: true; readonly vouch: Vouch; readonly voucher: Did } | { readonly ok: false; readonly reason: string };

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function didFromKid(kid: string): string {
  const hashIndex = kid.indexOf("#");
  return hashIndex === -1 ? kid : kid.slice(0, hashIndex);
}

export interface VerifyVouchOptions {
  /** Override "now" for deterministic tests. Defaults to `Date.now()`. */
  readonly now?: number;
}

/**
 * Verify a compact-JWS `Vouch`: signature, structure, and (if present)
 * expiry. Never throws — every failure mode (malformed wire format,
 * bad signature, wrong VC shape, missing/invalid `vouchedCapability`,
 * expired) becomes a structured `{ ok: false, reason }`, mirroring
 * `lib/credentials/verify.ts`'s fail-closed posture for the exact same
 * bug class M3 was once rejected for leaving unguarded.
 */
export function verifyVouch(jwt: string, options: VerifyVouchOptions = {}): VerifiedVouch {
  const now = options.now ?? Date.now();

  let candidateIssuer: string;
  try {
    candidateIssuer = didFromKid(parseCompactJws(jwt).header.kid);
  } catch (cause) {
    return { ok: false, reason: new VouchMalformedError("vouch JWS is not a well-formed compact JWS", { cause }).message };
  }

  let issuerPublicKey: Uint8Array;
  try {
    issuerPublicKey = decodeDidKey(candidateIssuer);
  } catch (cause) {
    return { ok: false, reason: new VouchIssuerUnresolvableError(candidateIssuer, { cause }).message };
  }

  let payload: unknown;
  try {
    ({ payload } = verifyCompactAndDecode(jwt, issuerPublicKey));
  } catch (cause) {
    // Same bug class M3 was once rejected for leaving unguarded: a REAL
    // signature over bytes that aren't valid JSON. Labeled as malformed
    // content, not a signature failure, since the signature verified.
    if (cause instanceof SyntaxErrorAsPayloadError) {
      return { ok: false, reason: new VouchMalformedError("vouch JWS signature verified but its payload is not valid JSON", { cause }).message };
    }
    return { ok: false, reason: new VouchSignatureInvalidError({ cause }).message };
  }

  if (!isPlainObject(payload)) {
    return { ok: false, reason: new VouchMalformedError("payload is not a JSON object").message };
  }
  const context = payload["@context"];
  if (!Array.isArray(context) || context[0] !== VC_CONTEXT_V2) {
    return { ok: false, reason: new VouchMalformedError(`"@context" must be an array whose first entry is "${VC_CONTEXT_V2}"`).message };
  }
  const type = payload["type"];
  if (!Array.isArray(type) || type[0] !== "VerifiableCredential" || type[1] !== VOUCH_TYPE) {
    return { ok: false, reason: new VouchMalformedError(`"type" must be ["VerifiableCredential", "${VOUCH_TYPE}"]`).message };
  }
  const issuer = payload["issuer"];
  if (typeof issuer !== "string" || issuer !== candidateIssuer) {
    return { ok: false, reason: new VouchMalformedError(`"issuer" must equal the signing key's did:key (${candidateIssuer})`).message };
  }
  const validFrom = payload["validFrom"];
  if (typeof validFrom !== "string" || Number.isNaN(Date.parse(validFrom))) {
    return { ok: false, reason: new VouchMalformedError('"validFrom" must be a valid ISO 8601 date-time string').message };
  }
  const validUntilRaw = payload["validUntil"];
  if (validUntilRaw !== undefined && (typeof validUntilRaw !== "string" || Number.isNaN(Date.parse(validUntilRaw)))) {
    return { ok: false, reason: new VouchMalformedError('"validUntil" must be a valid ISO 8601 date-time string when present').message };
  }
  const subject = payload["credentialSubject"];
  if (!isPlainObject(subject)) {
    return { ok: false, reason: new VouchMalformedError('"credentialSubject" must be an object').message };
  }
  const subjectId = subject["id"];
  if (typeof subjectId !== "string") {
    return { ok: false, reason: new VouchMalformedError('"credentialSubject.id" must be a string did:key').message };
  }
  try {
    decodeDidKey(subjectId);
  } catch (cause) {
    return { ok: false, reason: new VouchMalformedError(`"credentialSubject.id" is not a well-formed did:key: ${String(cause)}`).message };
  }
  if (subject["vouchedCapability"] !== VOUCHED_CAPABILITY_IDENTITY) {
    return {
      ok: false,
      reason: new VouchMalformedError(
        `"credentialSubject.vouchedCapability" must be "${VOUCHED_CAPABILITY_IDENTITY}", got ${JSON.stringify(subject["vouchedCapability"] ?? null)}`,
      ).message,
    };
  }

  if (validUntilRaw !== undefined) {
    const validUntilMs = Date.parse(validUntilRaw);
    if (now > validUntilMs) {
      return { ok: false, reason: new VouchExpiredError(validUntilRaw, now).message };
    }
  }

  const vouch: Vouch = {
    "@context": context as unknown as readonly [typeof VC_CONTEXT_V2, ...string[]],
    type: ["VerifiableCredential", VOUCH_TYPE],
    issuer: issuer as Did,
    validFrom,
    ...(validUntilRaw !== undefined ? { validUntil: validUntilRaw as string } : {}),
    credentialSubject: { id: subjectId as Did, vouchedCapability: VOUCHED_CAPABILITY_IDENTITY },
  };

  return { ok: true, vouch, voucher: issuer as Did };
}
