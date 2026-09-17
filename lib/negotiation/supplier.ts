/**
 * The Supplier: the composition root of M6. Holds a policy and a set of
 * trust anchors (never a keypair belonging to anyone else — see
 * `agent.ts`'s module comment on KEY_SEPARATION) and turns a
 * `Presentation` into a `NegotiationDecision` by running, in order:
 *
 *   1. **Session binding** — does this presentation's proof answer the
 *      EXACT challenge this session issued? (`GATE_SESSION_CHALLENGE`)
 *   2. **Proof of possession** — M1's `verifyPossession`, called
 *      DIRECTLY here, BEFORE either `presentation.credentials` field is
 *      ever read. This is what makes the brief's named "spoofed
 *      identity" failure test true structurally, not just by luck of
 *      check ordering: an impostor who cannot produce a valid signature
 *      is refused by the `catch` block below, and control never reaches
 *      the `evaluateAuthorityCredentialTrust` call beneath it — a
 *      credential that was never even looked at cannot have been the
 *      reason for the refusal. (M3's OWN verification chain also
 *      re-checks subject binding internally, using this same proof, as
 *      defense in depth — see `verify.ts`'s step 5 — but that is
 *      redundant with, not a substitute for, this earlier, cheaper,
 *      credential-blind gate.)
 *   3. **Credential trust** (M4) — `evaluateAuthorityCredentialTrust`/
 *      `evaluateHistoryAttestationTrust`, unmodified.
 *   4. **Policy** (M5) — `evaluatePolicyRequest`, unmodified.
 *
 * Every step past (2) only ever looks at what `presentation` carries and
 * what proof-of-possession already established (`provenDid`) — never at
 * any "who is asking" field a caller could have set directly. See
 * `messages.ts`'s module comment.
 *
 * Nothing below this module's own two `try`/`catch` blocks can throw for
 * a hostile `presentation`/`request`: `verifyPossession` is the one
 * function in the dependency chain that legitimately throws (malformed
 * DID, expired challenge, or a bad signature — all caught here), and
 * every M3/M4/M5 function this module calls afterwards already returns a
 * structured failure result instead of throwing for anything about the
 * MESSAGE. `evaluatePolicyRequest` can still throw `PolicyDefinitionError`
 * — but only for a malformed POLICY, a configuration bug this Supplier
 * was built with, never for anything a counterparty presents; see that
 * module's own comment for why that distinction is deliberate.
 */
import { createChallenge, encodeDidKey, verifyPossession, type Challenge, type CreateChallengeOptions, type Did } from "../identity/index.js";
import { evaluatePolicyRequest } from "../policy/index.js";
import {
  evaluateAuthorityCredentialTrust,
  evaluateHistoryAttestationTrust,
  type CredentialStatusEntry,
  type HistoryTrustDecision,
  type StatusListResolver,
  type TrustAnchorSet,
} from "../trust/index.js";
import type { NegotiationDecision } from "./decision.js";
import { GATE_MALFORMED_PRESENTATION, GATE_PROOF_OF_POSSESSION, GATE_SESSION_CHALLENGE, negotiationFieldEvidence } from "./explanation.js";
import type { NegotiationRequest, Presentation } from "./messages.js";

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Structurally validate that `proof` is at least shaped like a
 *  `ProofOfPossession` (an object naming `did`, a `challenge` object with
 *  a `nonce`, and a `signature`) — WITHOUT trusting any of those values.
 *  This exists solely so a malformed/hostile `presentation.proof` (e.g.
 *  `undefined`, `null`, `{}`) is refused instead of throwing a native
 *  `TypeError` the moment this function tries to read `proof.challenge.nonce`.
 *  Cryptographic validity is still entirely `verifyPossession`'s job —
 *  this only proves the shape is safe to read from. */
function hasProofShape(proof: unknown): proof is { readonly did: unknown; readonly challenge: { readonly nonce: unknown }; readonly signature: unknown } {
  return isPlainObject(proof) && isPlainObject(proof["challenge"]) && "did" in proof && "signature" in proof;
}

/**
 * Produce a plain, inert, DEFENSIVELY-READ copy of a hostile/malformed
 * `NegotiationRequest.scope` — this Supplier's own composition boundary
 * against a real, untrusted counterparty (FIX 1, L4 M6 review).
 *
 * Before this fix, this function only checked that `scope` WAS an
 * object and then passed the caller's own object through by reference.
 * That is not enough: a well-shaped object can still carry a throwing
 * OWN getter (`Object.defineProperty(scope, "amount", { get() { throw }
 * })`), a getter inherited from its PROTOTYPE (a plain property READ
 * still invokes an inherited accessor), or be a `Proxy` whose `get`/
 * `ownKeys`/`getOwnPropertyDescriptor` traps themselves throw — any of
 * which would surface as an unhandled rejection out of
 * `evaluatePresentation` the moment something downstream reads that
 * field. `lib/policy/engine.ts` now guards its OWN reads too (see
 * `safe-scope-read.ts`) — this is a SEPARATE, redundant guard at THIS
 * module's own boundary, not a substitute for that one: the verifier's
 * point stands that it is this Supplier's job to guard its own
 * composition boundary against hostile input, not to rely on a
 * dependency to do it.
 *
 * Only OWN, enumerable, STRING-keyed properties are ever copied — a
 * `Symbol` key is never a meaningful scope dimension
 * (`PolicyRequest.scope: Readonly<Record<string, unknown>>`) and is
 * simply skipped, never read. Every step that could touch attacker-
 * controlled behaviour (`Reflect.ownKeys`, `Object.getOwnPropertyDescriptor`,
 * the property read itself) is individually wrapped so a throw at ANY
 * one of them drops just that one field (or, for a top-level enumeration
 * failure, yields an empty scope) rather than propagating.
 */
function sanitizeScope(rawScope: unknown): Record<string, unknown> {
  if (typeof rawScope !== "object" || rawScope === null) {
    return {};
  }

  let keys: readonly PropertyKey[];
  try {
    keys = Reflect.ownKeys(rawScope);
  } catch {
    // A Proxy whose `ownKeys`/`getOwnPropertyDescriptor` trap throws —
    // treated as "no readable fields at all", never a crash.
    return {};
  }

  const out: Record<string, unknown> = {};
  for (const key of keys) {
    if (typeof key === "symbol") {
      continue;
    }
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Object.getOwnPropertyDescriptor(rawScope, key);
    } catch {
      continue;
    }
    if (descriptor === undefined || descriptor.enumerable === false) {
      continue;
    }
    let value: unknown;
    try {
      // The read that actually invokes an own or inherited getter, or a
      // Proxy's `get` trap — the one step in this whole function a
      // hostile `scope` can make throw for a key that otherwise looked
      // completely ordinary.
      value = (rawScope as Record<string, unknown>)[key];
    } catch {
      continue;
    }
    out[key] = value;
  }
  return out;
}

/** Coerce a hostile/malformed `NegotiationRequest` into one
 *  `lib/policy` can safely evaluate — see `sanitizeScope` above for why
 *  `scope` specifically needs a defensive COPY, not merely a shape
 *  check. */
function sanitizeRequest(request: NegotiationRequest): NegotiationRequest {
  return {
    action: typeof request?.action === "string" ? request.action : "",
    scope: sanitizeScope(request?.scope),
  };
}

export interface SupplierOptions {
  /** Untrusted data, re-validated by `lib/policy` on every call — see
   *  `validate.ts`. */
  readonly policy: unknown;
  readonly anchors: TrustAnchorSet;
  /** How to resolve a `BitstringStatusListCredential` URL to its JWS —
   *  omit to honestly report revocation as "not-checked" for every
   *  presentation (see `PresentedCredentials.credentialStatus`). */
  readonly statusListResolver?: StatusListResolver;
  /** Override "now" for deterministic tests/demo. Defaults to
   *  `Date.now()`. */
  readonly now?: number;
  readonly clockSkewMs?: number;
  readonly maxStatusListAgeMs?: number;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export class Supplier {
  readonly #options: SupplierOptions;

  constructor(options: SupplierOptions) {
    this.#options = options;
  }

  /** Issue a fresh challenge for a new session — the first message of
   *  the protocol. */
  issueChallenge(options: CreateChallengeOptions = {}): Challenge {
    return createChallenge({ ...(this.#options.now !== undefined ? { now: this.#options.now } : {}), ...options });
  }

  /**
   * Evaluate a `Presentation` answering `issuedChallenge` against
   * `request`. `issuedChallenge` must be the exact `Challenge` THIS
   * Supplier issued for THIS session (`issueChallenge` above) — a
   * caller cannot pass a stale one from a different session and have it
   * accepted, which is what closes the "a presentation answering a
   * DIFFERENT challenge is refused" requirement.
   */
  async evaluatePresentation(issuedChallenge: Challenge, presentation: Presentation, request: NegotiationRequest): Promise<NegotiationDecision> {
    const now = this.#options.now ?? Date.now();
    const rawProof: unknown = presentation?.proof;

    // --- Gate: the proof must at least be SHAPED like a proof before
    //     anything about it is read — a malformed/absent `proof` is
    //     refused here, not an unhandled TypeError three lines down.
    if (!hasProofShape(rawProof)) {
      // `claimedDid` has no genuine value to report here (there was no
      // well-formed `did` to read) — this typed placeholder is a
      // deliberate "unknown", never a guess dressed up as a real DID.
      const placeholderDid = "did:key:unknown" as Did;
      return {
        stage: "proof-of-possession",
        permitted: false,
        claimedDid: placeholderDid,
        rule: GATE_MALFORMED_PRESENTATION,
        field: negotiationFieldEvidence("presentation.proof", { actual: rawProof === undefined ? "missing" : JSON.stringify(rawProof) }),
        narrative: "the presentation did not carry a proof shaped as { did, challenge: { nonce }, signature } — refused before anything about it could be checked",
      };
    }
    const proof = rawProof as Presentation["proof"];

    // --- Gate: session binding — before touching the signature at all.
    if (proof.challenge.nonce !== issuedChallenge.nonce) {
      return {
        stage: "proof-of-possession",
        permitted: false,
        claimedDid: proof.did,
        rule: GATE_SESSION_CHALLENGE,
        field: negotiationFieldEvidence("proof.challenge.nonce", {
          actual: proof.challenge.nonce,
          note: `this session issued challenge nonce ${issuedChallenge.nonce}`,
        }),
        narrative: `the presented proof answers challenge nonce "${proof.challenge.nonce}", not "${issuedChallenge.nonce}" — the one this session actually issued; a proof captured from a different session (or replayed later) cannot be substituted here`,
      };
    }

    // --- Gate: proof of possession — the ONLY thing examined so far is
    //     `proof` itself. `presentation.credentials` has not been read
    //     even once at this point in the function.
    let presenterPublicKey: Uint8Array;
    try {
      presenterPublicKey = verifyPossession(proof, { now });
    } catch (error) {
      return {
        stage: "proof-of-possession",
        permitted: false,
        claimedDid: proof.did,
        rule: GATE_PROOF_OF_POSSESSION,
        field: negotiationFieldEvidence("proof.signature", { actual: errorMessage(error) }),
        narrative: `${proof.did} did not prove possession of the private key behind that DID over this session's fresh challenge (${errorMessage(error)}) — a copied DID string proves nothing; only a signature nobody without the true private key could produce does, and this one does not verify against that DID's public key`,
      };
    }
    const provenDid = encodeDidKey(presenterPublicKey);

    // --- From here on: M4 (trust) then M5 (policy), unmodified. Only
    //     what was presented and what was just cryptographically proven
    //     (`provenDid`, implicitly, via `proof` itself) are examined.
    // `presentation.credentials` is guarded the same defensive way as
    // `proof` was above — a hostile message could omit it entirely, or
    // supply a non-object, even though `Presentation`'s own TYPE says it
    // is always there; a type never crosses a real boundary for free
    // (the same lesson `lib/identity/did-key.ts`'s `Did` type documents).
    const rawCredentials: unknown = presentation?.credentials;
    const credentials = isPlainObject(rawCredentials) ? rawCredentials : {};
    const authorityJwt = typeof credentials["authorityJwt"] === "string" ? credentials["authorityJwt"] : "";
    // Only a genuine OBJECT is passed through as `credentialStatus` — a
    // `null`/array/primitive here would otherwise reach `checkRevocation`
    // (`lib/trust/status-list.ts`), which reads `entry.statusSize` etc.
    // as its very first statement with no guard of its own (it document-
    // edly trusts its caller to hand it an object). `null` in particular
    // throws on property access rather than returning `undefined`, so
    // this guard is what keeps a hostile `credentialStatus: null` from
    // becoming an unhandled rejection three calls up the stack.
    const rawCredentialStatus = credentials["credentialStatus"];
    const credentialStatus: CredentialStatusEntry | undefined = isPlainObject(rawCredentialStatus) ? (rawCredentialStatus as unknown as CredentialStatusEntry) : undefined;
    const historyJwtsRaw = credentials["historyJwts"];
    const historyJwts: readonly string[] = Array.isArray(historyJwtsRaw) ? historyJwtsRaw.filter((entry): entry is string => typeof entry === "string") : [];

    const authority = await evaluateAuthorityCredentialTrust({
      jwt: authorityJwt,
      presenterProof: proof,
      anchors: this.#options.anchors,
      ...(credentialStatus !== undefined && this.#options.statusListResolver !== undefined
        ? { credentialStatus, statusListResolver: this.#options.statusListResolver }
        : {}),
      now,
      ...(this.#options.clockSkewMs !== undefined ? { clockSkewMs: this.#options.clockSkewMs } : {}),
      ...(this.#options.maxStatusListAgeMs !== undefined ? { maxStatusListAgeMs: this.#options.maxStatusListAgeMs } : {}),
    });

    const history: HistoryTrustDecision[] = [];
    for (const jwt of historyJwts) {
      history.push(
        await evaluateHistoryAttestationTrust({
          jwt,
          presenterProof: proof,
          now,
          ...(this.#options.clockSkewMs !== undefined ? { clockSkewMs: this.#options.clockSkewMs } : {}),
        }),
      );
    }

    const decision = evaluatePolicyRequest({
      policy: this.#options.policy,
      request: sanitizeRequest(request),
      authority,
      history,
    });

    if (decision.permitted) {
      return { stage: "policy", permitted: true, provenDid, explanation: decision.explanation, envelope: decision.envelope };
    }
    return { stage: "policy", permitted: false, provenDid, explanation: decision.explanation };
  }
}
