/**
 * The Supplier: the composition root of M6. Holds a policy and a set of
 * trust anchors (never a keypair belonging to anyone else — see
 * `agent.ts`'s module comment on KEY_SEPARATION) and turns a
 * `Presentation` into a `NegotiationDecision` by running, in order:
 *
 *   1. **Session binding** — does this presentation's proof answer the
 *      EXACT challenge this session issued? (`GATE_SESSION_CHALLENGE`)
 *   1.5. **Single-use, "already spent" check** (FIX 3, L4 M6 review) —
 *      has THIS session already consumed this exact nonce via an
 *      earlier `evaluatePresentation` call? (`GATE_CHALLENGE_ALREADY_
 *      CONSUMED`) — see `#consumedChallengeNonces`'s own comment for why
 *      this state lives here and not in `lib/identity/challenge.ts`.
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
 *   2.5. **Single-use, "mark spent" step** (FIX 3, L4 M6 review; REORDERED
 *      in the SECOND L4 M6 review, FIX B) — only once (2) has actually
 *      verified does the nonce get marked consumed, immediately
 *      afterward and still before credential trust or policy run, so a
 *      rejected attempt still can never be retried against the same
 *      challenge for a LATER reason (untrusted issuer, over-scope, ...).
 *      The first fix round consumed the nonce BEFORE step 2, the instant
 *      a presentation merely CITED it — which let anyone who knew or
 *      intercepted a challenge nonce (public the moment it's on the
 *      wire) burn the legitimate holder's one shot with a garbage
 *      signature, without holding any private key. See the `try`/`catch`
 *      around `verifyPossession` below for exactly where consumption now
 *      happens, and why that ordering doesn't weaken the concurrency
 *      guarantee.
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
 *
 * DEPLOYMENT WARNING (FIX D, second L4 M6 review): the single-use
 * guarantee above (steps 1.5/2.5) is tracked in `#consumedChallengeNonces`
 * — an in-memory field on ONE `Supplier` INSTANCE, not anything shared or
 * durable. That is deliberate for this milestone (`Supplier` is
 * documented, here and in that field's own comment, as "the stateful,
 * long-lived object for one real negotiation session"), but it is only
 * as strong as the deployment's own discipline about instance lifetime:
 * a `Supplier` reused across the whole session sees every nonce it has
 * ever issued and can genuinely refuse a replay. A STATELESS server that
 * constructs a fresh `Supplier` per HTTP request, by contrast, would
 * silently defeat single-use entirely — every request gets a brand-new,
 * empty `#consumedChallengeNonces`, so the exact same (challenge,
 * presentation) pair verifies again on every "fresh" instance, with no
 * error, no warning, nothing to notice until it's exploited. A real
 * production deployment that cannot pin one `Supplier` instance to one
 * session for its whole lifetime (for example: a horizontally-scaled or
 * per-request-instantiated backend) needs single-use tracked in shared
 * storage instead — e.g. a keyed store (Redis, a database table, ...)
 * that every process/request consults, keyed by nonce, with the same
 * "consume only after `verifyPossession` succeeds" ordering as FIX B
 * below and its own TTL-based eviction mirroring `#pruneExpiredNonces`.
 * That storage is out of scope here — this module only documents the
 * requirement, deliberately does not build it.
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
import {
  GATE_CHALLENGE_ALREADY_CONSUMED,
  GATE_MALFORMED_PRESENTATION,
  GATE_PROOF_OF_POSSESSION,
  GATE_SESSION_CHALLENGE,
  negotiationFieldEvidence,
} from "./explanation.js";
import type { NegotiationRequest, Presentation } from "./messages.js";

/** Cap on how many `vouches` candidates one presentation may offer
 *  before being forwarded to `lib/trust`'s `evaluateIssuerTrust`. See
 *  this module's own comment on `sanitizeVouches` (FIX 4, L4 M6 review)
 *  for why this exists: `evaluateIssuerTrust` independently
 *  cryptographically verifies EVERY candidate (one `verifyVouch` call —
 *  a real Ed25519 verification — per entry), and that loop lives in
 *  `lib/trust/anchors.ts`, which is FROZEN for this milestone and takes
 *  no cap of its own. A legitimate presenter needs at most one real
 *  vouch to satisfy the depth-1 model (`VOUCH_DEPTH_LIMIT`); this cap is
 *  deliberately generous well beyond that (room for a presenter that
 *  genuinely holds vouches from several candidate anchors) while still
 *  bounding the worst-case synchronous verification cost of a single
 *  `evaluatePresentation` call to a small constant regardless of how
 *  many entries a hostile counterparty stuffs into the message.
 *
 *  Exported so `supplier.test.ts`'s regression test (FIX C, second L4
 *  M6 review) can size its fixtures off the real cap instead of a
 *  second, independently-hardcoded "16" that could silently drift out
 *  of sync with this one. Mutation testing found that removing the
 *  `.slice` this constant feeds (below, in `sanitizeVouches`) broke
 *  none of the 288 existing tests, even though the cap demonstrably
 *  changes real outcomes (a real vouch beyond the cap is dropped and
 *  never verified) — nothing in the suite had ever exercised more than
 *  a handful of vouches at once. */
export const MAX_VOUCHES_PER_PRESENTATION = 16;

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
 *
 * Exported ONLY so `supplier.test.ts` can assert this function's own
 * copying behaviour directly (second L4 M6 review, FIX C): mutation
 * testing found that gutting this function to pass `rawScope` through BY
 * REFERENCE (dropping the defensive copy, keeping only the shape check)
 * broke none of the 288 existing tests, because `lib/policy/engine.ts`'s
 * own guard (`safe-scope-read.ts`) independently tolerates the same
 * hostile accessors and produces the identical DECISION either way —
 * that guard was never a substitute for this one, but from outside
 * `evaluatePresentation` the two are indistinguishable. The only way to
 * pin "this function itself still copies" is to call it directly and
 * inspect its return value's identity, not the decision it eventually
 * feeds into.
 */
export function sanitizeScope(rawScope: unknown): Record<string, unknown> {
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

/**
 * Coerce a hostile/malformed `PresentedCredentials.vouches` into an
 * array `lib/trust`'s `evaluateIssuerTrust` can safely consume (FIX 4,
 * L4 M6 review): a non-array is read as "no vouches offered" (never a
 * thrown error from iterating a non-iterable), a non-string entry
 * (`null`, a number, an object masquerading as a JWT) is dropped rather
 * than handed to `verifyVouch`, and the result is capped at
 * `MAX_VOUCHES_PER_PRESENTATION` — see that constant's own comment for
 * why the cap exists (each surviving entry costs one real signature
 * verification in a dependency this milestone does not modify).
 */
function sanitizeVouches(rawVouches: unknown): readonly string[] {
  if (!Array.isArray(rawVouches)) {
    return [];
  }
  const strings = rawVouches.filter((entry): entry is string => typeof entry === "string");
  return strings.slice(0, MAX_VOUCHES_PER_PRESENTATION);
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

  /**
   * Nonces of challenges already answered by an evaluated presentation,
   * mapped to that challenge's own `expiresAt` (FIX 3, L4 M6 review).
   *
   * `lib/identity/challenge.ts` deliberately does not track nonces
   * itself — its own module comment says plainly "this module must work
   * with no storage" and names the caller as responsible for single-use
   * semantics. `Supplier` is exactly that: the stateful, long-lived
   * object for one real negotiation session, unlike the stateless
   * `createChallenge`/`verifyPossession` primitives. This is where "a
   * challenge may be answered at most once" is actually enforced.
   *
   * Bounded memory: `#pruneExpiredNonces` (called at the top of every
   * `evaluatePresentation`) drops every entry this session's own
   * `verifyPossession` (M1, frozen) would ALREADY refuse to accept a
   * fresh proof against — see that method's own comment for exactly why
   * the prune predicate is written as M1's complement, never restated
   * as its own constant. Nothing is lost by pruning on that boundary:
   * a nonce still inside it can still be legitimately replayed-checked
   * (single-use must still catch it), and a nonce past it is refused
   * regardless by `verifyPossession`'s own `ChallengeExpiredError`
   * check, so dropping the bookkeeping entry changes nothing observable.
   */
  readonly #consumedChallengeNonces = new Map<string, number>();

  constructor(options: SupplierOptions) {
    this.#options = options;
  }

  /**
   * Drop every consumed-nonce bookkeeping entry that cannot possibly
   * matter anymore — see `#consumedChallengeNonces`'s own comment.
   *
   * SECOND L4 M6 REVIEW (FIX A, CRITICAL): this predicate must stay the
   * exact logical complement of M1's `verifyPossession` expiry check
   * (`lib/identity/challenge.ts`: `if (now > proof.challenge.expiresAt)
   * throw ChallengeExpiredError`) — never a value independently derived
   * from `expiresAt`. `verifyPossession` is frozen for this milestone
   * and is the sole authority on "is this challenge still acceptable";
   * this Supplier only remembers nonces, it does not get its own vote.
   * M1 refuses when `now > expiresAt`, i.e. it still ACCEPTS at the
   * boundary `now === expiresAt`. So this must evict only when
   * `now > expiresAt` too (`expiresAt < now`) — an entry sitting exactly
   * on the boundary is one M1 would still accept a fresh proof against,
   * so pruning it here would let single-use bookkeeping forget a nonce
   * proof-of-possession still considers live, reopening the exact replay
   * window FIX 3 (first L4 M6 review) existed to close. The previous
   * version of this line read `expiresAt <= now` — off by the single
   * instant `now === expiresAt` — which is precisely the regression
   * `supplier.test.ts`'s "prune/expiry boundary" block pins.
   *
   * A future change to EITHER this line or `verifyPossession`'s own
   * expiry check must keep them exact complements of one another
   * (`<=` here iff `>` there, or vice versa) — whichever direction
   * changes, re-derive this one from it rather than editing them
   * independently, or this same one-instant replay window reopens.
   */
  #pruneExpiredNonces(now: number): void {
    for (const [nonce, expiresAt] of this.#consumedChallengeNonces) {
      if (expiresAt < now) {
        this.#consumedChallengeNonces.delete(nonce);
      }
    }
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
    this.#pruneExpiredNonces(now);
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

    // --- Gate: single-use (FIX 3, L4 M6 review) — this EXACT challenge,
    //     confirmed above to be one this session genuinely issued, must
    //     not already have been answered by an earlier evaluated
    //     presentation. Checked before proof-of-possession (cheaper, and
    //     logically prior: "has this already been spent" doesn't need a
    //     signature check to answer).
    if (this.#consumedChallengeNonces.has(issuedChallenge.nonce)) {
      return {
        stage: "proof-of-possession",
        permitted: false,
        claimedDid: proof.did,
        rule: GATE_CHALLENGE_ALREADY_CONSUMED,
        field: negotiationFieldEvidence("proof.challenge.nonce", {
          actual: proof.challenge.nonce,
          note: "this session already consumed this exact challenge nonce via an earlier evaluatePresentation call",
        }),
        narrative: `challenge nonce "${issuedChallenge.nonce}" was already answered by an earlier presentation to this session — a challenge may be answered at most once, so this replay is refused even though the nonce genuinely belongs to this session and has not yet expired`,
      };
    }
    // --- Gate: proof of possession — the ONLY thing examined so far is
    //     `proof` itself. `presentation.credentials` has not been read
    //     even once at this point in the function.
    //
    // SECOND L4 M6 REVIEW (FIX B): this check runs BEFORE the nonce is
    // marked consumed (below) — deliberately reordered from the first
    // fix round, which consumed the nonce the instant a presentation
    // CITED it, regardless of whether it proved anything. That let
    // anyone who merely knew or intercepted a challenge nonce (public
    // information the moment it's on the wire — nonces are not secrets,
    // only private keys are) burn the real counterparty's one shot with
    // a garbage signature, never having held any private key: a pure
    // denial of service against the legitimate holder. Verifying first
    // and consuming only on success means an invalid signature costs
    // the attacker nothing AND costs the legitimate holder nothing —
    // their own, still-unconsumed, genuinely-answerable challenge is
    // untouched by someone else's failed attempt against the same nonce.
    let presenterPublicKey: Uint8Array;
    try {
      presenterPublicKey = verifyPossession(proof, { now });
    } catch (error) {
      // Possession was NOT proven — the nonce stays unconsumed, so the
      // legitimate holder (if this attempt wasn't them) can still answer
      // this same challenge afterwards.
      return {
        stage: "proof-of-possession",
        permitted: false,
        claimedDid: proof.did,
        rule: GATE_PROOF_OF_POSSESSION,
        field: negotiationFieldEvidence("proof.signature", { actual: errorMessage(error) }),
        narrative: `${proof.did} did not prove possession of the private key behind that DID over this session's fresh challenge (${errorMessage(error)}) — a copied DID string proves nothing; only a signature nobody without the true private key could produce does, and this one does not verify against that DID's public key`,
      };
    }

    // Possession genuinely proven, over THIS session's own,
    // not-yet-consumed challenge — NOW consume the nonce, still before
    // credential trust or policy are evaluated, so a presentation that
    // clears THIS gate can never be retried after being refused for some
    // OTHER reason (untrusted issuer, over-scope, ...) below. This keeps
    // FIX 3's original guarantee ("a rejected attempt can never be
    // retried") intact for every refusal reason from here on, while no
    // longer applying it to a signature that never verified at all.
    //
    // Still entirely synchronous relative to every check above (no
    // `await` has occurred yet in this call) — the concurrency property
    // ("two calls racing on one challenge via Promise.all: exactly one
    // permitted") is unaffected by moving this line: a JS async function
    // runs synchronously up to its first `await`, so of two concurrent
    // `evaluatePresentation` calls on the same nonce, whichever's
    // synchronous prefix reaches this line first commits the nonce
    // before the other call's single-use check (above) can observe
    // anything else; the loser is refused there, not here.
    this.#consumedChallengeNonces.set(issuedChallenge.nonce, issuedChallenge.expiresAt);

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
    // FIX 4 (L4 M6 review): wire M4's `vouched` issuer-trust path through
    // this protocol — see `messages.ts`'s `PresentedCredentials.vouches`
    // and `sanitizeVouches` above for why this is capped and filtered
    // before ever reaching `evaluateAuthorityCredentialTrust`/
    // `evaluateIssuerTrust` (`lib/trust`, unmodified).
    const vouches = sanitizeVouches(credentials["vouches"]);

    const authority = await evaluateAuthorityCredentialTrust({
      jwt: authorityJwt,
      presenterProof: proof,
      anchors: this.#options.anchors,
      vouches,
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
