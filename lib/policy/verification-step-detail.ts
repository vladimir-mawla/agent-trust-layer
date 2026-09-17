/**
 * M3_STEP_LABEL: recovering a distinction M3's own `VerificationStep`
 * collapses, without editing M3 (frozen).
 *
 * `lib/credentials/verify.ts` labels TWO different failures with the
 * identical `step: "parse"`:
 *   1. the JWS wire format itself is broken (`parseCompactJws` throws),
 *      discovered BEFORE any signature is checked — nothing about the
 *      token has been trusted yet at all; and
 *   2. the signature verifies successfully, but the bytes it covers are
 *      not valid JSON (`decodeVerifiedPayload` throws) — this can ONLY
 *      happen after a real key holder produced a real signature over
 *      those exact bytes.
 *
 * `verify.ts`'s own comment calls this out deliberately: case 2 is
 * discovered "one step later" than case 1, "same failure class... just
 * discovered one step later", and is intentionally reported with the
 * identical step label. That is the right call for `lib/credentials`
 * itself (both are, from a pure verification-chain perspective, "could
 * not get a usable payload out of this token"). It stops being the
 * right call the moment something downstream builds telemetry or an
 * explanation OVER the step label alone: a system that reads "parse" as
 * shorthand for "never got signature-checked" will misclassify case 2,
 * which is a materially STRONGER attack signal (a real keyholder
 * deliberately signed garbage) than case 1 (an attacker who couldn't
 * even produce a well-formed token).
 *
 * This module recovers the distinction for M5's explanations without
 * touching M3. Because M3's `VerificationFailure` carries no separate
 * field for it, the only signal available post-hoc is the `reason`
 * STRING `verify.ts` already produces — specifically,
 * `decodeVerifiedPayload` (in `lib/credentials/jws.ts`) is the ONLY
 * "parse"-step throw site whose message is exactly
 * `"payload is not valid JSON"` (`MalformedJwsError`'s `${reason}`
 * template makes that message `"Malformed JWS: payload is not valid
 * JSON"`); every pre-signature `parseCompactJws` failure produces a
 * different message (`"token is empty"`, `"expected 3 dot-separated
 * segments..."`, `"payload is not valid base64url"`, etc. — note
 * `"payload is not valid base64url"` is a DIFFERENT message than
 * `"payload is not valid JSON"`, and is itself pre-signature: it means
 * the payload SEGMENT isn't even valid base64url, discovered before any
 * signature check, unlike the JSON check which runs only after).
 *
 * This is a string match against a message `lib/credentials` owns and
 * could change — deliberately confined to THIS module (`engine.ts` calls
 * it only to enrich an `Explanation`'s narrative/evidence, never to
 * change an accept/refuse OUTCOME), and pinned by
 * `verification-step-detail.test.ts` against the actual message
 * `lib/credentials` produces today via a real fabricated JWS (a genuine
 * signature over genuinely non-JSON bytes), so a future change to that
 * message fails a test in THIS module rather than silently losing the
 * distinction again.
 */
import type { VerificationStep } from "../credentials/index.js";

export type ParseFailureRefinement = "pre-signature" | "post-signature-payload-not-json" | "not-applicable";

/** The exact, and only, message `decodeVerifiedPayload` produces for a
 *  verified-but-non-JSON payload, wrapped in `MalformedJwsError`'s
 *  `Malformed JWS: ${reason}` template. See the module comment. */
const POST_SIGNATURE_PAYLOAD_NOT_JSON_MESSAGE = "Malformed JWS: payload is not valid JSON";

/**
 * Refine a `"parse"`-step `VerificationFailure` into which of the two
 * distinct cases it actually is. Returns `"not-applicable"` for any
 * other step (there is nothing to refine — the distinction this module
 * exists for is specific to `"parse"`).
 */
export function refineParseFailure(step: VerificationStep, reason: string): ParseFailureRefinement {
  if (step !== "parse") {
    return "not-applicable";
  }
  return reason === POST_SIGNATURE_PAYLOAD_NOT_JSON_MESSAGE ? "post-signature-payload-not-json" : "pre-signature";
}

/** Human-readable note for an `Explanation`'s field evidence — never
 *  itself the authoritative signal (that's the `ParseFailureRefinement`
 *  value), just a rendering of it. */
export function describeParseFailureRefinement(refinement: ParseFailureRefinement): string | undefined {
  switch (refinement) {
    case "pre-signature":
      return "wire format was unparseable before any signature check ran";
    case "post-signature-payload-not-json":
      return "a real signature verified over bytes that are not valid JSON — a stronger attack signal than an unparseable token (see M3_STEP_LABEL)";
    case "not-applicable":
      return undefined;
  }
}
