/**
 * REGRESSION 11 — a validly-signed non-JSON payload crashed the
 * verifier. REAL HISTORICAL DEFECT (M3, CRITICAL), not a hypothetical:
 * an attacker signs arbitrary non-JSON bytes with its own real Ed25519
 * key and sets the JWS header's `kid` to its own genuine DID. The JWS
 * parses cleanly (3 well-formed base64url segments), the signature
 * GENUINELY verifies (a real key signed exactly these bytes) — and then
 * `JSON.parse` throws on the non-JSON payload, and that exception
 * propagated UNCAUGHT out of both `verifyAuthorityCredential` and
 * `verifyHistoryAttestation`, instead of the structured
 * `VerificationFailure` this project's whole design promises.
 *
 * See `lib/credentials/jws.ts`'s `decodeVerifiedPayload` (which now
 * wraps this exact case in a try/catch and throws a typed
 * `MalformedJwsError`) and `lib/credentials/verify.ts`'s own comment:
 * "A signature can be perfectly valid over bytes that still aren't
 * valid JSON (an attacker signing arbitrary non-JSON bytes with their
 * OWN real key)... this can throw `MalformedJwsError` exactly like
 * `parseCompactJws` above does for the header segment." The SAME bug
 * class is independently guarded a second time in `lib/trust/jws-lite.ts`
 * (`SyntaxErrorAsPayloadError`, used by `status-list.ts`/`vouch.ts`) —
 * see regression 12's own comment, and `verify.ts`'s comment that this
 * "same bug class M3 was once rejected for leaving unguarded" is cited
 * throughout `lib/trust` as the reason those call sites guard it too.
 *
 * This test proves the fix now RETURNS a structured failure at the
 * "parse" step (both verify functions), rather than throwing.
 */
import { describe, expect, it } from "vitest";
import { createChallenge } from "../../../lib/identity/index.js";
import { verifyAuthorityCredential, verifyHistoryAttestation } from "../../../lib/credentials/index.js";
import { refineParseFailure } from "../../../lib/policy/index.js";
import { craftSignedNonJsonJws, makeIdentity } from "../helpers.js";

describe("regression 11 — a validly-signed non-JSON payload no longer crashes the verifier (real M3 CRITICAL defect)", () => {
  it("verifyAuthorityCredential does NOT throw for a genuinely-signed, non-JSON payload — it returns a structured \"parse\" failure", () => {
    const attacker = makeIdentity();
    const jwt = craftSignedNonJsonJws(attacker, "this is not JSON at all { [ garbage");
    const now = Date.now();
    const challenge = createChallenge({ now });
    const proof = { did: attacker.did, challenge, signature: "00".repeat(64) };

    expect(() => verifyAuthorityCredential(jwt, proof, { now })).not.toThrow();

    const result = verifyAuthorityCredential(jwt, proof, { now });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.step).toBe("parse");
      expect(result.reason).toContain("payload is not valid JSON");
    }
  });

  it("verifyHistoryAttestation does NOT throw for the identical attack shape", () => {
    const attacker = makeIdentity();
    const jwt = craftSignedNonJsonJws(attacker, "also not json: <<<>>>");
    const now = Date.now();
    const challenge = createChallenge({ now });
    const proof = { did: attacker.did, challenge, signature: "00".repeat(64) };

    expect(() => verifyHistoryAttestation(jwt, proof, { now })).not.toThrow();

    const result = verifyHistoryAttestation(jwt, proof, { now });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.step).toBe("parse");
      expect(result.reason).toContain("payload is not valid JSON");
    }
  });

  it("M5's own recovered distinction (verification-step-detail.ts) correctly labels this as the STRONGER post-signature signal, not a mere pre-signature parse failure", () => {
    const attacker = makeIdentity();
    const jwt = craftSignedNonJsonJws(attacker, "{not valid json");
    const now = Date.now();
    const challenge = createChallenge({ now });
    const proof = { did: attacker.did, challenge, signature: "00".repeat(64) };

    const result = verifyAuthorityCredential(jwt, proof, { now });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      const refinement = refineParseFailure(result.step, result.reason);
      expect(refinement).toBe("post-signature-payload-not-json");
      expect(refinement).not.toBe("pre-signature");
    }
  });

  it("[sanity] a genuinely malformed (unparseable) JWS is still labelled \"parse\" but refined as pre-signature — the distinction is real, not vacuous", () => {
    const result = verifyAuthorityCredential("not-a-jwt-at-all", { did: makeIdentity().did, challenge: createChallenge(), signature: "00" }, {});
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.step).toBe("parse");
      const refinement = refineParseFailure(result.step, result.reason);
      expect(refinement).toBe("pre-signature");
    }
  });
});
