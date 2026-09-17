"use client";

import { useState } from "react";
import { DidTag } from "./DidTag";
import {
  createChallenge,
  encodeDidKey,
  generateKeyPair,
  provePossession,
  verifyPossession,
  type Did,
} from "../../lib/identity/index.js";

/**
 * Runs entirely IN THE VIEWER'S BROWSER: `lib/identity` has zero
 * `node:` imports (only `@noble/curves` + `@noble/hashes`, pure
 * TypeScript, plus `multiformats` for the `did:key` multibase encoding)
 * — the exact design decision M1's own module comment names: "the same
 * verification code that runs here in M1 is the code that will run
 * client-side in M8's browser demo." This panel is that demo. Contrast
 * with the negotiation above, which cannot run client-side because
 * `lib/trust/bitstring.ts` imports `node:zlib` for revocation — see
 * `app/lib/negotiation-service.ts`'s module comment.
 *
 * The generated private key never leaves this component: it lives only
 * in a local variable inside `runDemo`, is used once to sign a
 * self-issued challenge, and is discarded when the function returns —
 * never stored in React state, never sent anywhere.
 */
type Step = "idle" | "ready" | "error";

export function IdentityPanel() {
  const [step, setStep] = useState<Step>("idle");
  const [did, setDid] = useState<Did | null>(null);
  const [proved, setProved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function runDemo() {
    try {
      const { publicKey, privateKey } = generateKeyPair();
      const generatedDid = encodeDidKey(publicKey);
      const challenge = createChallenge();
      const proof = provePossession(privateKey, generatedDid, challenge);
      const verifiedPublicKey = verifyPossession(proof);
      const ok = verifiedPublicKey.length === publicKey.length && verifiedPublicKey.every((byte, index) => byte === publicKey[index]);
      setDid(generatedDid);
      setProved(ok);
      setStep("ready");
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
      setStep("error");
    }
  }

  return (
    <section aria-labelledby="identity-heading" className="panel panel-secondary">
      <h2 id="identity-heading">Identity, generated in your browser</h2>
      <p className="panel-lede">
        <code>lib/identity</code> has no server-only dependency, so the exact same Ed25519 code that ran the negotiation above can run
        here, in this page, in your browser &mdash; nothing is sent to any server for this part. Your private key is generated, used
        once to sign a challenge, and discarded; it is never stored or transmitted.
      </p>
      <button type="button" className="evaluate-button" onClick={runDemo}>
        {step === "idle" ? "Generate a did:key and prove possession" : "Do it again"}
      </button>
      {step === "ready" && did !== null ? (
        <div className="identity-result">
          <div className="did-compare-row">
            <span className="did-compare-label">your did:key</span>
            <DidTag did={did} />
          </div>
          <p className={proved ? "identity-ok" : "identity-fail"}>
            {proved
              ? "Possession proven: a challenge was signed with the matching private key and verified against this DID's public key — entirely client-side."
              : "Verification did not recover the same public key — this should never happen; please report it."}
          </p>
        </div>
      ) : null}
      {step === "error" && error !== null ? <p className="panel-error" role="alert">{error}</p> : null}
    </section>
  );
}
