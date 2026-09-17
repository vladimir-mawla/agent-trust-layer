/**
 * A negotiating party's own identity: an Ed25519 keypair it alone
 * generates and holds, plus the `did:key` derived from it (M1).
 *
 * ## Why this class is the whole KEY_SEPARATION story
 *
 * `#privateKey` is a true JavaScript private class field (the `#` form,
 * not an underscore-prefixed convention) — it is a SyntaxError for any
 * code outside this class body to even name it, let alone read it.
 * `Supplier` (`supplier.ts`) never receives a `KeyHolder` instance at
 * all: it only ever receives a `Presentation` message — a challenge
 * response and JWT strings, exactly what a real wire protocol would
 * carry. `grep -n "privateKey" lib/negotiation/supplier.ts` finds
 * nothing, which is the concrete, checkable form of "the Supplier could
 * not forge the Buyer's proof even if it wanted to": there is no
 * variable, parameter, or import anywhere in the Supplier's own module
 * through which the Buyer's private key could arrive.
 *
 * Two agents in the M6 scenario (`scenario.ts`) are each their own,
 * independently-constructed `KeyHolder` — a Buyer and an Attacker, each
 * with a keypair the OTHER never sees. The Supplier is a separate class
 * (`supplier.ts`) that holds no keypair of its own at all in this
 * protocol slice: it only holds a policy and a set of trust anchors, and
 * verifies what is presented to it.
 */
import {
  encodeDidKey,
  generateKeyPair,
  provePossession,
  type Challenge,
  type Did,
  type ProofOfPossession,
} from "../identity/index.js";
import { issueAuthorityCredential, type IssueAuthorityCredentialInput } from "../credentials/index.js";
import { issueStatusListCredential, type IssueStatusListCredentialInput } from "../trust/index.js";

export class KeyHolder {
  readonly did: Did;
  readonly #privateKey: Uint8Array;

  constructor() {
    const { publicKey, privateKey } = generateKeyPair();
    this.did = encodeDidKey(publicKey);
    this.#privateKey = privateKey;
  }

  /**
   * Honest proof of possession: signs `challenge` while claiming THIS
   * holder's own DID. This is the only proof-producing method an honest
   * participant in the protocol ever calls.
   */
  provePossession(challenge: Challenge): ProofOfPossession {
    return provePossession(this.#privateKey, this.did, challenge);
  }

  /**
   * Models a DISHONEST presenter: signs `challenge` while claiming a DID
   * this holder does NOT control (`claimedDid`). This exists solely to
   * construct the M6 impersonation attack fixture (`scenario.ts`'s
   * "spoofed identity" beat) and is never reachable from
   * `provePossession` above. It does not — and structurally cannot —
   * grant the caller possession of anyone else's key: the signature it
   * produces is still made with THIS holder's own `#privateKey`, over a
   * message that names `claimedDid`. When the Supplier verifies that
   * signature against the public key it decodes FROM `claimedDid` (the
   * victim's real, public DID string), the two keys don't match and
   * verification fails — which is the entire mechanism behind "copying a
   * DID string proves nothing" (M1's own design goal, exercised here as
   * an attack rather than merely asserted in a comment).
   */
  attemptProofOfPossessionFor(claimedDid: Did, challenge: Challenge): ProofOfPossession {
    return provePossession(this.#privateKey, claimedDid, challenge);
  }

  /**
   * Issue and sign an `AuthorityCredential` naming this holder as
   * `issuer`. Used both for a legitimate trust-anchor identity granting
   * the Buyer authority, and — in the forged-credential attack fixture —
   * by an attacker minting authority over itself with its own key. Which
   * of those two things a given call represents is entirely a property
   * of WHO the caller is and what `subjectDid` it names, never of this
   * method's own logic: the method itself does not know or care whether
   * its caller is "the good issuer" or "an attacker".
   */
  issueAuthorityCredentialTo(input: Omit<IssueAuthorityCredentialInput, "issuerPrivateKey" | "issuerDid">): string {
    return issueAuthorityCredential({ ...input, issuerPrivateKey: this.#privateKey, issuerDid: this.did });
  }

  /** Issue and sign a `BitstringStatusListCredential` naming this holder
   *  as its issuer — used by the trust-anchor identity to publish the
   *  revocation status list the Supplier resolves during Beat 1/2. */
  issueStatusListCredential(input: Omit<IssueStatusListCredentialInput, "issuerPrivateKey" | "issuerDid">): string {
    return issueStatusListCredential({ ...input, issuerPrivateKey: this.#privateKey, issuerDid: this.did });
  }
}
