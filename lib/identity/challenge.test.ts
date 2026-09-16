import { describe, expect, it } from "vitest";
import {
  createChallenge,
  provePossession,
  verifyPossession,
  type Challenge,
} from "./challenge.js";
import { encodeDidKey } from "./did-key.js";
import { generateKeyPair } from "./keys.js";
import { ChallengeExpiredError, MalformedDidError, ProofVerificationError } from "./errors.js";

describe("createChallenge", () => {
  it("produces a nonce, and issuedAt strictly before expiresAt", () => {
    const challenge = createChallenge({ now: 1_000, ttlMs: 60_000 });
    expect(challenge.nonce).toMatch(/^[0-9a-f]+$/);
    expect(challenge.issuedAt).toBe(1_000);
    expect(challenge.expiresAt).toBe(61_000);
  });

  it("generates a different nonce every call", () => {
    const a = createChallenge();
    const b = createChallenge();
    expect(a.nonce).not.toBe(b.nonce);
  });

  it("rejects a non-positive TTL", () => {
    expect(() => createChallenge({ ttlMs: 0 })).toThrow(RangeError);
    expect(() => createChallenge({ ttlMs: -1 })).toThrow(RangeError);
  });
});

describe("provePossession / verifyPossession", () => {
  it("verifies a genuine proof and returns the claimed public key", () => {
    const { publicKey, privateKey } = generateKeyPair();
    const did = encodeDidKey(publicKey);
    const challenge = createChallenge({ now: 0, ttlMs: 60_000 });

    const proof = provePossession(privateKey, did, challenge);
    const verified = verifyPossession(proof, { now: 1_000 });

    expect(verified).toEqual(publicKey);
  });

  it("HEADLINE: signing a challenge with the WRONG key fails verification", () => {
    const owner = generateKeyPair();
    const attacker = generateKeyPair();
    const did = encodeDidKey(owner.publicKey); // the DID being claimed is the OWNER's

    const challenge = createChallenge({ now: 0, ttlMs: 60_000 });

    // The attacker signs with their OWN private key but claims the
    // owner's DID — they never had the owner's private key.
    const forgedProof = provePossession(attacker.privateKey, did, challenge);

    expect(() => verifyPossession(forgedProof, { now: 1_000 })).toThrow(ProofVerificationError);
  });

  it("rejects a proof whose nonce was tampered with after signing", () => {
    const { publicKey, privateKey } = generateKeyPair();
    const did = encodeDidKey(publicKey);
    const challenge = createChallenge({ now: 0, ttlMs: 60_000 });
    const proof = provePossession(privateKey, did, challenge);

    const tampered = {
      ...proof,
      challenge: { ...proof.challenge, nonce: `${proof.challenge.nonce}ff` } as Challenge,
    };

    expect(() => verifyPossession(tampered, { now: 1_000 })).toThrow(ProofVerificationError);
  });

  it("rejects a proof whose expiry was extended after signing", () => {
    const { publicKey, privateKey } = generateKeyPair();
    const did = encodeDidKey(publicKey);
    const challenge = createChallenge({ now: 0, ttlMs: 60_000 });
    const proof = provePossession(privateKey, did, challenge);

    // Extend expiresAt further into the future than what was actually
    // signed — the signature no longer matches the (tampered) message,
    // regardless of whether the new expiry itself looks fine.
    const tampered = {
      ...proof,
      challenge: { ...proof.challenge, expiresAt: proof.challenge.expiresAt + 1_000_000 } as Challenge,
    };

    expect(() => verifyPossession(tampered, { now: 1_000 })).toThrow(ProofVerificationError);
  });

  it("rejects an expired challenge even though the signature is valid", () => {
    const { publicKey, privateKey } = generateKeyPair();
    const did = encodeDidKey(publicKey);
    const challenge = createChallenge({ now: 0, ttlMs: 1_000 });
    const proof = provePossession(privateKey, did, challenge);

    // The signature over this exact, untampered proof IS valid — only
    // the passage of time makes it unacceptable.
    expect(() => verifyPossession(proof, { now: 5_000 })).toThrow(ChallengeExpiredError);
  });

  it("propagates a typed error for a malformed DID rather than throwing generically", () => {
    const challenge = createChallenge();
    const bogusProof = {
      did: "not-a-did" as never,
      challenge,
      signature: "00".repeat(64),
    };

    expect(() => verifyPossession(bogusProof, { now: 0 })).toThrow(MalformedDidError);
  });

  it("rejects a proof with a garbage (non-hex) signature instead of throwing unhandled", () => {
    const { publicKey } = generateKeyPair();
    const did = encodeDidKey(publicKey);
    const challenge = createChallenge({ now: 0, ttlMs: 60_000 });

    const bogusProof = { did, challenge, signature: "not-hex!!" };

    expect(() => verifyPossession(bogusProof, { now: 1_000 })).toThrow(ProofVerificationError);
  });
});
