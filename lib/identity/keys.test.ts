import { describe, expect, it } from "vitest";
import {
  ED25519_PUBLIC_KEY_LENGTH,
  ED25519_PRIVATE_KEY_LENGTH,
  decodePublicKeyHex,
  derivePublicKey,
  encodePublicKeyHex,
  generateKeyPair,
} from "./keys.js";
import { InvalidPublicKeyError } from "./errors.js";

describe("generateKeyPair", () => {
  it("produces correctly-sized Ed25519 keys", () => {
    const { publicKey, privateKey } = generateKeyPair();
    expect(publicKey).toHaveLength(ED25519_PUBLIC_KEY_LENGTH);
    expect(privateKey).toHaveLength(ED25519_PRIVATE_KEY_LENGTH);
  });

  it("generates a different keypair every call", () => {
    const a = generateKeyPair();
    const b = generateKeyPair();
    expect(a.privateKey).not.toEqual(b.privateKey);
    expect(a.publicKey).not.toEqual(b.publicKey);
  });

  it("derives the same public key from the private key it came with", () => {
    const { publicKey, privateKey } = generateKeyPair();
    expect(derivePublicKey(privateKey)).toEqual(publicKey);
  });
});

describe("encodePublicKeyHex / decodePublicKeyHex", () => {
  it("round-trips a public key through hex", () => {
    const { publicKey } = generateKeyPair();
    const hex = encodePublicKeyHex(publicKey);
    expect(decodePublicKeyHex(hex)).toEqual(publicKey);
  });

  it("rejects hex that decodes to the wrong length", () => {
    expect(() => decodePublicKeyHex("aabbcc")).toThrow(InvalidPublicKeyError);
  });

  it("rejects non-hex input", () => {
    expect(() => decodePublicKeyHex("not-hex-at-all!!")).toThrow(InvalidPublicKeyError);
  });

  it("rejects encoding a public key of the wrong length", () => {
    expect(() => encodePublicKeyHex(new Uint8Array(31))).toThrow(InvalidPublicKeyError);
  });
});
