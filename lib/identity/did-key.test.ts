import { describe, expect, it } from "vitest";
import { base58btc } from "multiformats/bases/base58";
import { decodeDidKey, encodeDidKey } from "./did-key.js";
import { generateKeyPair } from "./keys.js";
import { MalformedDidError } from "./errors.js";

describe("encodeDidKey / decodeDidKey round trip", () => {
  it("decodes back to exactly the same public key bytes it was derived from", () => {
    const { publicKey } = generateKeyPair();
    const did = encodeDidKey(publicKey);
    expect(decodeDidKey(did)).toEqual(publicKey);
  });

  it("produces a did:key with the expected method prefix and multibase marker", () => {
    const { publicKey } = generateKeyPair();
    const did = encodeDidKey(publicKey);
    expect(did.startsWith("did:key:z")).toBe(true);
  });

  it("is deterministic: encoding the same key twice gives the same DID", () => {
    const { publicKey } = generateKeyPair();
    expect(encodeDidKey(publicKey)).toBe(encodeDidKey(publicKey));
  });
});

describe("decodeDidKey rejects malformed input", () => {
  it("rejects a string missing the did:key: prefix", () => {
    const { publicKey } = generateKeyPair();
    const did = encodeDidKey(publicKey);
    const withoutPrefix = did.slice("did:key:".length);
    try {
      decodeDidKey(withoutPrefix);
      expect.unreachable("expected decodeDidKey to throw");
    } catch (err) {
      expect(err).toBeInstanceOf(MalformedDidError);
      expect((err as MalformedDidError).reason).toBe("BAD_PREFIX");
    }
  });

  it("rejects a completely unrelated string", () => {
    try {
      decodeDidKey("not-a-did-at-all");
      expect.unreachable("expected decodeDidKey to throw");
    } catch (err) {
      expect(err).toBeInstanceOf(MalformedDidError);
      expect((err as MalformedDidError).reason).toBe("BAD_PREFIX");
    }
  });

  it("rejects invalid base58btc after the prefix", () => {
    // '0', 'O', 'I', 'l' are all excluded from the base58 alphabet.
    try {
      decodeDidKey("did:key:z0OIl-not-base58");
      expect.unreachable("expected decodeDidKey to throw");
    } catch (err) {
      expect(err).toBeInstanceOf(MalformedDidError);
      expect((err as MalformedDidError).reason).toBe("BAD_MULTIBASE");
    }
  });

  it("rejects a multibase string with no leading z", () => {
    const { publicKey } = generateKeyPair();
    const did = encodeDidKey(publicKey);
    const multibaseWithoutZ = did.slice("did:key:z".length);
    try {
      decodeDidKey(`did:key:${multibaseWithoutZ}`);
      expect.unreachable("expected decodeDidKey to throw");
    } catch (err) {
      expect(err).toBeInstanceOf(MalformedDidError);
      expect((err as MalformedDidError).reason).toBe("BAD_MULTIBASE");
    }
  });

  it("rejects a well-formed multibase string with the wrong multicodec prefix", () => {
    // Tag 32 arbitrary bytes with a multicodec prefix that is NOT 0xed 0x01
    // (0x00 0x01 is not a registered key type here) so the bytes are
    // otherwise indistinguishable from a valid Ed25519 did:key.
    const wrongCodec = new Uint8Array(34);
    wrongCodec[0] = 0x00;
    wrongCodec[1] = 0x01;
    const did = `did:key:${base58btc.encode(wrongCodec)}`;
    try {
      decodeDidKey(did);
      expect.unreachable("expected decodeDidKey to throw");
    } catch (err) {
      expect(err).toBeInstanceOf(MalformedDidError);
      expect((err as MalformedDidError).reason).toBe("BAD_MULTICODEC");
    }
  });

  it("rejects the right multicodec with the wrong key length", () => {
    // Correct 0xed 0x01 prefix, but only 10 key bytes instead of 32.
    const tooShort = new Uint8Array(12);
    tooShort[0] = 0xed;
    tooShort[1] = 0x01;
    const did = `did:key:${base58btc.encode(tooShort)}`;
    try {
      decodeDidKey(did);
      expect.unreachable("expected decodeDidKey to throw");
    } catch (err) {
      expect(err).toBeInstanceOf(MalformedDidError);
      expect((err as MalformedDidError).reason).toBe("BAD_KEY_LENGTH");
    }
  });

  it("rejects encoding a public key of the wrong length", () => {
    expect(() => encodeDidKey(new Uint8Array(16))).toThrow(RangeError);
  });
});
