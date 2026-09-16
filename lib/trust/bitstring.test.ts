import { describe, expect, it } from "vitest";
import { createEmptyEncodedList, decodeEncodedList, getStatusBit, withBitSet } from "./bitstring.js";
import { BitstringIndexError, StatusListMalformedError } from "./errors.js";

describe("bitstring encode/decode round trip", () => {
  it("an empty list decodes back to all-zero bytes of the requested size", () => {
    const encoded = createEmptyEncodedList(64);
    const bytes = decodeEncodedList(encoded);
    expect(bytes.length).toBe(8);
    expect([...bytes]).toEqual(new Array(8).fill(0));
  });

  it("starts with the multibase base64url 'u' prefix", () => {
    const encoded = createEmptyEncodedList(64);
    expect(encoded[0]).toBe("u");
  });

  it("rejects a sizeBits that is not a positive multiple of 8", () => {
    expect(() => createEmptyEncodedList(0)).toThrow(RangeError);
    expect(() => createEmptyEncodedList(-8)).toThrow(RangeError);
    expect(() => createEmptyEncodedList(10)).toThrow(RangeError);
  });
});

describe("bit ordering: index 0 is the left-most (most-significant) bit", () => {
  it("setting bit 0 sets the high bit of byte 0, not the low bit", () => {
    const encoded = withBitSet(createEmptyEncodedList(64), 0);
    const bytes = decodeEncodedList(encoded);
    expect(bytes[0]).toBe(0b1000_0000);
  });

  it("setting bit 7 sets the low bit of byte 0", () => {
    const encoded = withBitSet(createEmptyEncodedList(64), 7);
    const bytes = decodeEncodedList(encoded);
    expect(bytes[0]).toBe(0b0000_0001);
  });

  it("setting bit 8 sets the high bit of byte 1, leaving byte 0 untouched", () => {
    const encoded = withBitSet(createEmptyEncodedList(64), 8);
    const bytes = decodeEncodedList(encoded);
    expect(bytes[0]).toBe(0);
    expect(bytes[1]).toBe(0b1000_0000);
  });

  it("getStatusBit reads back exactly the bit that was set, and no neighbor", () => {
    const encoded = withBitSet(createEmptyEncodedList(64), 13);
    const bytes = decodeEncodedList(encoded);
    for (let i = 0; i < 64; i += 1) {
      expect(getStatusBit(bytes, i)).toBe(i === 13);
    }
  });
});

describe("getStatusBit fails closed with typed errors, never an unhandled throw", () => {
  const bytes = decodeEncodedList(createEmptyEncodedList(64));

  it("rejects a negative index", () => {
    expect(() => getStatusBit(bytes, -1)).toThrow(BitstringIndexError);
  });

  it("rejects a non-integer index", () => {
    expect(() => getStatusBit(bytes, 1.5)).toThrow(BitstringIndexError);
  });

  it("rejects an index at the bitstring's length (one past the last valid index)", () => {
    expect(() => getStatusBit(bytes, 64)).toThrow(BitstringIndexError);
  });

  it("accepts the last valid index without throwing", () => {
    expect(() => getStatusBit(bytes, 63)).not.toThrow();
  });

  it("rejects a wildly out-of-range index", () => {
    expect(() => getStatusBit(bytes, 1_000_000)).toThrow(BitstringIndexError);
  });
});

describe("decodeEncodedList fails closed on garbage input, never an unhandled throw", () => {
  it("rejects a string missing the multibase prefix", () => {
    expect(() => decodeEncodedList("not-multibase-prefixed")).toThrow(StatusListMalformedError);
  });

  it("rejects an empty string", () => {
    expect(() => decodeEncodedList("")).toThrow(StatusListMalformedError);
  });

  it("rejects invalid base64url after the multibase prefix", () => {
    expect(() => decodeEncodedList("u***not-base64url***")).toThrow(StatusListMalformedError);
  });

  it("rejects valid base64url that isn't valid GZIP data", () => {
    // "uAAAA" decodes as valid base64url bytes that are not a GZIP stream.
    expect(() => decodeEncodedList("uAAAA")).toThrow(StatusListMalformedError);
  });
});
