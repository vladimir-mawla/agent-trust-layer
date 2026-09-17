import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { encodeBase64Url } from "../credentials/index.js";
import { MAX_DECOMPRESSED_BITSTRING_BYTES, createEmptyEncodedList, decodeEncodedList, encodeList, getStatusBit, withBitSet } from "./bitstring.js";
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

// ---------------------------------------------------------------------
// FINDING 3 (LOW-MEDIUM) — `decodeEncodedList` must bound how much a
// single `encodedList` is allowed to decompress to, explicitly (via
// `gunzipSync`'s own `maxOutputLength`), not merely by accident of
// `MAX_JWS_LENGTH` bounding the compressed input. A highly compressible
// payload (e.g. all-zero bytes, exactly what a real bitstring mostly
// looks like) can decompress to something far larger than what it took
// to compress — this proves the explicit cap actually refuses that,
// fails closed with the existing typed error, and never lets an
// oversized allocation complete.
// ---------------------------------------------------------------------
describe("decodeEncodedList enforces MAX_DECOMPRESSED_BITSTRING_BYTES (FINDING 3)", () => {
  it("refuses (fails closed, never throws a native error) a GZIP payload that would decompress well beyond the cap", () => {
    // All-zero bytes are maximally compressible: a few-KB compressed
    // stream can still expand to many times MAX_DECOMPRESSED_BITSTRING_BYTES
    // if nothing bounds the output. Comfortably over the cap (2x) so this
    // assertion isn't sensitive to an off-by-one at the exact boundary.
    const oversized = new Uint8Array(MAX_DECOMPRESSED_BITSTRING_BYTES * 2);
    const compressed = gzipSync(oversized);
    const encodedList = `u${encodeBase64Url(compressed)}`;

    expect(() => decodeEncodedList(encodedList)).toThrow(StatusListMalformedError);
  });

  it("still accepts a large, legitimate bitstring comfortably under the cap", () => {
    // A one-megabyte bitstring (8x the spec's 16KB privacy floor) is well
    // within MAX_DECOMPRESSED_BITSTRING_BYTES (8MB) and must decode fine —
    // proving the cap doesn't quietly reject realistic large deployments.
    const oneMegabyte = new Uint8Array(1024 * 1024);
    const encodedList = encodeList(oneMegabyte);

    const decoded = decodeEncodedList(encodedList);
    expect(decoded.length).toBe(oneMegabyte.length);
  });
});
