import { describe, expect, it } from "vitest";
import { decodeBase64Url, encodeBase64Url } from "./base64url.js";

describe("encodeBase64Url / decodeBase64Url round trip", () => {
  it("round-trips arbitrary bytes, including all three padding-length cases", () => {
    for (const length of [0, 1, 2, 3, 4, 5, 31, 32, 64, 255]) {
      const bytes = new Uint8Array(length);
      for (let i = 0; i < length; i += 1) {
        bytes[i] = (i * 37 + 11) % 256;
      }
      expect(decodeBase64Url(encodeBase64Url(bytes))).toEqual(bytes);
    }
  });

  it("never emits padding or the standard-base64 '+'/'/' characters", () => {
    const bytes = Uint8Array.from({ length: 32 }, (_, i) => (i * 251) % 256);
    const encoded = encodeBase64Url(bytes);
    expect(encoded).not.toMatch(/[+/=]/);
  });

  it("matches a known RFC 4648 test vector", () => {
    // "any carnal pleasure." -> base64 "YW55IGNhcm5hbCBwbGVhc3VyZS4=" (no
    // '+'/'/' in this particular vector, so base64url is identical minus
    // the trailing '=' padding).
    const bytes = new TextEncoder().encode("any carnal pleasure.");
    expect(encodeBase64Url(bytes)).toBe("YW55IGNhcm5hbCBwbGVhc3VyZS4");
  });
});

describe("decodeBase64Url rejects malformed input", () => {
  it("rejects characters outside the base64url alphabet", () => {
    expect(() => decodeBase64Url("not valid! chars")).toThrow(RangeError);
    expect(() => decodeBase64Url("has+plus")).toThrow(RangeError);
    expect(() => decodeBase64Url("has/slash")).toThrow(RangeError);
  });

  it("rejects a length that leaves exactly one leftover base64 character", () => {
    // 4k+1 characters can never be a valid base64 encoding of anything.
    expect(() => decodeBase64Url("A")).toThrow(RangeError);
    expect(() => decodeBase64Url("AAAAA")).toThrow(RangeError);
  });

  it("accepts correctly padded input even though encodeBase64Url never produces it", () => {
    const bytes = new TextEncoder().encode("pad"); // 3 bytes -> 4 base64 chars, no padding needed to test with
    const bytes2 = new TextEncoder().encode("pa"); // 2 bytes -> 3 base64url chars -> needs 1 '=' when padded
    const unpadded = encodeBase64Url(bytes2);
    expect(unpadded.length % 4).toBe(3);
    const padded = `${unpadded}=`;
    expect(decodeBase64Url(padded)).toEqual(bytes2);
    expect(decodeBase64Url(encodeBase64Url(bytes))).toEqual(bytes);
  });
});
