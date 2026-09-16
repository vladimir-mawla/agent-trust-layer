import { describe, expect, it } from "vitest";
import { bytesToHex } from "@noble/hashes/utils.js";
import { decodeDidKey, encodeDidKey } from "./did-key.js";

/**
 * Cross-check against a real external Ed25519 did:key test vector.
 *
 * Provenance: the DID string below is quoted verbatim from the "Ed25519
 * with X25519" example in the official did:key method specification
 * (w3c-ccg/did-method-key, index.html — mirrored at
 * https://w3c-ccg.github.io/did-method-key/), confirmed by fetching the
 * spec source directly rather than trusting a secondhand summary.
 *
 * The spec's HTML shows the DID and its DID Document but does not print
 * the raw public-key bytes inline, so the expected hex below was derived
 * INDEPENDENTLY using a from-scratch base58btc decoder (implemented using
 * only bigint arithmetic and the base58 alphabet, with NO dependency on
 * multiformats or any library) to ensure this constant does not route
 * through the same base58 decoder as the function under test. Both sides
 * of the assertion MUST use different implementations, or a broken decoder
 * would pass the test silently. Derivation: base58btc.decode("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
 * produces 34 bytes = 2-byte ED25519_MULTICODEC_PREFIX (0xed 0x01) + 32-byte
 * Ed25519 public key. Strip the prefix and you have the constant below.
 */
const SPEC_DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

/**
 * Expected 32-byte Ed25519 public key, independently derived from the spec
 * DID using a from-scratch base58 decoder with bigint arithmetic (not
 * multiformats). The entire point of this constant is that it was computed
 * a different way, so a broken decoder in the library under test cannot
 * silently pass.
 */
const SPEC_PUBLIC_KEY_HEX = "2e6fcce36701dc791488e0d0b1745cc1e33a4c1c9fcc41c63bd343dbbe0970e6";

describe("W3C did:key spec Ed25519 vector", () => {
  it("decodes the spec's example DID to the expected 32-byte public key", () => {
    const publicKey = decodeDidKey(SPEC_DID);
    expect(publicKey).toHaveLength(32);
    expect(bytesToHex(publicKey)).toBe(SPEC_PUBLIC_KEY_HEX);
  });

  it("re-encodes that same public key back to the exact spec DID", () => {
    const publicKey = decodeDidKey(SPEC_DID);
    expect(encodeDidKey(publicKey)).toBe(SPEC_DID);
  });
});
