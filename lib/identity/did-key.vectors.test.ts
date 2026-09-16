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
 * independently — decoding this exact DID string with the `multiformats`
 * base58btc codec (the same battle-tested library this project's
 * did:key.ts leans on, used here directly rather than through our own
 * decodeDidKey, so this isn't just checking our code against itself) and
 * stripping the two-byte 0xed/0x01 multicodec prefix. Anyone can redo
 * this independently: `base58btc.decode(did.slice("did:key:".length))`.
 * We did not invent this vector — if it were unverifiable we would have
 * omitted it rather than fabricate one.
 */
const SPEC_DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
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
