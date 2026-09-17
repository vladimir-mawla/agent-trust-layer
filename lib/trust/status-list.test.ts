import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { encodeDidKey, generateKeyPair, type Did } from "../identity/index.js";
import { VC_CONTEXT_V2, encodeBase64Url, verificationMethodId } from "../credentials/index.js";
import {
  checkRevocation,
  DEFAULT_MAX_STATUS_LIST_AGE_MS,
  issueStatusListCredential,
  type StatusListResolver,
} from "./status-list.js";
import { signCompact } from "./jws-lite.js";
import { createEmptyEncodedList } from "./bitstring.js";

interface Identity {
  readonly publicKey: Uint8Array;
  readonly privateKey: Uint8Array;
  readonly did: Did;
}

function makeIdentity(): Identity {
  const { publicKey, privateKey } = generateKeyPair();
  return { publicKey, privateKey, did: encodeDidKey(publicKey) };
}

/**
 * Forge a compact JWS that is REAL by every check `parseCompactJws` and
 * a signature check perform — a well-formed header naming `signer`'s own
 * `kid`, valid base64url throughout, and a genuine Ed25519 signature by
 * `signer`'s own private key over the exact bytes transmitted — except
 * the payload segment decodes to bytes that are not valid JSON at all.
 * This is M3's finding-0 bug class (a validly-signed non-JSON payload
 * must fail closed, never throw unhandled), reproduced here for
 * `lib/trust`'s own JWS-lite layer. Mirrors
 * `lib/credentials/verify.test.ts`'s identically-named helper.
 */
function forgeValidSignatureOverNonJsonPayload(signer: Identity, rawPayloadText: string): string {
  const headerB64 = encodeBase64Url(utf8ToBytes(JSON.stringify({ alg: "EdDSA", kid: verificationMethodId(signer.did), typ: "vc+jwt" })));
  const payloadB64 = encodeBase64Url(utf8ToBytes(rawPayloadText));
  const signingInput = utf8ToBytes(`${headerB64}.${payloadB64}`);
  const signatureB64 = encodeBase64Url(ed25519.sign(signingInput, signer.privateKey));
  return `${headerB64}.${payloadB64}.${signatureB64}`;
}

const STATUS_LIST_URL = "https://issuer.example/status/3";

function resolverFor(jwt: string): StatusListResolver {
  return async (url: string) => {
    if (url !== STATUS_LIST_URL) throw new Error(`unexpected url ${url}`);
    return jwt;
  };
}

describe("checkRevocation — happy path", () => {
  it("reports 'active' for an index whose bit is not set", async () => {
    const issuer = makeIdentity();
    const jwt = issueStatusListCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      statusPurpose: "revocation",
      sizeBits: 128,
      now: 0,
    });

    const result = await checkRevocation(
      { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: 5, statusListCredential: STATUS_LIST_URL },
      resolverFor(jwt),
      issuer.did,
      { now: 0 },
    );

    expect(result.outcome).toBe("active");
  });
});

describe("revoked credential -> refused", () => {
  it("reports 'revoked' when the credential's bit is set", async () => {
    const issuer = makeIdentity();
    const jwt = issueStatusListCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      statusPurpose: "revocation",
      sizeBits: 128,
      revokedIndices: [5],
      now: 0,
    });

    const result = await checkRevocation(
      { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: 5, statusListCredential: STATUS_LIST_URL },
      resolverFor(jwt),
      issuer.did,
      { now: 0 },
    );

    expect(result.outcome).toBe("revoked");
  });
});

describe("valid credential, index NOT set in the bitstring -> accepted", () => {
  it("reports 'active' when a DIFFERENT index (not this credential's) is revoked", async () => {
    const issuer = makeIdentity();
    const jwt = issueStatusListCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      statusPurpose: "revocation",
      sizeBits: 128,
      revokedIndices: [99],
      now: 0,
    });

    const result = await checkRevocation(
      { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: 5, statusListCredential: STATUS_LIST_URL },
      resolverFor(jwt),
      issuer.did,
      { now: 0 },
    );

    expect(result.outcome).toBe("active");
  });
});

describe("status list with a broken signature -> refused (fail closed)", () => {
  it("reports 'indeterminate' when signed by a different key than its claimed issuer", async () => {
    const issuer = makeIdentity();
    const mallory = makeIdentity();
    const payload = {
      "@context": [VC_CONTEXT_V2],
      type: ["VerifiableCredential", "BitstringStatusListCredential"],
      issuer: issuer.did,
      iss: issuer.did,
      validFrom: new Date(0).toISOString(),
      credentialSubject: {
        type: "BitstringStatusList",
        statusPurpose: "revocation",
        encodedList: "uH4sIAAAAAAAA_2NgAAIAAAD__wMAAAAAAAAAAAA",
      },
    };
    const forged = signCompact(payload, verificationMethodId(issuer.did), mallory.privateKey);

    const result = await checkRevocation(
      { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: 0, statusListCredential: STATUS_LIST_URL },
      resolverFor(forged),
      issuer.did,
      { now: 0 },
    );

    expect(result.outcome).toBe("indeterminate");
    if (result.outcome !== "indeterminate") throw new Error("expected indeterminate");
    expect(result.cause.kind).toBe("status-list-signature-invalid");
  });
});

describe("status list too stale -> refused; exact boundary tested", () => {
  it("is fresh exactly at the threshold (not stale)", async () => {
    const issuer = makeIdentity();
    const jwt = issueStatusListCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      statusPurpose: "revocation",
      sizeBits: 128,
      validFrom: new Date(0).toISOString(),
      now: 0,
    });

    const result = await checkRevocation(
      { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: 0, statusListCredential: STATUS_LIST_URL },
      resolverFor(jwt),
      issuer.did,
      { now: DEFAULT_MAX_STATUS_LIST_AGE_MS, maxStatusListAgeMs: DEFAULT_MAX_STATUS_LIST_AGE_MS },
    );

    expect(result.outcome).toBe("active");
  });

  it("is stale one millisecond past the threshold", async () => {
    const issuer = makeIdentity();
    const jwt = issueStatusListCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      statusPurpose: "revocation",
      sizeBits: 128,
      validFrom: new Date(0).toISOString(),
      now: 0,
    });

    const result = await checkRevocation(
      { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: 0, statusListCredential: STATUS_LIST_URL },
      resolverFor(jwt),
      issuer.did,
      { now: DEFAULT_MAX_STATUS_LIST_AGE_MS + 1, maxStatusListAgeMs: DEFAULT_MAX_STATUS_LIST_AGE_MS },
    );

    expect(result.outcome).toBe("indeterminate");
    if (result.outcome !== "indeterminate") throw new Error("expected indeterminate");
    expect(result.cause.kind).toBe("status-list-stale");
  });
});

describe("status list unavailable / resolver throws -> refused, no unhandled throw", () => {
  it("reports 'indeterminate' when the resolver rejects", async () => {
    const issuer = makeIdentity();
    const failing: StatusListResolver = async () => {
      throw new Error("network is down");
    };

    const result = await checkRevocation(
      { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: 0, statusListCredential: STATUS_LIST_URL },
      failing,
      issuer.did,
      { now: 0 },
    );

    expect(result.outcome).toBe("indeterminate");
    if (result.outcome !== "indeterminate") throw new Error("expected indeterminate");
    expect(result.cause.kind).toBe("status-list-unavailable");
  });
});

describe("statusPurpose mismatch", () => {
  it("refuses when the entry's statusPurpose isn't declared by the resolved list", async () => {
    const issuer = makeIdentity();
    const jwt = issueStatusListCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      statusPurpose: "suspension",
      sizeBits: 128,
      now: 0,
    });

    const result = await checkRevocation(
      { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: 0, statusListCredential: STATUS_LIST_URL },
      resolverFor(jwt),
      issuer.did,
      { now: 0 },
    );

    expect(result.outcome).toBe("indeterminate");
    if (result.outcome !== "indeterminate") throw new Error("expected indeterminate");
    expect(result.cause.kind).toBe("status-list-purpose-mismatch");
  });
});

describe("bitstring index out of range, negative, non-integer -> typed error, never unhandled", () => {
  it("refuses a negative statusListIndex", async () => {
    const issuer = makeIdentity();
    const jwt = issueStatusListCredential({ issuerPrivateKey: issuer.privateKey, issuerDid: issuer.did, statusPurpose: "revocation", sizeBits: 128, now: 0 });
    const result = await checkRevocation(
      { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: -1, statusListCredential: STATUS_LIST_URL },
      resolverFor(jwt),
      issuer.did,
      { now: 0 },
    );
    expect(result.outcome).toBe("indeterminate");
    if (result.outcome !== "indeterminate") throw new Error("expected indeterminate");
    expect(result.cause.kind).toBe("bitstring-index-invalid");
  });

  it("refuses a non-integer statusListIndex", async () => {
    const issuer = makeIdentity();
    const jwt = issueStatusListCredential({ issuerPrivateKey: issuer.privateKey, issuerDid: issuer.did, statusPurpose: "revocation", sizeBits: 128, now: 0 });
    const result = await checkRevocation(
      { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: 1.5, statusListCredential: STATUS_LIST_URL },
      resolverFor(jwt),
      issuer.did,
      { now: 0 },
    );
    expect(result.outcome).toBe("indeterminate");
    if (result.outcome !== "indeterminate") throw new Error("expected indeterminate");
    expect(result.cause.kind).toBe("bitstring-index-invalid");
  });

  it("refuses an out-of-range statusListIndex (beyond the bitstring's length)", async () => {
    const issuer = makeIdentity();
    const jwt = issueStatusListCredential({ issuerPrivateKey: issuer.privateKey, issuerDid: issuer.did, statusPurpose: "revocation", sizeBits: 128, now: 0 });
    const result = await checkRevocation(
      { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: 1_000_000, statusListCredential: STATUS_LIST_URL },
      resolverFor(jwt),
      issuer.did,
      { now: 0 },
    );
    expect(result.outcome).toBe("indeterminate");
    if (result.outcome !== "indeterminate") throw new Error("expected indeterminate");
    expect(result.cause.kind).toBe("bitstring-index-invalid");
  });
});

describe("malformed/garbage status list VC -> typed error, never unhandled", () => {
  it("refuses a resolver result that isn't a JWS at all", async () => {
    const issuer = makeIdentity();
    const result = await checkRevocation(
      { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: 0, statusListCredential: STATUS_LIST_URL },
      async () => "complete garbage, not a JWS",
      issuer.did,
      { now: 0 },
    );
    expect(result.outcome).toBe("indeterminate");
    if (result.outcome !== "indeterminate") throw new Error("expected indeterminate");
    expect(result.cause.kind).toBe("status-list-malformed");
  });

  it("fails closed, never throws, for a REAL signature over a non-JSON payload (M3 finding-0 bug class)", async () => {
    const issuer = makeIdentity();
    const forged = forgeValidSignatureOverNonJsonPayload(issuer, "not json at all");

    const result = await checkRevocation(
      { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: 0, statusListCredential: STATUS_LIST_URL },
      resolverFor(forged),
      issuer.did,
      { now: 0 },
    );

    expect(result.outcome).toBe("indeterminate");
    if (result.outcome !== "indeterminate") throw new Error("expected indeterminate");
    expect(result.cause.kind).toBe("status-list-malformed");
    expect(result.cause.message).toMatch(/not valid JSON/);
  });

  it("refuses a well-signed JWS whose payload isn't a BitstringStatusListCredential", async () => {
    const issuer = makeIdentity();
    const payload = { hello: "world" };
    const jwt = signCompact(payload, verificationMethodId(issuer.did), issuer.privateKey);

    const result = await checkRevocation(
      { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: 0, statusListCredential: STATUS_LIST_URL },
      resolverFor(jwt),
      issuer.did,
      { now: 0 },
    );
    expect(result.outcome).toBe("indeterminate");
    if (result.outcome !== "indeterminate") throw new Error("expected indeterminate");
    expect(result.cause.kind).toBe("status-list-malformed");
  });

  it("refuses a status list with an unresolvable issuer", async () => {
    const issuer = makeIdentity();
    const payload = {
      "@context": [VC_CONTEXT_V2],
      type: ["VerifiableCredential", "BitstringStatusListCredential"],
      issuer: "did:key:zNOTVALID",
      iss: "did:key:zNOTVALID",
      validFrom: new Date(0).toISOString(),
      credentialSubject: { type: "BitstringStatusList", statusPurpose: "revocation", encodedList: "uAAAA" },
    };
    const jwt = signCompact(payload, "did:key:zNOTVALID#did:key:zNOTVALID", issuer.privateKey);

    const result = await checkRevocation(
      { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: 0, statusListCredential: STATUS_LIST_URL },
      resolverFor(jwt),
      issuer.did,
      { now: 0 },
    );
    expect(result.outcome).toBe("indeterminate");
    if (result.outcome !== "indeterminate") throw new Error("expected indeterminate");
    expect(["status-list-issuer-unresolvable", "status-list-malformed"]).toContain(result.cause.kind);
  });

  it("refuses a resolver result that isn't even a string", async () => {
    const issuer = makeIdentity();
    const result = await checkRevocation(
      { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: 0, statusListCredential: STATUS_LIST_URL },
      // @ts-expect-error deliberately violating StatusListResolver's contract to prove fail-closed handling
      async () => ({ not: "a string" }),
      issuer.did,
      { now: 0 },
    );
    expect(result.outcome).toBe("indeterminate");
  });
});

describe("issuer-identity mismatch on the status list credential itself", () => {
  it("refuses when the credential claims a different issuer than the key that signed it", async () => {
    const acme = makeIdentity();
    const mallory = makeIdentity();
    const payload = {
      "@context": [VC_CONTEXT_V2],
      type: ["VerifiableCredential", "BitstringStatusListCredential"],
      issuer: acme.did,
      iss: acme.did,
      validFrom: new Date(0).toISOString(),
      credentialSubject: { type: "BitstringStatusList", statusPurpose: "revocation", encodedList: createEmptyEncodedList(128) },
    };
    // kid names Acme (so decodeDidKey succeeds and signature verifies),
    // but the ACTUAL signing key is Mallory's -- verifyCompactAndDecode
    // will fail because the signature won't verify against Acme's key.
    const forged = signCompact(payload, verificationMethodId(acme.did), mallory.privateKey);

    const result = await checkRevocation(
      { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: 0, statusListCredential: STATUS_LIST_URL },
      resolverFor(forged),
      acme.did,
      { now: 0 },
    );
    expect(result.outcome).toBe("indeterminate");
    if (result.outcome !== "indeterminate") throw new Error("expected indeterminate");
    expect(result.cause.kind).toBe("status-list-signature-invalid");
  });
});

// ---------------------------------------------------------------------
// FINDING 1 (CRITICAL) regression — L4 VERIFY rejected M4 because
// `checkRevocation` checked only that the resolved status list was
// INTERNALLY self-consistent (its own `issuer` claim matched whoever
// actually signed it), never that it was issued by the credential's own
// real issuer, or by any expected identity at all. That meant a resolver
// which returned a "clean" status list signed by ANY throwaway keypair —
// no compromise of the real issuer's key required — got the credential
// accepted even when the REAL issuer had genuinely revoked it. Fixed by
// making `expectedIssuer` a required parameter to `checkRevocation` and
// refusing any resolved list whose issuer doesn't match it.
// ---------------------------------------------------------------------
describe("FINDING 1 — status list issuer must match the credential's own issuer (bypass regression)", () => {
  const ENTRY = { type: "BitstringStatusListEntry" as const, statusPurpose: "revocation", statusListIndex: 3, statusListCredential: STATUS_LIST_URL };

  it("sanity: the REAL issuer's genuinely-revoking status list is correctly refused", async () => {
    const realIssuer = makeIdentity();
    const revokedListJwt = issueStatusListCredential({
      issuerPrivateKey: realIssuer.privateKey,
      issuerDid: realIssuer.did,
      statusPurpose: "revocation",
      sizeBits: 128,
      revokedIndices: [3],
      now: 0,
    });

    const result = await checkRevocation(ENTRY, resolverFor(revokedListJwt), realIssuer.did, { now: 0 });

    expect(result.outcome).toBe("revoked");
  });

  it("REFUSES an unrelated throwaway-keypair-signed 'clean' list swapped in for the same URL, naming the issuer mismatch", async () => {
    const realIssuer = makeIdentity();
    // A completely unrelated, attacker-controlled keypair -- not a
    // compromise of realIssuer's key, just some other identity that can
    // sign its own perfectly well-formed, perfectly self-consistent
    // status list credential.
    const throwaway = makeIdentity();

    const cleanListFromThrowaway = issueStatusListCredential({
      issuerPrivateKey: throwaway.privateKey,
      issuerDid: throwaway.did,
      statusPurpose: "revocation",
      sizeBits: 128,
      // deliberately no revokedIndices -- index 3 reads as unset/"clean"
      now: 0,
    });

    // Same credentialStatus entry (same URL, same index) as the sanity
    // check above -- only the RESOLVER's answer differs, exactly modeling
    // a semi-trusted status-list host returning a different list than the
    // real issuer published (ADR 0003's own threat model names the host
    // as only semi-trusted).
    const result = await checkRevocation(ENTRY, resolverFor(cleanListFromThrowaway), realIssuer.did, { now: 0 });

    expect(result.outcome).toBe("indeterminate");
    if (result.outcome !== "indeterminate") throw new Error("expected indeterminate");
    expect(result.cause.kind).toBe("status-list-issuer-mismatch");
    expect(result.reason).toContain(realIssuer.did);
    expect(result.reason).toContain(throwaway.did);
  });
});

// ---------------------------------------------------------------------
// FINDING 2 (MEDIUM) regression — checkRevocation had no timeout around
// the injected resolver, so a resolver that never settles hung the whole
// trust decision indefinitely (fail-closed logic never ran, because
// nothing ever settled). Fixed with a caller-overridable
// `resolverTimeoutMs`, defaulting to `DEFAULT_RESOLVER_TIMEOUT_MS`,
// treating expiry as `indeterminate`.
// ---------------------------------------------------------------------
describe("FINDING 2 — a hanging resolver must not hang checkRevocation forever", () => {
  it("times out and refuses (fail closed) when the resolver never settles", async () => {
    const issuer = makeIdentity();
    const hangingResolver: StatusListResolver = () => new Promise<string>(() => {}); // never resolves or rejects

    const result = await checkRevocation(
      { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: 0, statusListCredential: STATUS_LIST_URL },
      hangingResolver,
      issuer.did,
      { now: 0, resolverTimeoutMs: 25 },
    );

    expect(result.outcome).toBe("indeterminate");
    if (result.outcome !== "indeterminate") throw new Error("expected indeterminate");
    expect(result.cause.kind).toBe("status-list-resolver-timeout");
  });

  it("still succeeds for a slow-but-successful resolver that settles inside the timeout window", async () => {
    const issuer = makeIdentity();
    const jwt = issueStatusListCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      statusPurpose: "revocation",
      sizeBits: 128,
      now: 0,
    });
    const slowButSuccessful: StatusListResolver = () => new Promise<string>((resolve) => setTimeout(() => resolve(jwt), 10));

    const result = await checkRevocation(
      { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: 0, statusListCredential: STATUS_LIST_URL },
      slowButSuccessful,
      issuer.did,
      { now: 0, resolverTimeoutMs: 200 },
    );

    expect(result.outcome).toBe("active");
  });
});
