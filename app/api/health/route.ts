/**
 * `/api/health` — proves two independent things on every request:
 *
 *   1. This process is the commit it claims to be (`commit`).
 *   2. M1's identity primitive (keygen -> did:key encode/decode ->
 *      challenge-response proof of possession) still works IN THIS
 *      DEPLOYED ENVIRONMENT, not just on a developer's machine. That is
 *      the whole point of running the round-trip here instead of just
 *      linking to M1's test suite: `npm test` proves the code is correct
 *      once, locally; this endpoint proves it still works every time
 *      someone (or Vercel's own health checks) hits the deployed URL.
 *
 * Fail-closed: if the identity round-trip throws for any reason, this
 * returns HTTP 503, never 200. A health endpoint that reports healthy
 * while its core cryptographic primitive is broken is worse than no
 * health endpoint — it would hide exactly the failure it exists to catch.
 *
 * Runs on the Node.js runtime (not Edge) because @noble/curves and
 * multiformats are not guaranteed Edge-compatible, and is forced dynamic
 * so Vercel never serves a stale prerendered response — a cached "ok"
 * would defeat the entire purpose of checking anything.
 */
import { NextResponse } from "next/server";
import { execSync } from "node:child_process";
// Kept ".js"-suffixed, matching lib/'s own internal NodeNext-style
// imports, because webpack's `resolve.extensionAlias` (configured in
// next.config.ts) resolves it to index.ts — see that file for why
// Turbopack needed this app forced onto `--webpack` in the first place.
import {
  generateKeyPair,
  encodeDidKey,
  decodeDidKey,
  createChallenge,
  provePossession,
  verifyPossession,
} from "../../../lib/identity/index.js";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type IdentityCheck = { readonly pass: true; readonly elapsedMs: number } | { readonly pass: false; readonly error: string };

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

/**
 * The real round-trip: generate a keypair, encode/decode its did:key,
 * assert the bytes survive that trip, then run a full challenge-response
 * proof of possession and assert it recovers the same public key.
 *
 * Deliberately returns only pass/fail + timing — never the generated
 * private key, public key, or DID — so a health check response can never
 * leak key material (see the repo's key-hygiene gate).
 */
function runIdentityRoundTrip(): { elapsedMs: number } {
  const start = performance.now();

  const keyPair = generateKeyPair();
  const did = encodeDidKey(keyPair.publicKey);
  const decodedPublicKey = decodeDidKey(did);
  if (!bytesEqual(decodedPublicKey, keyPair.publicKey)) {
    throw new Error("did:key round-trip decoded a different public key than it encoded");
  }

  const challenge = createChallenge();
  const proof = provePossession(keyPair.privateKey, did, challenge);
  const verifiedPublicKey = verifyPossession(proof);
  if (!bytesEqual(verifiedPublicKey, keyPair.publicKey)) {
    throw new Error("challenge verification recovered a different public key than the signer's");
  }

  return { elapsedMs: performance.now() - start };
}

function checkIdentity(): IdentityCheck {
  try {
    const { elapsedMs } = runIdentityRoundTrip();
    return { pass: true, elapsedMs };
  } catch (error) {
    return { pass: false, error: error instanceof Error ? error.message : String(error) };
  }
}

/**
 * The deployed commit. Vercel sets `VERCEL_GIT_COMMIT_SHA` for every
 * build; falling back to the local git HEAD (and then "unknown") makes
 * `npm run dev` and any non-Vercel environment return something useful
 * instead of crashing when that variable is absent.
 */
function resolveCommit(): string {
  const fromVercel = process.env.VERCEL_GIT_COMMIT_SHA;
  if (fromVercel) {
    return fromVercel;
  }
  try {
    return execSync("git rev-parse HEAD", { stdio: ["ignore", "pipe", "ignore"] })
      .toString()
      .trim();
  } catch {
    return "unknown";
  }
}

export function GET(): NextResponse {
  const commit = resolveCommit();
  const identity = checkIdentity();

  const body = {
    status: identity.pass ? "ok" : "unhealthy",
    commit,
    checks: { identity },
  };

  return NextResponse.json(body, { status: identity.pass ? 200 : 503 });
}
