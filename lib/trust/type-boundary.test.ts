/**
 * Compile-time proof that a `Vouch` conveys IDENTITY trust and can NEVER
 * be used to claim AUTHORITY — the rule `vouch.ts`'s module comment
 * names as "the rule that stops this becoming a reputation score".
 *
 * `npm run typecheck` is the actual assertion here, exactly like
 * `lib/credentials/type-boundary.test.ts` for ADR 0002: every
 * `@ts-expect-error` below must genuinely fail to compile, or `tsc`
 * reports "Unused '@ts-expect-error' directive" and the gate fails. If
 * `Vouch`'s subject type is ever accidentally widened to overlap with
 * `AuthorityCredentialSubject` (e.g. `vouchedCapability` loosened from
 * the literal `"identity"` to `string`, or an `action`/`scope` field
 * added), THIS FILE turns that regression into a `npm run typecheck`
 * failure instead of a silent hole reopening the "score with no
 * mechanism" the brief disqualifies.
 *
 * Nothing below runs at module scope — declared and referenced with
 * `void` only, same pattern as the M3 file this mirrors.
 */
import { describe, expect, it } from "vitest";
import type { AuthorityCredentialSubject } from "../credentials/index.js";
import type { Vouch, VouchSubject, VOUCHED_CAPABILITY_IDENTITY } from "./vouch.js";

function requiresAuthoritySubject(subject: AuthorityCredentialSubject): void {
  void subject;
}

function requiresVouchSubject(subject: VouchSubject): void {
  void subject;
}

function proof_vouchSubjectCannotSatisfyAuthoritySubject(vouch: Vouch): void {
  // @ts-expect-error — a Vouch's credentialSubject has no `action`/
  // `scope` at all, so it can never structurally satisfy
  // AuthorityCredentialSubject, which REQUIRES both. A vouch cannot be
  // mistaken for a grant of authority because there is nothing in its
  // shape an authority-consuming function could even read as scope.
  requiresAuthoritySubject(vouch.credentialSubject);
}

function proof_vouchedCapabilityCannotBeAuthority(): void {
  // @ts-expect-error — `vouchedCapability` is typed as the single
  // literal "identity", with no "authority" sibling to widen into. This
  // assignment must fail to compile; if it ever starts compiling, the
  // type has been loosened into exactly the identity/authority
  // conflation this module's whole design forbids.
  const capability: typeof VOUCHED_CAPABILITY_IDENTITY = "authority";
  void capability;
}

void proof_vouchSubjectCannotSatisfyAuthoritySubject;
void proof_vouchedCapabilityCannotBeAuthority;

describe("type-level: a Vouch can never satisfy an AuthorityCredential's subject shape", () => {
  it("is proven by the @ts-expect-error directives above compiling (i.e. `npm run typecheck` passing)", () => {
    // Nothing to execute at runtime — the assertion IS the typecheck.
    expect(typeof requiresAuthoritySubject).toBe("function");
    expect(typeof requiresVouchSubject).toBe("function");
  });
});
