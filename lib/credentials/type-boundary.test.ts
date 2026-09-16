/**
 * Compile-time proof of ADR 0002: a verified `HistoryAttestation` cannot
 * satisfy anywhere a verified `AuthorityCredential` is required, and vice
 * versa. `npm run typecheck` is the actual assertion here — every
 * `@ts-expect-error` below must genuinely fail to compile, or `tsc`
 * itself reports "Unused '@ts-expect-error' directive" and the gate
 * fails. That means if ADR 0002's type split is ever accidentally
 * loosened (e.g. `type` widened from a literal tuple to `string[]`),
 * THIS FILE is what turns that regression into a `npm run typecheck`
 * failure instead of a silent hole.
 *
 * The functions below are never called at module scope — only declared
 * and referenced with `void`, so nothing in this file has a runtime
 * side effect. Vitest (via esbuild) strips types without checking them,
 * so this file also runs as an ordinary (trivially passing) test; the
 * type-level claim is enforced by `tsc`, not by vitest.
 */
import { describe, expect, it } from "vitest";
import type { VerificationSuccess } from "./verification-result.js";
import type { AuthorityCredential, HistoryAttestation } from "./vc-types.js";

function requiresAuthority(verified: VerificationSuccess<AuthorityCredential>): void {
  void verified;
}

function requiresHistory(verified: VerificationSuccess<HistoryAttestation>): void {
  void verified;
}

function proof_historyCannotSatisfyAuthority(history: VerificationSuccess<HistoryAttestation>): void {
  // @ts-expect-error — a verified HistoryAttestation is not assignable to
  // a verified AuthorityCredential: history answers "should I?", never
  // "may you?". If this line stops erroring, ADR 0002's type split has
  // been weakened and `npm run typecheck` must fail here to say so.
  requiresAuthority(history);
}

function proof_authorityCannotSatisfyHistory(authority: VerificationSuccess<AuthorityCredential>): void {
  // @ts-expect-error — the same separation holds in the other
  // direction: an authority grant is not itself an observed history.
  requiresHistory(authority);
}

void proof_historyCannotSatisfyAuthority;
void proof_authorityCannotSatisfyHistory;

describe("type-level: authority and history verification results are mutually exclusive", () => {
  it("is proven by the @ts-expect-error directives above compiling (i.e. `npm run typecheck` passing)", () => {
    // Nothing to execute at runtime — the assertion IS the typecheck.
    // This trivial check just keeps the file from being an empty test
    // suite (vitest fails a file with zero assertions run).
    expect(typeof requiresAuthority).toBe("function");
    expect(typeof requiresHistory).toBe("function");
  });
});
