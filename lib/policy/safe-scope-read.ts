/**
 * Defensive, hostile-input-safe reads of `PolicyRequest.scope` fields —
 * the ROOT-LAYER half of the FIX for the L4 M6 review's REJECTING
 * finding ("a throwing getter must never escape as a rejection").
 *
 * ## Why this exists
 *
 * `evaluatePolicyRequest`'s `request.scope` is `Readonly<Record<string,
 * unknown>>` — a TYPE, not a guarantee. `request` is never run through
 * `validatePolicy` (only `policy` is); it is exactly the kind of value
 * ADR 0004 itself already warns about for `policy` ("claims arrive as
 * JSON, not TypeScript"), except here the untrusted party controls it
 * directly and there is no JSON.parse step in between to make a getter
 * impossible. Before this fix, `engine.ts` read `request.scope[field]`
 * (and separately probed `Object.prototype.hasOwnProperty.call(
 * request.scope, field)`) as plain, trusted property access. A hostile
 * `scope` whose `field` is an accessor that throws — an own
 * `Object.defineProperty`-installed getter, one inherited via the
 * prototype chain (a property READ still invokes an inherited
 * accessor), or a `Proxy` whose `get`/`getOwnPropertyDescriptor` traps
 * throw — made that read itself throw, propagating out of
 * `evaluatePolicyRequest` as an uncaught exception and, through
 * `Supplier.evaluatePresentation` (`lib/negotiation/supplier.ts`), out
 * as an unhandled PROMISE REJECTION instead of the structured
 * `PolicyDecision` this engine's whole contract promises. This is the
 * exact same defect class ("a caller can turn 'never-quite-verified
 * input' into an unhandled exception instead of a structured refusal")
 * that got M3 rejected once already, and — per `decision-guards.ts`'s
 * own comment — got M6 rejected too.
 *
 * ## Scope of the fix, deliberately narrow
 *
 * Every OTHER object this engine reads scope-shaped data from —
 * `envelope.scope` (built by M3's `verify.ts` from a JSON-parsed JWT
 * payload — JSON.parse cannot produce a getter, a Proxy, or a
 * throwing-`toString` value) and `matchingRule.maxScope` (rebuilt
 * field-by-field into a fresh plain object by `validate.ts`'s
 * `validateNumericRecord`) — is already safe DATA by construction. Only
 * `request.scope` crosses a real boundary from a party this project
 * does not control, so only reads FROM `request.scope` need this
 * defensive wrapper; wrapping the others too would be dead-code
 * defense against an input shape that cannot occur.
 *
 * ## Fail-closed posture
 *
 * A read that throws for ANY reason (getter, proxy trap, whatever) is
 * treated EXACTLY like the field being entirely absent — never as its
 * own distinct outcome. `engine.ts`'s existing "omitted-but-bounded
 * field -> refuse" gate (FINDING 4) already covers "absent", so a
 * throwing accessor for a bounded field refuses via that same,
 * already-tested code path, just with a note distinguishing "it threw"
 * from "it was never supplied" for a clearer explanation.
 */

/** The result of attempting to read one field off an untrusted `scope`
 *  object without letting any part of that read propagate an
 *  exception. */
export interface ScopeFieldRead {
  /** Best-effort "is this an own, enumerable-or-not-but-present key" —
   *  `false` whenever the presence check itself could not be completed
   *  safely, so a caller cannot distinguish "genuinely absent" from
   *  "the presence check threw" by relying on this alone; use
   *  `threw` for that. */
  readonly present: boolean;
  /** The value read, or `undefined` if the read never completed
   *  (absent, or threw). */
  readonly value: unknown;
  /** `true` if EITHER the presence check or the value read itself threw
   *  — i.e. `scope` (or its prototype chain, or a Proxy trap) is
   *  actively hostile for this field, as opposed to merely omitting
   *  it. */
  readonly threw: boolean;
}

/**
 * Read `scope[field]` (plus a best-effort own-property presence check)
 * without ever throwing, regardless of what `scope` is: `null`/
 * `undefined`, a plain object, an object with a throwing OWN getter for
 * `field`, an object whose PROTOTYPE has a throwing getter for `field`,
 * or a `Proxy` whose `get`/`getOwnPropertyDescriptor`/`ownKeys` traps
 * themselves throw. Every one of those resolves to a `ScopeFieldRead`
 * with `threw: true` rather than escaping as an exception.
 */
export function readScopeField(scope: unknown, field: string): ScopeFieldRead {
  let present = false;
  let presenceThrew = false;
  try {
    present = scope !== null && scope !== undefined && Object.prototype.hasOwnProperty.call(scope, field);
  } catch {
    // A Proxy whose `getOwnPropertyDescriptor`/`ownKeys` trap throws
    // makes even ASKING "do you have this key" unsafe.
    presenceThrew = true;
  }

  let value: unknown;
  let valueThrew = false;
  try {
    // A plain bracket read: this is what invokes an own OR inherited
    // getter, and what a Proxy's `get` trap intercepts. `scope` being
    // `null`/`undefined` reads as `undefined` here without throwing —
    // property access on `null`/`undefined` is the one case this `try`
    // does not need a trap for, but is included for uniformity.
    value = (scope as Record<string, unknown> | null | undefined)?.[field];
  } catch {
    valueThrew = true;
  }

  return { present: present && !presenceThrew, value: valueThrew ? undefined : value, threw: presenceThrew || valueThrew };
}
