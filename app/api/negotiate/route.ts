/**
 * `/api/negotiate` — M8's server-side negotiation endpoint.
 *
 * GET returns the fixed four-beat scenario (M6's own
 * `runFourBeatScenario`) as JSON — this is what proves, independent of
 * the rendered page, that the four beats really come from running the
 * real protocol: `curl -s localhost:3000/api/negotiate` shows the exact
 * same decisions `app/page.tsx` renders server-side.
 *
 * POST runs ONE custom negotiation for the interactive control: a
 * viewer-chosen `amount` and, optionally, an `attack` to mount (spoof
 * the buyer's DID, forge a credential, or present a revoked one). The
 * response is a real `NegotiationDecision` produced by actually running
 * `lib/negotiation`'s `Supplier.evaluatePresentation` — never a
 * lookup table keyed by amount.
 *
 * WHY THIS MUST RUN ON THE NODE.JS RUNTIME, SERVER-SIDE ONLY:
 * `lib/negotiation` composes `lib/trust`, and `lib/trust/bitstring.ts`
 * imports `node:zlib` to (de)compress the W3C Bitstring Status List used
 * for revocation — see that file's own module comment. `node:zlib` has
 * no browser implementation, so this negotiation logic cannot run in the
 * viewer's browser as written; running it here, in a Route Handler,
 * keeps the REAL verification/policy code path (identical to
 * `scripts/demo-negotiation.ts` and `lib/negotiation/scenario.test.ts`)
 * while still letting the page be interactive. `dynamic = "force-dynamic"`
 * matches `app/api/health/route.ts`'s own reasoning: fresh Ed25519 keys
 * are generated on every call (by design — see `negotiation-service.ts`),
 * so a cached response would be actively misleading.
 *
 * NO KEY MATERIAL EVER LEAVES THIS FUNCTION: every DTO returned below is
 * built field-by-field in `negotiation-service.ts` from `KeyHolder.did`
 * (a public string) and structured `NegotiationDecision`/`Explanation`
 * data — never from a `KeyHolder` instance itself, and a `KeyHolder`'s
 * `#privateKey` is a true JS private class field that cannot be read,
 * enumerated, or JSON-serialised from outside that class in the first
 * place (see `lib/negotiation/agent.ts`).
 */
import { NextResponse } from "next/server";
import { ATTACK_KINDS, getFixedFourBeats, runCustomNegotiation, type AttackKind } from "../../lib/negotiation-service.js";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(): Promise<NextResponse> {
  const scenario = await getFixedFourBeats();
  return NextResponse.json(scenario);
}

function isAttackKind(value: unknown): value is AttackKind {
  return typeof value === "string" && (ATTACK_KINDS as readonly string[]).includes(value);
}

/** A JSON object as opposed to an array, `null`, or a primitive.
 *  `typeof value === "object" && value !== null` alone is not enough:
 *  arrays are also `typeof "object"` and would otherwise slip past this
 *  guard and reach the `amount`/`attack` lookups below, which only
 *  happen to reject them indirectly (the fields they read are absent on
 *  an array, so `amount` ends up `NaN`). Reject the wrong shape here,
 *  explicitly, with the same structured error the other invalid bodies
 *  get — do not rely on that fallthrough. A key literally named
 *  `__proto__` is not special-cased and needs none: `JSON.parse` (which
 *  `request.json()` uses) always creates it as an ordinary own
 *  property, never as the object's actual prototype, so it is a plain
 *  object like any other here. */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export async function POST(request: Request): Promise<NextResponse> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "request body must be valid JSON" }, { status: 400 });
  }

  if (!isPlainObject(body)) {
    return NextResponse.json({ error: "request body must be a JSON object" }, { status: 400 });
  }

  const rawAmount = body["amount"];
  const amount = typeof rawAmount === "number" ? rawAmount : Number(rawAmount);
  if (!Number.isFinite(amount)) {
    return NextResponse.json({ error: '"amount" must be a finite number' }, { status: 400 });
  }

  const rawAttack = body["attack"];
  const attack: AttackKind = isAttackKind(rawAttack) ? rawAttack : "none";

  const result = await runCustomNegotiation({ amount, attack });
  return NextResponse.json(result);
}
