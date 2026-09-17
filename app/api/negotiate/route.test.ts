/**
 * Body-shape validation for `POST /api/negotiate` — specifically the
 * fix for a loose array-body check: `typeof value === "object" &&
 * value !== null` alone accepts arrays too (they are `typeof
 * "object"`), so a `[1,2,3]` body used to slip past the object guard
 * and only get rejected indirectly once `amount`/`attack` lookups came
 * back empty. `isPlainObject` in `./route.ts` now rejects arrays (and
 * anything else that isn't a plain object) explicitly, with the same
 * structured `{ error }` shape every other invalid body gets. This
 * file exercises that guard directly against the real `POST` handler —
 * never a re-implementation of it.
 */
import { describe, expect, it } from "vitest";
import { POST } from "./route.js";

async function postRaw(rawBody: string): Promise<{ status: number; json: unknown }> {
  const request = new Request("http://localhost/api/negotiate", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: rawBody,
  });
  const response = await POST(request);
  return { status: response.status, json: await response.json() };
}

function postJson(body: unknown): Promise<{ status: number; json: unknown }> {
  return postRaw(JSON.stringify(body));
}

describe("POST /api/negotiate — invalid body shapes", () => {
  it("rejects an array body with a 400 and the same structured error as other invalid bodies, never a 500", async () => {
    const { status, json } = await postJson([1, 2, 3]);
    expect(status).toBe(400);
    expect(json).toEqual({ error: "request body must be a JSON object" });
  });

  it("rejects a null body with a 400 and the structured error", async () => {
    const { status, json } = await postJson(null);
    expect(status).toBe(400);
    expect(json).toEqual({ error: "request body must be a JSON object" });
  });

  it("rejects a string body with a 400 and the structured error", async () => {
    const { status, json } = await postJson("not an object");
    expect(status).toBe(400);
    expect(json).toEqual({ error: "request body must be a JSON object" });
  });

  it("rejects a number body with a 400 and the structured error", async () => {
    const { status, json } = await postJson(42);
    expect(status).toBe(400);
    expect(json).toEqual({ error: "request body must be a JSON object" });
  });

  it("does not misfire on a plain object that happens to carry an own '__proto__' key", async () => {
    // Built as a raw JSON string, exactly how `request.json()` (JSON.parse)
    // receives it over the wire: JSON.parse always creates "__proto__" as
    // an ordinary OWN property, never as the object's actual prototype, so
    // this is a plain object like any other and must be processed normally
    // rather than rejected by the shape guard.
    const { status, json } = await postRaw('{"__proto__":{"polluted":true},"amount":150,"attack":"none"}');
    expect(status).toBe(200);
    expect(json).toMatchObject({ decision: expect.any(Object) });
  });
});
