import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { COMPLETED_MILESTONES, MILESTONES } from "./milestones";

/**
 * Guards against the drift that already happened once: the landing page said
 * "Milestone M2 of 9" for the whole of M3 and M4, on a public URL, because the
 * number lived in prose with nothing tying it to reality.
 *
 * `app/milestones.ts` now feeds the page and `.genesis/DONE.html` records build
 * state. Nothing structurally stopped them disagreeing again, so this asserts
 * the one property that actually matters publicly: **the set of milestones
 * claimed complete must be identical in both.**
 *
 * It deliberately does NOT compare the not-done states. DONE.html tracks build
 * state (todo / wip) while milestones.ts describes what a stranger should be
 * told (queued / in-progress); those granularities differ on purpose, and
 * forcing them to match would make this test fight legitimate edits instead of
 * catching false claims.
 */
const DONE_HTML = new URL("../.genesis/DONE.html", import.meta.url);

/**
 * Every (milestone id, pill state) pair in DONE.html's status table.
 *
 * Anchored on the pill deliberately: DONE.html carries a second table keyed by
 * the same milestone ids (the per-milestone skills list), so matching on the id
 * alone double-counts every row.
 */
function pillsInDoneHtml(): { id: string; state: string }[] {
  const html = readFileSync(DONE_HTML, "utf8");
  const rows = html.matchAll(
    /<tr><td>(M\d+)<\/td>(?:(?!<\/tr>)[\s\S])*?<span class="pill[^"]*">([a-z]+)<\/span>/g,
  );
  return [...rows].map((r) => ({ id: r[1]!, state: r[2]! }));
}

/** Milestone ids whose DONE.html pill reads "done". */
function completedInDoneHtml(): string[] {
  return pillsInDoneHtml().filter((p) => p.state === "done").map((p) => p.id);
}

describe("app/milestones.ts agrees with .genesis/DONE.html", () => {
  it("finds milestone rows in DONE.html at all", () => {
    // If the markup is reshaped, the parse silently returning nothing would make
    // every assertion below vacuously true. Fail loudly instead.
    const ids = pillsInDoneHtml().map((p) => p.id);
    expect(ids.length).toBe(MILESTONES.length);
    expect(ids).toEqual(MILESTONES.map((m) => m.id));
  });

  it("claims exactly the same milestones complete in both places", () => {
    const fromHtml = completedInDoneHtml();
    const fromModule = MILESTONES.filter((m) => m.status === "done").map((m) => m.id);
    expect(fromModule).toEqual(fromHtml);
  });

  it("derives the public count from the same source, not a literal", () => {
    expect(COMPLETED_MILESTONES).toBe(completedInDoneHtml().length);
  });
});
