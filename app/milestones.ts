/**
 * The project's milestone state, in one place.
 *
 * WHY THIS FILE EXISTS: the landing page previously hard-coded the string
 * "Milestone M2 of 9", and went on claiming M2 for the whole of M3 and M4 —
 * on a public URL, for a project judged partly on whether its claims are
 * accurate. A number written into a sentence has no reason to change when the
 * work does.
 *
 * So the page derives everything it says about progress from this array
 * instead: the count, the current milestone, and which layers actually exist.
 * Flipping a pill in `.genesis/DONE.html` and updating this list are the same
 * act, and there is exactly one line to change rather than a paragraph to
 * re-read.
 *
 * This is the authoritative list for anything the deployed app renders.
 * `.genesis/PLAN.md` holds the full definition of each milestone — its freeze
 * boundary, demo command and success criteria — which is deliberately not
 * duplicated here; a public page has no business restating a build plan.
 */

export type MilestoneStatus = "done" | "in-progress" | "queued";

export interface Milestone {
  /** Stable identifier, matching `.genesis/PLAN.md` and DONE.html. */
  readonly id: string;
  /** Short description — this is read by strangers, so no internal shorthand. */
  readonly title: string;
  readonly status: MilestoneStatus;
}

export const MILESTONES: readonly Milestone[] = [
  { id: "M1", title: "Identity — did:key and proof of possession", status: "done" },
  { id: "M2", title: "Live deployment", status: "done" },
  { id: "M3", title: "Verifiable credentials — issue and verify", status: "done" },
  { id: "M4", title: "Revocation and trust anchors", status: "done" },
  { id: "M5", title: "Policy engine with explanations", status: "in-progress" },
  { id: "M6", title: "Cross-agent negotiation", status: "queued" },
  { id: "M7", title: "The attack suite", status: "queued" },
  { id: "M8", title: "The interactive demo", status: "queued" },
  { id: "M9", title: "Architecture snapshot and thesis", status: "queued" },
] as const;

export const TOTAL_MILESTONES = MILESTONES.length;

export const COMPLETED_MILESTONES = MILESTONES.filter((m) => m.status === "done").length;

/**
 * The milestone currently being built, if any. Undefined between milestones —
 * the page must not assume one is always in flight.
 */
export const CURRENT_MILESTONE: Milestone | undefined = MILESTONES.find(
  (m) => m.status === "in-progress",
);

/** True once every milestone is done, so the page can stop calling itself unfinished. */
export const ALL_COMPLETE = COMPLETED_MILESTONES === TOTAL_MILESTONES;
