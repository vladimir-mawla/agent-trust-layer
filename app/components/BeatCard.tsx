import { formatEvidenceValue, toDisplayDecision } from "../lib/decision-view.js";
import { DidTag } from "./DidTag";
import type { NegotiationDecision } from "../../lib/negotiation/index.js";

export interface BeatCardProps {
  readonly title: string;
  readonly asker: string;
  readonly askedFor: string;
  readonly decision: NegotiationDecision;
  /** DOM id for the `<article>`, so the intro can link straight to one
   *  specific beat (e.g. `#beat-spoofed-identity` for Beat 3) — never
   *  set by the interactive panel's one-off result, which has nothing
   *  fixed to link to. */
  readonly id?: string | undefined;
  /** Rendered as `data-testid="decision"` when present — the fixed four
   *  beats use this (M8's own demo command greps for it); the
   *  interactive panel's result deliberately omits it so the page's
   *  server-rendered first frame always greps to exactly 4. */
  readonly testId?: string | undefined;
  /** For a proof-of-possession refusal: the DID the presenter falsely
   *  claimed actually belongs to. Rendered as an explicit character-by-
   *  character comparison (computed here, never hardcoded) so a reader
   *  can see for themselves that the two strings are identical. */
  readonly realOwnerOfClaimedDid?: string | undefined;
  readonly realOwnerLabel?: string | undefined;
  /** An extra, honestly-worded annotation the caller supplies for one
   *  specific beat (Beat 4's "valid signature, untrusted issuer" point)
   *  — never a substitute for the structured fields rendered above it. */
  readonly annotation?: string | undefined;
}

export function BeatCard({ title, asker, askedFor, decision, testId, realOwnerOfClaimedDid, realOwnerLabel, annotation, id }: BeatCardProps) {
  const display = toDisplayDecision(decision);
  const chainBroken = display.stage === "proof-of-possession";
  const claimedDidMatches = chainBroken && realOwnerOfClaimedDid !== undefined ? display.claimedDid === realOwnerOfClaimedDid : undefined;

  return (
    <article
      className="beat-card"
      data-permitted={display.permitted}
      {...(id !== undefined ? { id } : {})}
      {...(testId !== undefined ? { "data-testid": testId } : {})}
    >
      <header className="beat-card-head">
        <span className={`chip ${display.permitted ? "chip-permit" : "chip-refuse"}`}>
          {display.verdictLabel}
          {display.refusalKind !== undefined ? ` · ${display.refusalKind}` : ""}
        </span>
        <h3 className="beat-card-title">{title}</h3>
      </header>

      <dl className="beat-meta">
        <div>
          <dt>asker</dt>
          <dd>{asker}</dd>
        </div>
        <div>
          <dt>asked for</dt>
          <dd className="tabular">{askedFor}</dd>
        </div>
      </dl>

      {chainBroken && display.claimedDid !== undefined && realOwnerOfClaimedDid !== undefined ? (
        <div className={`did-compare${claimedDidMatches ? " did-compare-match" : ""}`}>
          <div className="did-compare-row">
            <span className="did-compare-label">claimed identity</span>
            <DidTag did={display.claimedDid} match={claimedDidMatches} />
          </div>
          <div className="did-compare-row">
            <span className="did-compare-label">{realOwnerLabel ?? "real owner of that DID"}</span>
            <DidTag did={realOwnerOfClaimedDid} match={claimedDidMatches} />
          </div>
          {claimedDidMatches ? (
            <p className="did-compare-note">
              Character-for-character identical. Copying a public DID string is free — proving possession of the private key behind it is
              not, which is exactly what failed here, <strong>before</strong> the presented credential was ever examined.
            </p>
          ) : null}
        </div>
      ) : null}

      <p className="beat-stage">{display.stageLabel}</p>

      <div className="beat-rule">
        <span className="beat-rule-id">{display.ruleId}</span>
        <span className="beat-rule-desc">{display.ruleDescription}</span>
      </div>

      <div className="evidence-row">
        <span className="evidence-path">{display.field.path}</span>
        {display.field.requested !== undefined ? (
          <span className="evidence-chip tabular">
            requested&nbsp;<strong>{formatEvidenceValue(display.field.requested)}</strong>
          </span>
        ) : null}
        {display.field.permitted !== undefined ? (
          <span className="evidence-chip tabular">
            permitted&nbsp;<strong>{formatEvidenceValue(display.field.permitted)}</strong>
          </span>
        ) : null}
        {display.field.actual !== undefined ? (
          <span className="evidence-chip tabular">
            actual&nbsp;<strong>{formatEvidenceValue(display.field.actual)}</strong>
          </span>
        ) : null}
      </div>

      <p className="beat-narrative">{display.narrative}</p>
      {annotation !== undefined ? <p className="beat-annotation">{annotation}</p> : null}
    </article>
  );
}
