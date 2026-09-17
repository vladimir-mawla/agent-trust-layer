import { truncateDid } from "../lib/decision-view.js";

/**
 * A monospace, middle-truncated DID — the head stays visible (so Beat
 * 3's point, that two DIDs are byte-for-byte identical, reads at a
 * glance) and the tail stays visible (so a reader can still confirm two
 * DIDs are DIFFERENT without expanding anything). `title` carries the
 * full string so hovering (or a screen reader) still gets the whole DID.
 */
export function DidTag({ did, match }: { readonly did: string; readonly match?: boolean | undefined }) {
  return (
    <code className={`did-tag${match === true ? " did-tag-match" : match === false ? " did-tag-differ" : ""}`} title={did}>
      {truncateDid(did)}
    </code>
  );
}
