import {
  ALL_COMPLETE,
  COMPLETED_MILESTONES,
  CURRENT_MILESTONE,
  MILESTONES,
  TOTAL_MILESTONES,
} from "./milestones";
import { getFixedFourBeats } from "./lib/negotiation-service.js";
import { BeatCard } from "./components/BeatCard";
import { InteractivePanel } from "./components/InteractivePanel";
import { IdentityPanel } from "./components/IdentityPanel";
import { DidTag } from "./components/DidTag";

/**
 * Every progress claim on this page is derived from `./milestones.ts`, never
 * written into prose — see that module's own comment.
 *
 * The four-beat demo below is fetched and rendered SERVER-SIDE, on this
 * same request (`getFixedFourBeats` calls `lib/negotiation`'s real
 * `runFourBeatScenario` directly): a judge, a thumbnail, and a shared
 * link all see all four decisions on the first frame, with no button to
 * click and no client-side JavaScript required — `curl -s $URL/` alone
 * already contains them. `app/api/negotiate` (GET) exposes the identical
 * data as JSON, and its POST handler backs the interactive control
 * further down this page.
 *
 * Forced dynamic for the same reason `/api/negotiate` is: fresh Ed25519
 * keys are generated on every call to `getFixedFourBeats` (deliberately
 * — see `negotiation-service.ts`), so a statically-prerendered page
 * would freeze one run's cast forever until the next deploy, silently
 * contradicting "this is a real decision made on this request".
 */
export const dynamic = "force-dynamic";

export default async function Home() {
  const scenario = await getFixedFourBeats();
  const beatMeta: Record<string, { readonly annotation?: string; readonly compare?: boolean }> = {
    "spoofed-identity": { compare: true },
    "forged-credential": {
      annotation:
        "Honestly labelled: the attacker's own signature on this credential is genuinely valid. It is refused because the attacker is not a trust anchor this Supplier configured — a valid signature and a trusted issuer are different questions.",
    },
  };

  return (
    <main>
      <span className="badge">
        {ALL_COMPLETE
          ? `Complete · ${TOTAL_MILESTONES} milestones`
          : `${COMPLETED_MILESTONES} of ${TOTAL_MILESTONES} milestones` +
            (CURRENT_MILESTONE ? ` · ${CURRENT_MILESTONE.id} in progress` : "")}
      </span>

      <h1>agent-trust-layer</h1>

      <p className="dek">
        A trust decision, made visible: who asked, what they asked for, what a real policy engine decided, and the exact rule and field
        that decided it &mdash; never a bare accept/refuse.
      </p>

      <p className="signpost">
        Look for <a href="#beat-spoofed-identity">Beat 3</a>: an impostor presents the buyer&rsquo;s own real, unexpired credential
        while claiming a DID that is character-for-character identical to the buyer&rsquo;s &mdash; and is refused anyway, because it
        cannot sign the challenge.
      </p>

      <section aria-labelledby="demo-heading" className="demo-section">
        <h2 id="demo-heading">Four requests, one Supplier</h2>
        <p className="panel-lede">
          A Buyer and an Attacker, each holding their own Ed25519 keypair, negotiate with a Supplier that holds a policy and a set of
          trust anchors. Every decision below comes from actually running that protocol on this request &mdash; nothing here is a
          recorded transcript.
        </p>
        <dl className="cast-list">
          <div>
            <dt>trust anchor (issuer)</dt>
            <dd>
              <DidTag did={scenario.cast.issuerDid} />
            </dd>
          </div>
          <div>
            <dt>buyer</dt>
            <dd>
              <DidTag did={scenario.cast.buyerDid} />
            </dd>
          </div>
          <div>
            <dt>attacker</dt>
            <dd>
              <DidTag did={scenario.cast.attackerDid} />
            </dd>
          </div>
        </dl>
        <p className="policy-line tabular">
          Policy &ldquo;{scenario.policy.id}&rdquo; v{scenario.policy.version}: <code>{scenario.policy.action}</code> permitted up to{" "}
          <strong>amount = {scenario.policy.grantedMaxAmount}</strong>; revocation must be checked.
        </p>

        <div className="beat-grid">
          {scenario.beats.map((beat) => (
            <BeatCard
              key={beat.id}
              id={`beat-${beat.id}`}
              title={beat.title}
              asker={beat.asker}
              askedFor={beat.askedFor}
              decision={beat.decision}
              testId="decision"
              realOwnerOfClaimedDid={beatMeta[beat.id]?.compare === true ? scenario.cast.buyerDid : undefined}
              realOwnerLabel="buyer's real DID"
              annotation={beatMeta[beat.id]?.annotation}
            />
          ))}
        </div>
      </section>

      <InteractivePanel />

      <IdentityPanel />

      <h2>What is built</h2>
      <ul className="ledger">
        {MILESTONES.map((m) => (
          <li key={m.id} data-status={m.status}>
            <span className="mid">{m.id}</span>
            <span className="mtitle">{m.title}</span>
            <span className="mstate">
              {m.status === "done" ? "done" : m.status === "in-progress" ? "building" : "queued"}
            </span>
          </li>
        ))}
      </ul>

      <p>
        The health endpoint is not a liveness ping. It generates a keypair, encodes a{" "}
        <code>did:key</code>, decodes it back, signs a challenge and verifies it &mdash; on every
        request, inside this deployment &mdash; and returns <code>503</code> rather than <code>200</code>{" "}
        if any of that fails. It also reports the deployed commit, so you can confirm the running
        code is the code in the repository.
      </p>

      <div className="links">
        <a href="https://github.com/vladimir-mawla/agent-trust-layer">Source on GitHub &rarr;</a>
        <a href="/api/health">Health endpoint (/api/health) &rarr;</a>
        <a href="/api/negotiate">Negotiation endpoint (/api/negotiate) &rarr;</a>
      </div>
    </main>
  );
}
