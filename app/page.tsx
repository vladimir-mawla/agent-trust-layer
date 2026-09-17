import {
  ALL_COMPLETE,
  COMPLETED_MILESTONES,
  CURRENT_MILESTONE,
  MILESTONES,
  TOTAL_MILESTONES,
} from "./milestones";

/**
 * Every progress claim on this page is derived from `./milestones.ts`, never
 * written into prose. The previous version hard-coded "Milestone M2 of 9" and
 * kept saying it through M3 and M4 — a stale claim on a public URL, which is
 * exactly what this project argues against everywhere else.
 */
export default function Home() {
  return (
    <main>
      <span className="badge">
        {ALL_COMPLETE
          ? `Complete · ${TOTAL_MILESTONES} milestones`
          : `${COMPLETED_MILESTONES} of ${TOTAL_MILESTONES} milestones` +
            (CURRENT_MILESTONE ? ` · ${CURRENT_MILESTONE.id} in progress` : "")}
      </span>

      <h1>agent-trust-layer</h1>

      <p>
        A verifiable trust layer for AI agents: self-certifying <code>did:key</code> identity,
        verifiable credentials signed as JWTs, revocation with trust anchors, and a policy engine
        that explains every accept and refuse decision instead of returning a bare boolean.
      </p>
      <p>
        Trust here is not a number. It is a decision — about a specific counterparty, for a
        specific action, under a stated policy, from evidence anyone can verify themselves.
      </p>

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
        {CURRENT_MILESTONE
          ? "The interactive demo — a scripted negotiation between two agents, showing the credential chain and the reason behind each decision — lands in M8. Until then, the layers marked done above are real, tested code rather than a plan."
          : "Every milestone above is complete."}
      </p>
      <p>
        The health endpoint is not a liveness ping. It generates a keypair, encodes a{" "}
        <code>did:key</code>, decodes it back, signs a challenge and verifies it — on every
        request, inside this deployment — and returns <code>503</code> rather than <code>200</code>{" "}
        if any of that fails. It also reports the deployed commit, so you can confirm the running
        code is the code in the repository.
      </p>

      <div className="links">
        <a href="https://github.com/vladimir-mawla/agent-trust-layer">Source on GitHub &rarr;</a>
        <a href="/api/health">Health endpoint (/api/health) &rarr;</a>
      </div>
    </main>
  );
}
