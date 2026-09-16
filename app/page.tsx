export default function Home() {
  return (
    <main>
      <span className="badge">Milestone M2 of 9 &middot; Under construction</span>
      <h1>agent-trust-layer</h1>
      <p>
        A verifiable trust layer for AI agents: self-certifying <code>did:key</code> identity,
        signed verifiable credentials, revocation, and a policy engine that explains every
        accept/refuse decision instead of returning a bare boolean.
      </p>
      <p>
        This is a live deployment skeleton, not the finished product. The full interactive demo
        (a scripted negotiation between two agents, with the credential chain and the reason
        behind each decision made visible) lands in milestone M8. Right now this page exists
        mainly to prove there is a real, public URL serving real code.
      </p>
      <div className="links">
        <a href="https://github.com/vladimir-mawla/agent-trust-layer">
          Source on GitHub &rarr;
        </a>
        <a href="/api/health">Health endpoint (/api/health) &rarr;</a>
      </div>
    </main>
  );
}
