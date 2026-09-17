import { describe, expect, it } from "vitest";
import { createChallenge, encodeDidKey, generateKeyPair, provePossession, type Did, type ProofOfPossession } from "../identity/index.js";
import { issueAuthorityCredential, issueHistoryAttestation } from "../credentials/index.js";
import { TrustAnchorSet } from "../trust/anchors.js";
import { issueStatusListCredential } from "../trust/status-list.js";
import { evaluateAuthorityCredentialTrust, evaluateHistoryAttestationTrust, type TrustDecision } from "../trust/index.js";
import type { AuthorityCredential } from "../credentials/index.js";
import { evaluatePolicyRequest, type EvaluatePolicyRequestInput, type PolicyDecision } from "./engine.js";
import { ACTION_SCOPE_RULE_KIND, HISTORY_NARROW_RULE_KIND, type Policy } from "./policy-types.js";

interface Identity {
  readonly publicKey: Uint8Array;
  readonly privateKey: Uint8Array;
  readonly did: Did;
}

function makeIdentity(): Identity {
  const { publicKey, privateKey } = generateKeyPair();
  return { publicKey, privateKey, did: encodeDidKey(publicKey) };
}

function proofOfPossessionFor(identity: Identity, now = 0): ProofOfPossession {
  const challenge = createChallenge({ now, ttlMs: 60_000 });
  return provePossession(identity.privateKey, identity.did, challenge);
}

const MANDATORY_REVOCATION_POLICY_BASE = {
  id: "supplier-policy",
  version: "1.0.0",
  revocationHandling: { requireChecked: true } as const,
};

function purchasePolicy(overrides: Partial<Policy> = {}): Policy {
  return {
    ...MANDATORY_REVOCATION_POLICY_BASE,
    rules: [{ kind: ACTION_SCOPE_RULE_KIND, id: "R-purchase", description: "purchases up to the credential's own scope", action: "purchase", maxScope: {} }],
    ...overrides,
  };
}

async function acceptedAuthority(
  issuer: Identity,
  subject: Identity,
  anchors: TrustAnchorSet,
  opts: { readonly scope?: Record<string, number>; readonly withRevocationChecked?: boolean } = {},
): Promise<TrustDecision<AuthorityCredential> & { accepted: true }> {
  const jwt = issueAuthorityCredential({
    issuerPrivateKey: issuer.privateKey,
    issuerDid: issuer.did,
    subjectDid: subject.did,
    action: "purchase",
    scope: opts.scope ?? { maxAmount: 500 },
    validUntil: "2099-01-01T00:00:00Z",
    now: 0,
  });

  if (opts.withRevocationChecked) {
    const statusListJwt = issueStatusListCredential({ issuerPrivateKey: issuer.privateKey, issuerDid: issuer.did, statusPurpose: "revocation", sizeBits: 128, now: 0 });
    const decision = await evaluateAuthorityCredentialTrust({
      jwt,
      presenterProof: proofOfPossessionFor(subject, 0),
      anchors,
      credentialStatus: { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: 1, statusListCredential: "https://issuer.example/status/1" },
      statusListResolver: async () => statusListJwt,
      now: 0,
    });
    if (!decision.accepted) throw new Error("expected acceptance in fixture");
    return decision;
  }

  const decision = await evaluateAuthorityCredentialTrust({ jwt, presenterProof: proofOfPossessionFor(subject, 0), anchors, now: 0 });
  if (!decision.accepted) throw new Error("expected acceptance in fixture");
  return decision;
}

function expectNonEmptyExplanation(decision: PolicyDecision): void {
  expect(decision.explanation.rule.ruleId.length).toBeGreaterThan(0);
  expect(decision.explanation.rule.description.length).toBeGreaterThan(0);
  expect(decision.explanation.field.path.length).toBeGreaterThan(0);
  expect(decision.explanation.narrative.length).toBeGreaterThan(0);
  expect(Array.isArray(decision.explanation.caveats)).toBe(true);
}

const allDecisions: PolicyDecision[] = [];
function record(decision: PolicyDecision): PolicyDecision {
  allDecisions.push(decision);
  return decision;
}

describe("evaluatePolicyRequest — permit path", () => {
  it("permits an in-scope request from a direct anchor's authority credential, naming the rule and the satisfying field", async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const anchors = new TrustAnchorSet([issuer.did]);
    const authority = await acceptedAuthority(issuer, subject, anchors, { withRevocationChecked: true });

    const decision = record(
      evaluatePolicyRequest({
        policy: purchasePolicy({ rules: [{ kind: ACTION_SCOPE_RULE_KIND, id: "R-purchase", description: "office supplies purchases", action: "purchase", maxScope: { maxAmount: 500 } }] }),
        request: { action: "purchase", scope: { maxAmount: 200 } },
        authority,
        history: [],
      }),
    );

    expect(decision.permitted).toBe(true);
    if (!decision.permitted) throw new Error("expected permit");
    expect(decision.explanation.rule.ruleId).toBe("R-purchase");
    expect(decision.explanation.field.path).toBe("credentialSubject.action");
    expect(decision.explanation.field.permitted).toBe("purchase");
    expect(decision.envelope.action).toBe("purchase");
    expectNonEmptyExplanation(decision);
  });
});

describe("evaluatePolicyRequest — over-scope, distinct from wrong-action and no-authority", () => {
  it("refuses a request over the credential's own scope, naming the exact field and both values", async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const anchors = new TrustAnchorSet([issuer.did]);
    const authority = await acceptedAuthority(issuer, subject, anchors, { scope: { maxAmount: 500 }, withRevocationChecked: true });

    const decision = record(
      evaluatePolicyRequest({
        policy: purchasePolicy(),
        request: { action: "purchase", scope: { maxAmount: 5_000 } },
        authority,
        history: [],
      }),
    );

    expect(decision.permitted).toBe(false);
    if (decision.permitted) throw new Error("expected refusal");
    expect(decision.explanation.refusalKind).toBe("over-scope");
    expect(decision.explanation.field.path).toBe("scope.maxAmount");
    expect(decision.explanation.field.requested).toBe(5_000);
    expect(decision.explanation.field.permitted).toBe(500);
    expectNonEmptyExplanation(decision);
  });

  it("refuses a wrong-action request distinctly from over-scope", async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const anchors = new TrustAnchorSet([issuer.did]);
    const authority = await acceptedAuthority(issuer, subject, anchors, { withRevocationChecked: true });

    const decision = record(
      evaluatePolicyRequest({
        policy: purchasePolicy(),
        request: { action: "delete-database", scope: {} },
        authority,
        history: [],
      }),
    );

    expect(decision.permitted).toBe(false);
    if (decision.permitted) throw new Error("expected refusal");
    expect(decision.explanation.refusalKind).toBe("wrong-action");
    expect(decision.explanation.field.requested).toBe("delete-database");
    expect(decision.explanation.field.permitted).toBe("purchase");
    expectNonEmptyExplanation(decision);
  });

  it("refuses when no authority credential was presented at all, distinctly from wrong-action and over-scope", () => {
    const decision = record(
      evaluatePolicyRequest({
        policy: purchasePolicy(),
        request: { action: "purchase", scope: { maxAmount: 1 } },
        authority: null,
        history: [],
      }),
    );

    expect(decision.permitted).toBe(false);
    if (decision.permitted) throw new Error("expected refusal");
    expect(decision.explanation.refusalKind).toBe("no-authority-credential");
    expectNonEmptyExplanation(decision);
  });
});

describe("evaluatePolicyRequest — revocation", () => {
  it("refuses a revoked credential", async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const anchors = new TrustAnchorSet([issuer.did]);

    const jwt = issueAuthorityCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      action: "purchase",
      scope: { maxAmount: 500 },
      validUntil: "2099-01-01T00:00:00Z",
      now: 0,
    });
    const statusListJwt = issueStatusListCredential({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      statusPurpose: "revocation",
      sizeBits: 128,
      revokedIndices: [1],
      now: 0,
    });
    const authority = await evaluateAuthorityCredentialTrust({
      jwt,
      presenterProof: proofOfPossessionFor(subject, 0),
      anchors,
      credentialStatus: { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: 1, statusListCredential: "https://issuer.example/status/1" },
      statusListResolver: async () => statusListJwt,
      now: 0,
    });
    expect(authority.accepted).toBe(false);

    const decision = record(evaluatePolicyRequest({ policy: purchasePolicy(), request: { action: "purchase", scope: { maxAmount: 1 } }, authority, history: [] }));

    expect(decision.permitted).toBe(false);
    if (decision.permitted) throw new Error("expected refusal");
    expect(decision.explanation.refusalKind).toBe("revoked");
    expectNonEmptyExplanation(decision);
  });

  it("refuses by default when revocation was never checked (mandatory gate)", async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const anchors = new TrustAnchorSet([issuer.did]);
    const authority = await acceptedAuthority(issuer, subject, anchors); // no credentialStatus/resolver supplied
    expect(authority.revocation.outcome).toBe("not-checked");

    const decision = record(
      evaluatePolicyRequest({
        policy: purchasePolicy(), // revocationHandling: { requireChecked: true } — the default, mandatory value
        request: { action: "purchase", scope: { maxAmount: 1 } },
        authority,
        history: [],
      }),
    );

    expect(decision.permitted).toBe(false);
    if (decision.permitted) throw new Error("expected refusal");
    expect(decision.explanation.refusalKind).toBe("revocation-not-checked");
    expectNonEmptyExplanation(decision);
  });

  it("permits an unchecked-revocation credential ONLY when the policy explicitly, affirmatively opts in, and records that opt-in in the explanation", async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const anchors = new TrustAnchorSet([issuer.did]);
    const authority = await acceptedAuthority(issuer, subject, anchors);
    expect(authority.revocation.outcome).toBe("not-checked");

    const permissivePolicy: Policy = {
      id: "supplier-policy-permissive",
      version: "1.0.0",
      revocationHandling: { requireChecked: false, acknowledgedBy: "ops-lead@example.com", reason: "no status list infra for this low-risk action yet" },
      rules: [{ kind: ACTION_SCOPE_RULE_KIND, id: "R-purchase", description: "purchase ceiling", action: "purchase", maxScope: { maxAmount: 500 } }],
    };

    const decision = record(evaluatePolicyRequest({ policy: permissivePolicy, request: { action: "purchase", scope: { maxAmount: 1 } }, authority, history: [] }));

    expect(decision.permitted).toBe(true);
    if (!decision.permitted) throw new Error("expected permit");
    expect(decision.explanation.caveats).toHaveLength(1);
    expect(decision.explanation.caveats[0]).toMatchObject({
      kind: "revocation-not-checked-accepted",
      acknowledgedBy: "ops-lead@example.com",
      reason: "no status list infra for this low-risk action yet",
    });
    expectNonEmptyExplanation(decision);
  });
});

describe("evaluatePolicyRequest — untrusted issuer", () => {
  it("refuses a self-issued authority credential (untrusted-issuer), distinctly from every other refusal", async () => {
    const attacker = makeIdentity();
    const anchors = new TrustAnchorSet([makeIdentity().did]);

    const jwt = issueAuthorityCredential({
      issuerPrivateKey: attacker.privateKey,
      issuerDid: attacker.did,
      subjectDid: attacker.did,
      action: "purchase",
      scope: { maxAmount: 1_000_000 },
      validUntil: "2099-01-01T00:00:00Z",
      now: 0,
    });
    const authority = await evaluateAuthorityCredentialTrust({ jwt, presenterProof: proofOfPossessionFor(attacker, 0), anchors, now: 0 });
    expect(authority.accepted).toBe(false);

    const decision = record(evaluatePolicyRequest({ policy: purchasePolicy(), request: { action: "purchase", scope: { maxAmount: 1 } }, authority, history: [] }));

    expect(decision.permitted).toBe(false);
    if (decision.permitted) throw new Error("expected refusal");
    expect(decision.explanation.refusalKind).toBe("untrusted-issuer");
    expectNonEmptyExplanation(decision);
  });
});

describe("evaluatePolicyRequest — history narrowing", () => {
  it("refuses a request that a history constraint narrows below, naming the attestation and the constraint", async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const anchors = new TrustAnchorSet([issuer.did]);
    const authority = await acceptedAuthority(issuer, subject, anchors, { scope: { maxAmount: 500 }, withRevocationChecked: true });

    const historyJwt = issueHistoryAttestation({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      observationType: "disputes-observed",
      metrics: { disputeCount: 3 },
      now: 0,
    });
    const history = await evaluateHistoryAttestationTrust({ jwt: historyJwt, presenterProof: proofOfPossessionFor(subject, 0), now: 0 });
    expect(history.accepted).toBe(true);

    const policy: Policy = {
      id: "supplier-policy-narrowed",
      version: "1.0.0",
      revocationHandling: { requireChecked: true },
      rules: [
        { kind: ACTION_SCOPE_RULE_KIND, id: "R-purchase", description: "purchase ceiling", action: "purchase", maxScope: { maxAmount: 500 } },
        {
          kind: HISTORY_NARROW_RULE_KIND,
          id: "R-dispute-narrow",
          description: "3+ observed disputes narrow the purchase ceiling to 100",
          action: "purchase",
          observationType: "disputes-observed",
          metric: "disputeCount",
          operator: "gte",
          threshold: 3,
          scopeField: "maxAmount",
          narrowedMax: 100,
        },
      ],
    };

    const decision = record(evaluatePolicyRequest({ policy, request: { action: "purchase", scope: { maxAmount: 200 } }, authority, history: [history] }));

    expect(decision.permitted).toBe(false);
    if (decision.permitted) throw new Error("expected refusal");
    expect(decision.explanation.refusalKind).toBe("history-constraint");
    expect(decision.explanation.rule.ruleId).toBe("R-dispute-narrow");
    expect(decision.explanation.field.requested).toBe(200);
    expect(decision.explanation.field.permitted).toBe(100);
    expect(decision.explanation.narrative).toContain(issuer.did);
    expectNonEmptyExplanation(decision);
  });

  it("still refuses when history attestations are present but no authority credential is (history alone never permits)", async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();

    const historyJwt = issueHistoryAttestation({
      issuerPrivateKey: issuer.privateKey,
      issuerDid: issuer.did,
      subjectDid: subject.did,
      observationType: "transactions-completed",
      metrics: { count: 9_999 },
      now: 0,
    });
    const history = await evaluateHistoryAttestationTrust({ jwt: historyJwt, presenterProof: proofOfPossessionFor(subject, 0), now: 0 });

    const decision = record(evaluatePolicyRequest({ policy: purchasePolicy(), request: { action: "purchase", scope: { maxAmount: 1 } }, authority: null, history: [history] }));

    expect(decision.permitted).toBe(false);
    if (decision.permitted) throw new Error("expected refusal");
    expect(decision.explanation.refusalKind).toBe("no-authority-credential");
    expectNonEmptyExplanation(decision);
  });
});

describe("evaluatePolicyRequest — no matching rule (policy authored nothing for this action)", () => {
  it("refuses, distinctly, when the policy has no action-scope rule for the credential's granted action", async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const anchors = new TrustAnchorSet([issuer.did]);
    const authority = await acceptedAuthority(issuer, subject, anchors, { withRevocationChecked: true });

    const emptyPolicy: Policy = { id: "empty-policy", version: "1.0.0", revocationHandling: { requireChecked: true }, rules: [] };
    const decision = record(evaluatePolicyRequest({ policy: emptyPolicy, request: { action: "purchase", scope: { maxAmount: 1 } }, authority, history: [] }));

    expect(decision.permitted).toBe(false);
    if (decision.permitted) throw new Error("expected refusal");
    expect(decision.explanation.refusalKind).toBe("no-matching-rule");
    expectNonEmptyExplanation(decision);
  });
});

describe("every-decision-is-explainable — property across every case exercised above", () => {
  it("every recorded decision (permit or refuse) carries a non-empty structured explanation", () => {
    expect(allDecisions.length).toBeGreaterThanOrEqual(10);
    for (const decision of allDecisions) {
      expectNonEmptyExplanation(decision);
      // Never a bare boolean: `outcome`/`refusalKind` are always present
      // alongside rule/field/narrative, never standing in on their own.
      expect(["permitted", "refused"]).toContain(decision.permitted ? "permitted" : "refused");
    }
  });
});

// ---------------------------------------------------------------------
// FINDING 1 (L4 M5 review): malformed `authority`/`history` inputs must
// fail closed as a structured `PolicyDecision`, never throw a bare
// TypeError. `validatePolicy` already defends the `policy` argument this
// thoroughly; before this fix, `authority`/`history` got none of it
// because they're typed as trusted `TrustDecision`s — true only for a
// caller that never crosses a serialization boundary (see engine.ts's
// module comment and ADR 0004's own "claims arrive as JSON, not
// TypeScript"). Every case below deliberately bypasses TypeScript (via
// an untyped raw input) the way a JSON-sourced caller would.
// ---------------------------------------------------------------------
function callWithRawInput(raw: Record<string, unknown>): PolicyDecision {
  return evaluatePolicyRequest(raw as unknown as EvaluatePolicyRequestInput);
}

describe("evaluatePolicyRequest — malformed authority/history inputs fail closed, never throw (FINDING 1)", () => {
  const policy = purchasePolicy();
  const request = { action: "purchase", scope: { maxAmount: 1 } };

  it("authority: undefined — returns a structured refusal, never throws", () => {
    let decision: PolicyDecision | undefined;
    expect(() => {
      decision = record(callWithRawInput({ policy, request, authority: undefined, history: [] }));
    }).not.toThrow();
    expect(decision?.permitted).toBe(false);
    if (!decision || decision.permitted) throw new Error("expected refusal");
    expect(decision.explanation.refusalKind).toBe("no-authority-credential");
    expectNonEmptyExplanation(decision);
  });

  it("authority: {} — returns a structured refusal, never throws", () => {
    let decision: PolicyDecision | undefined;
    expect(() => {
      decision = record(callWithRawInput({ policy, request, authority: {}, history: [] }));
    }).not.toThrow();
    expect(decision?.permitted).toBe(false);
    if (!decision || decision.permitted) throw new Error("expected refusal");
    expect(decision.explanation.refusalKind).toBe("no-authority-credential");
    expectNonEmptyExplanation(decision);
  });

  it("authority: {accepted: true} with every nested field missing — returns a structured refusal, never throws", () => {
    let decision: PolicyDecision | undefined;
    expect(() => {
      decision = record(callWithRawInput({ policy, request, authority: { accepted: true }, history: [] }));
    }).not.toThrow();
    expect(decision?.permitted).toBe(false);
    if (!decision || decision.permitted) throw new Error("expected refusal");
    expect(decision.explanation.refusalKind).toBe("no-authority-credential");
    expectNonEmptyExplanation(decision);
  });

  it("authority: {accepted: false, stage: <unrecognised>} — returns a structured refusal, never throws (engine.ts used to assume anything not credential-verification/issuer-trust must be revocation)", () => {
    let decision: PolicyDecision | undefined;
    expect(() => {
      decision = record(callWithRawInput({ policy, request, authority: { accepted: false, stage: "some-future-stage", reason: "x" }, history: [] }));
    }).not.toThrow();
    expect(decision?.permitted).toBe(false);
    if (!decision || decision.permitted) throw new Error("expected refusal");
    expect(decision.explanation.refusalKind).toBe("no-authority-credential");
    expectNonEmptyExplanation(decision);
  });

  it("history: not an array at all — returns a structured refusal, never throws", () => {
    let decision: PolicyDecision | undefined;
    expect(() => {
      decision = record(callWithRawInput({ policy, request, authority: null, history: "not-an-array" }));
    }).not.toThrow();
    expect(decision?.permitted).toBe(false);
    if (!decision || decision.permitted) throw new Error("expected refusal");
    expect(decision.explanation.refusalKind).toBe("no-authority-credential");
    expectNonEmptyExplanation(decision);
  });

  // Both fixtures below deliberately include a `history-narrow` rule
  // matching the request's action — WITHOUT one, `computeHistoryConstraints`
  // never even iterates into `history`'s individual entries (its outer
  // loop is over policy rules first), so a garbage entry would be
  // "dropped" merely by never being looked at, not by surviving the
  // guard. With the rule present, `history-constraints.ts:76`
  // (`decision.credentialVerification.credential...`) is the exact line
  // that used to throw for `{ accepted: true }` and `null` entries.
  const policyWithHistoryRule: Policy = {
    id: "policy-garbage-history-fixture",
    version: "1.0.0",
    revocationHandling: { requireChecked: true },
    rules: [
      { kind: ACTION_SCOPE_RULE_KIND, id: "R-purchase", description: "x", action: "purchase", maxScope: { maxAmount: 500 } },
      {
        kind: HISTORY_NARROW_RULE_KIND,
        id: "R-narrow",
        description: "narrows on disputes (irrelevant to whether it fires here — the point is the loop reaches every history entry)",
        action: "purchase",
        observationType: "disputes-observed",
        metric: "disputeCount",
        operator: "gte",
        threshold: 3,
        scopeField: "maxAmount",
        narrowedMax: 100,
      },
    ],
  };

  it("history: [{accepted: true}] — a garbage entry alongside a REAL accepted authority is dropped, never fatal, and the real permit still goes through", async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const anchors = new TrustAnchorSet([issuer.did]);
    const authority = await acceptedAuthority(issuer, subject, anchors, { scope: { maxAmount: 500 }, withRevocationChecked: true });

    let decision: PolicyDecision | undefined;
    expect(() => {
      decision = record(
        callWithRawInput({
          policy: policyWithHistoryRule,
          request: { action: "purchase", scope: { maxAmount: 200 } },
          authority,
          history: [{ accepted: true }],
        }),
      );
    }).not.toThrow();
    expect(decision?.permitted).toBe(true);
    if (!decision) throw new Error("expected a decision");
    expectNonEmptyExplanation(decision);
  });

  it("history: an array containing null alongside a real accepted authority — null is dropped, never fatal", async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const anchors = new TrustAnchorSet([issuer.did]);
    const authority = await acceptedAuthority(issuer, subject, anchors, { scope: { maxAmount: 500 }, withRevocationChecked: true });

    let decision: PolicyDecision | undefined;
    expect(() => {
      decision = record(
        callWithRawInput({
          policy: policyWithHistoryRule,
          request: { action: "purchase", scope: { maxAmount: 200 } },
          authority,
          history: [null],
        }),
      );
    }).not.toThrow();
    expect(decision?.permitted).toBe(true);
    if (!decision) throw new Error("expected a decision");
    expectNonEmptyExplanation(decision);
  });
});

// ---------------------------------------------------------------------
// FINDING 4 (L4 M5 review): omitting a bounded scope field must not
// bypass the ceiling. The loop used to iterate only `request.scope`'s
// own keys — a field never named by the request was never checked at
// all, so `{ scope: {} }` against a policy with a `maxAmount` ceiling
// returned an unconditional permit, never even consulting the
// credential's own granted ceiling.
// ---------------------------------------------------------------------
describe("evaluatePolicyRequest — omitting a bounded scope field is refused, not an implicit bypass (FINDING 4)", () => {
  it("an entirely empty scope ({}) is refused when the action has a bounded field, instead of an unconditional permit", async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const anchors = new TrustAnchorSet([issuer.did]);
    const authority = await acceptedAuthority(issuer, subject, anchors, { scope: { maxAmount: 500 }, withRevocationChecked: true });

    const decision = record(
      evaluatePolicyRequest({
        policy: purchasePolicy({ rules: [{ kind: ACTION_SCOPE_RULE_KIND, id: "R-purchase", description: "x", action: "purchase", maxScope: { maxAmount: 500 } }] }),
        request: { action: "purchase", scope: {} },
        authority,
        history: [],
      }),
    );

    expect(decision.permitted).toBe(false);
    if (decision.permitted) throw new Error("expected refusal");
    expect(decision.explanation.refusalKind).toBe("over-scope");
    expect(decision.explanation.field.path).toBe("scope.maxAmount");
    expectNonEmptyExplanation(decision);
  });

  it("a scope naming SOME but not all bounded fields is refused for the omitted field", async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const anchors = new TrustAnchorSet([issuer.did]);
    const authority = await acceptedAuthority(issuer, subject, anchors, { scope: { maxAmount: 500, maxItems: 10 }, withRevocationChecked: true });

    const decision = record(
      evaluatePolicyRequest({
        policy: purchasePolicy({
          rules: [{ kind: ACTION_SCOPE_RULE_KIND, id: "R-purchase", description: "x", action: "purchase", maxScope: { maxAmount: 500, maxItems: 10 } }],
        }),
        request: { action: "purchase", scope: { maxAmount: 200 } }, // maxItems omitted
        authority,
        history: [],
      }),
    );

    expect(decision.permitted).toBe(false);
    if (decision.permitted) throw new Error("expected refusal");
    expect(decision.explanation.refusalKind).toBe("over-scope");
    expect(decision.explanation.field.path).toBe("scope.maxItems");
    expectNonEmptyExplanation(decision);
  });

  it("a scope field no rule or credential covers is silently ignored (still permitted), distinct from an omitted BOUNDED field", async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const anchors = new TrustAnchorSet([issuer.did]);
    const authority = await acceptedAuthority(issuer, subject, anchors, { scope: { maxAmount: 500 }, withRevocationChecked: true });

    const decision = record(
      evaluatePolicyRequest({
        policy: purchasePolicy({ rules: [{ kind: ACTION_SCOPE_RULE_KIND, id: "R-purchase", description: "x", action: "purchase", maxScope: { maxAmount: 500 } }] }),
        request: { action: "purchase", scope: { maxAmount: 200, unrelatedField: 999 } },
        authority,
        history: [],
      }),
    );

    expect(decision.permitted).toBe(true);
    expectNonEmptyExplanation(decision);
  });

  it("a scope naming an extra field the credential itself never mentions, but the POLICY does, is still bound-checked", async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const anchors = new TrustAnchorSet([issuer.did]);
    // Credential grants ONLY maxAmount — maxItems is a policy-only ceiling.
    const authority = await acceptedAuthority(issuer, subject, anchors, { scope: { maxAmount: 500 }, withRevocationChecked: true });

    const policy = purchasePolicy({
      rules: [{ kind: ACTION_SCOPE_RULE_KIND, id: "R-purchase", description: "x", action: "purchase", maxScope: { maxAmount: 500, maxItems: 10 } }],
    });

    const permitted = record(
      evaluatePolicyRequest({ policy, request: { action: "purchase", scope: { maxAmount: 200, maxItems: 5 } }, authority, history: [] }),
    );
    expect(permitted.permitted).toBe(true);

    const refused = record(
      evaluatePolicyRequest({ policy, request: { action: "purchase", scope: { maxAmount: 200, maxItems: 50 } }, authority, history: [] }),
    );
    expect(refused.permitted).toBe(false);
    if (refused.permitted) throw new Error("expected refusal");
    expect(refused.explanation.refusalKind).toBe("over-scope");
    expect(refused.explanation.field.path).toBe("scope.maxItems");
    expectNonEmptyExplanation(refused);
  });
});

// ---------------------------------------------------------------------
// FINDING 5 (L4 M5 review): `credential-verification-failed` — one of
// nine documented RefusalKinds — had zero coverage anywhere despite
// being reachable. Reached here through the REAL path: a malformed JWT
// through the real `evaluateAuthorityCredentialTrust`, into
// `evaluatePolicyRequest`.
// ---------------------------------------------------------------------
describe("evaluatePolicyRequest — credential-verification-failed is reachable via a real malformed JWT (FINDING 5)", () => {
  it("refuses with refusalKind credential-verification-failed and a populated explanation", async () => {
    const subject = makeIdentity();
    const anchors = new TrustAnchorSet([makeIdentity().did]);

    const authority = await evaluateAuthorityCredentialTrust({
      jwt: "abc.def", // malformed compact JWS — fails M3's own "parse" step
      presenterProof: proofOfPossessionFor(subject, 0),
      anchors,
      now: 0,
    });
    expect(authority.accepted).toBe(false);
    if (authority.accepted) throw new Error("expected a verification failure in this fixture");
    expect(authority.stage).toBe("credential-verification");

    const decision = record(evaluatePolicyRequest({ policy: purchasePolicy(), request: { action: "purchase", scope: { maxAmount: 1 } }, authority, history: [] }));

    expect(decision.permitted).toBe(false);
    if (decision.permitted) throw new Error("expected refusal");
    expect(decision.explanation.refusalKind).toBe("credential-verification-failed");
    expect(decision.explanation.narrative.length).toBeGreaterThan(0);
    expectNonEmptyExplanation(decision);
  });
});

// ---------------------------------------------------------------------
// FINDING 8 (L4 M5 review, defending an M3 gap without editing M3): M3
// never validates that `credentialSubject.scope` values are finite — a
// hand-crafted JWT with a literal `1e400` decodes to a real `Infinity`
// (the normal issuance path closes this only by accident:
// `JSON.stringify(Infinity)` produces `null`, which a `typeof` guard
// then excludes — not a deliberate check). Since M3 is frozen, this
// fixture simulates "what if a scope value WAS non-finite" directly (the
// way `type-boundary.test.ts` already builds hand-constructed
// `AuthorityEnvelope`/rule fixtures to test arithmetic in isolation),
// to prove M5 defends anyway: a non-finite bound refuses, never permits.
// ---------------------------------------------------------------------
function fabricatedAcceptedAuthority(scope: Record<string, number>): TrustDecision<AuthorityCredential> & { readonly accepted: true } {
  const issuer = makeIdentity();
  const subject = makeIdentity();
  return {
    accepted: true,
    reason: "fabricated fixture for FINDING 8 — simulates a scope value M3 never validates as finite",
    credentialVerification: {
      ok: true,
      credential: { credentialSubject: { id: subject.did, action: "purchase", scope } },
      verifiedIssuer: issuer.did,
      verifiedSubject: subject.did,
      verifiedAt: 0,
      revocationChecked: false,
    },
    issuerTrust: { trusted: true, issuer: issuer.did, reason: { kind: "direct-anchor" } },
    revocation: { outcome: "not-checked", reason: "fabricated fixture; revocation is irrelevant to this test" },
  } as unknown as TrustDecision<AuthorityCredential> & { readonly accepted: true };
}

describe("evaluatePolicyRequest — a non-finite bound refuses rather than permits (FINDING 3 / FINDING 8)", () => {
  const permissivePolicy: Policy = {
    id: "policy-nonfinite-fixture",
    version: "1.0.0",
    revocationHandling: { requireChecked: false, acknowledgedBy: "test-fixture", reason: "no status list wired up in this fixture" },
    rules: [{ kind: ACTION_SCOPE_RULE_KIND, id: "R-purchase", description: "purchase ceiling", action: "purchase", maxScope: {} }],
  };

  it("an Infinity scope value on the authority credential itself refuses, never permits", () => {
    const authority = fabricatedAcceptedAuthority({ maxAmount: Number.POSITIVE_INFINITY });

    const decision = record(evaluatePolicyRequest({ policy: permissivePolicy, request: { action: "purchase", scope: { maxAmount: 1_000_000 } }, authority, history: [] }));

    expect(decision.permitted).toBe(false);
    if (decision.permitted) throw new Error("expected refusal — a non-finite ceiling must never read as unconditional permission");
    expect(decision.explanation.refusalKind).toBe("over-scope");
    expectNonEmptyExplanation(decision);
  });

  it("a non-finite REQUESTED value refuses, never compared as \"within\" any ceiling", () => {
    const authority = fabricatedAcceptedAuthority({ maxAmount: 500 });

    const decision = record(
      evaluatePolicyRequest({ policy: permissivePolicy, request: { action: "purchase", scope: { maxAmount: Number.POSITIVE_INFINITY } }, authority, history: [] }),
    );

    expect(decision.permitted).toBe(false);
    if (decision.permitted) throw new Error("expected refusal — a non-finite requested value must never read as within scope");
    expect(decision.explanation.refusalKind).toBe("over-scope");
    expectNonEmptyExplanation(decision);
  });
});
