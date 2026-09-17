"use client";

import { useState } from "react";
import { BeatCard } from "./BeatCard";
import type { AttackKind, CustomNegotiationDto } from "../lib/negotiation-service.js";

/**
 * The one interactive control M8 requires: a viewer picks a requested
 * amount and, optionally, an attack to mount, and this POSTs to
 * `/api/negotiate` — a real Next.js Route Handler that runs the actual
 * `lib/negotiation` protocol (see that route's own module comment for
 * why it must run server-side) and returns a real decision. Nothing
 * here computes a verdict; this component only sends the request and
 * renders whatever `NegotiationDecision` comes back, via the same
 * `BeatCard` the fixed four beats use.
 *
 * Only TYPES are imported from `negotiation-service.ts` (erased at
 * compile time) — no negotiation code, and therefore no `node:zlib`,
 * ever ships to the browser from this file.
 */
const ATTACK_OPTIONS: ReadonlyArray<{ readonly value: AttackKind; readonly label: string; readonly hint: string }> = [
  { value: "none", label: "Honest buyer", hint: "presents its own, real credential and proves its own DID" },
  { value: "spoof-did", label: "Impostor — spoof the buyer's DID", hint: "signs with its OWN key while claiming the buyer's DID" },
  { value: "forge-credential", label: "Attacker — forge a credential", hint: "mints itself a credential; genuinely valid signature, self-issued" },
  { value: "revoked-credential", label: "Buyer — present a revoked credential", hint: "a real, otherwise-valid credential whose status list marks it revoked" },
];

const PRESETS: ReadonlyArray<{ readonly label: string; readonly amount: number }> = [
  { label: "150 (within scope)", amount: 150 },
  { label: "5,000 (over scope)", amount: 5000 },
  { label: "−500 (negative)", amount: -500 },
];

export function InteractivePanel() {
  const [amount, setAmount] = useState<number>(150);
  const [attack, setAttack] = useState<AttackKind>("none");
  const [result, setResult] = useState<CustomNegotiationDto | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function evaluate() {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch("/api/negotiate", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ amount, attack }),
      });
      if (!response.ok) {
        const body: unknown = await response.json().catch(() => ({}));
        const message = typeof body === "object" && body !== null && "error" in body ? String((body as { error: unknown }).error) : `request failed (${response.status})`;
        throw new Error(message);
      }
      const data = (await response.json()) as CustomNegotiationDto;
      setResult(data);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
      setResult(null);
    } finally {
      setLoading(false);
    }
  }

  return (
    <section aria-labelledby="try-it-heading" className="panel">
      <h2 id="try-it-heading">Make your own decision</h2>
      <p className="panel-lede">
        Pick an amount and, optionally, an attack to mount. This calls the same Supplier code as the four beats above &mdash; a real
        decision, not a lookup table.
      </p>

      <div className="control-row">
        <label className="control" htmlFor="amount-input">
          <span>requested amount</span>
          <input
            id="amount-input"
            type="number"
            inputMode="numeric"
            value={amount}
            onChange={(event) => setAmount(event.target.valueAsNumber)}
            className="tabular"
          />
        </label>
        <div className="preset-row">
          {PRESETS.map((preset) => (
            <button key={preset.label} type="button" className="preset-button" onClick={() => setAmount(preset.amount)}>
              {preset.label}
            </button>
          ))}
        </div>
      </div>

      <fieldset className="attack-fieldset">
        <legend>present as</legend>
        {ATTACK_OPTIONS.map((option) => (
          <label key={option.value} className="attack-option">
            <input type="radio" name="attack" value={option.value} checked={attack === option.value} onChange={() => setAttack(option.value)} />
            <span>
              <strong>{option.label}</strong>
              <span className="attack-hint"> &mdash; {option.hint}</span>
            </span>
          </label>
        ))}
      </fieldset>

      <button type="button" className="evaluate-button" onClick={evaluate} disabled={loading || !Number.isFinite(amount)}>
        {loading ? "Evaluating…" : "Evaluate this request"}
      </button>

      {error !== null ? <p className="panel-error" role="alert">{error}</p> : null}

      {result !== null ? (
        <div className="panel-result">
          <BeatCard
            title="Your request"
            asker={result.asker}
            askedFor={result.askedFor}
            decision={result.decision}
            realOwnerOfClaimedDid={result.attack === "spoof-did" ? result.cast.buyerDid : undefined}
            realOwnerLabel="buyer's real DID"
          />
        </div>
      ) : null}
    </section>
  );
}
