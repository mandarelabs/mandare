/**
 * @mandarelabs/policy-engine (Apache-2.0) — the mandate enforcement point,
 * embeddable in third-party gateways and frameworks.
 *
 * The interface is deliberately Cedar-shaped — (principal, action, resource,
 * context) → decision (BUILD-DECISIONS Q9) — so portable scope policies can
 * move to cedar-wasm post-MVP. Budgets and velocity are STATEFUL and
 * quantitative; the real engine (S2) decrements counters in the same DB
 * transaction as the ledger write. Cedar/OPA cannot do that, hence custom.
 */

export interface PolicyRequest {
  /** Agent DID asking to act. */
  principal: string;
  /** Namespaced action, e.g. 'llm.call'. */
  action: string;
  /** What it wants to touch, e.g. a model id or counterparty. */
  resource: string;
  /** Quantitative context: estimated cost in micros, currency, task id… */
  context: Readonly<Record<string, unknown>>;
}

export interface PolicyDecision {
  decision: 'allow' | 'deny';
  /** Human-readable reasons — these end up in approval pushes and audit output. */
  reasons: readonly string[];
}

export interface PolicyEngine {
  /**
   * Callers MUST fail closed (rule R1): treat a thrown error exactly like a
   * deny — if the engine cannot answer, nothing moves.
   */
  evaluate(request: PolicyRequest): Promise<PolicyDecision>;
}

/**
 * S0 placeholder: allows everything, loudly labeled. It exists so every door
 * wires the enforcement call-site and its fail-closed handling NOW; S2
 * replaces it with the budget/velocity engine evaluating real mandates.
 * Deliberately NOT named "default" anything — using it in production should
 * look as wrong as it is.
 */
export class UnconfiguredPolicyEngine implements PolicyEngine {
  evaluate(request: PolicyRequest): Promise<PolicyDecision> {
    return Promise.resolve({
      decision: 'allow',
      reasons: [
        `policy engine not configured (S0 walking skeleton) — allowing ${request.action} on ${request.resource} unchecked`,
      ],
    });
  }
}
