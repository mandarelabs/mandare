/**
 * Cedar-shaped evaluation interface (BUILD-DECISIONS Q9): (principal, action,
 * resource, context) → decision. Portable scope policies can move to
 * cedar-wasm post-MVP without reshaping call sites.
 */

export interface PolicyRequest {
  /** Agent DID asking to act. */
  principal: string;
  /** Namespaced action, e.g. 'llm.call'. */
  action: string;
  /** What it wants to touch, e.g. a model id or counterparty. */
  resource: string;
  /** Quantitative context: estimated cost in micros, currency, counters… */
  context: Readonly<Record<string, unknown>>;
}

export interface PolicyDecision {
  decision: 'allow' | 'deny';
  /** Human-readable reasons — these end up in approval pushes and audit output. */
  reasons: readonly string[];
  /** Machine-readable refusal code, present on deny. */
  code?: string;
}

export interface PolicyEngine {
  /**
   * Callers MUST fail closed (rule R1): treat a thrown error exactly like a
   * deny — if the engine cannot answer, nothing moves.
   */
  evaluate(request: PolicyRequest): Promise<PolicyDecision>;
}
