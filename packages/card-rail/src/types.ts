import type {
  AppendInput,
  AppendProjectedResult,
  ProjectionRunner,
  Projector,
} from '@mandarelabs/ledger';
import type { PolicyEngine } from '@mandarelabs/policy-engine';
import type { MandateV1 } from '@mandarelabs/spec';

import type { CardRegistry } from './registry.js';
import type { StripeClient } from './stripe-client.js';
import type { WaiverStore } from './waivers.js';

/** The ledger surface the card door needs — same narrow shape as the gateway. */
export interface CardLedgerWriter extends ProjectionRunner {
  appendProjected(input: AppendInput, project: Projector): Promise<AppendProjectedResult>;
}

/**
 * The S4 approval primitive, structurally (the gateway passes its own
 * ApprovalService + Notifier instances — one approval surface, two rails;
 * decisions land on the gateway's existing POST /approvals/:id endpoint).
 */
export interface CardApprovalChannel {
  create(input: {
    requestHash: string;
    estimateMicros: number;
    currency: string;
    model: string;
    target: string;
    actor: string;
    mandateId: string;
    thresholdMicros: number;
  }): {
    id: string;
    approveToken: string;
    denyToken: string;
    expiresAtIso: string;
    outcome: Promise<'approved' | 'denied' | 'timeout'>;
  };
  pendingCount(): number;
}

export interface CardNotifier {
  send(notification: {
    approvalId: string;
    title: string;
    message: string;
    approveUrl: string;
    denyUrl: string;
    approveBody: string;
    denyBody: string;
    expiresAt: string;
  }): Promise<void>;
}

/**
 * Authentication for the card-CREATION route, provided by the door that
 * mounts the rail (the gateway owns auth modes — token PoP, passport, or
 * localhost 'none'). The webhook route never uses this: its caller is
 * Stripe, authenticated by the webhook signature alone.
 */
export type CreateAuthenticator = (request: unknown) => Promise<
  | { ok: true; actor: string }
  | { ok: false; status: number; body: { error: string; code?: string } }
>;

export interface CardRailConfig {
  doorId: string;
  ledgerCurrency: string;
  maxIntentsPerMinute: number;
  maxPendingApprovals: number;
  /** Base URL the approval push buttons POST back to (gateway /approvals). */
  approvalBaseUrl: string;
  /** Stripe webhook signing secret — MANDATORY for the webhook route. */
  webhookSecret: string;
  webhookToleranceSeconds: number;
  /** How long a granted step-up waiver stays redeemable. */
  waiverTtlMs: number;
  /** Issuing cardholder the door creates cards under; null = creation closed. */
  cardholderId: string | null;
}

export interface CardRailDeps {
  config: CardRailConfig;
  ledger: CardLedgerWriter;
  /** Card-rail policy engine (SPEC §5 order over the 'card' spend scope). */
  policy: PolicyEngine;
  mandate: MandateV1;
  /** null = card creation/cancel unavailable; webhook decisions still work. */
  stripe: StripeClient | null;
  approvals: CardApprovalChannel;
  notifier?: CardNotifier;
  waivers: WaiverStore;
  authenticateCreate: CreateAuthenticator;
  /** Test override; defaults to a registry rebuilt from the ledger. */
  registry?: CardRegistry;
  clock?: () => Date;
}
