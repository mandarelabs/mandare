/**
 * @mandarelabs/card-rail — the Stripe Issuing door (AGPL-3.0-only).
 *
 * Mounted onto the gateway's Fastify app (one door process, one door key,
 * one ledger): mandate-checked virtual-card creation, and real-time
 * `issuing_authorization.request` decisions that reserve/settle into the
 * SAME budget projection as LLM spend — one mandate, one cap, both rails.
 */

export { registerCardRail, CARD_CREATE_FAILED } from './routes.js';
export type { CardRailStatus } from './routes.js';
export type {
  CardApprovalChannel,
  CardLedgerWriter,
  CardNotifier,
  CardRailConfig,
  CardRailDeps,
  CreateAuthenticator,
} from './types.js';
export { StripeClient, StripeApiError, encodeForm } from './stripe-client.js';
export type { StripeCard, StripeCardholder } from './stripe-client.js';
export {
  DEFAULT_TOLERANCE_SECONDS,
  signStripePayload,
  verifyStripeSignature,
} from './webhook-signature.js';
export type { WebhookVerifyFailure, WebhookVerifyResult } from './webhook-signature.js';
export {
  authorizationRequestHash,
  decisionResponseHash,
  isPartialableRefusal,
  maxApprovableMicros,
  parseAuthorizationEvent,
} from './authorization.js';
export type { AuthorizationRequest } from './authorization.js';
export {
  CARD_CREATE_DENIED,
  CARD_CREATE_INTENT,
  CARD_CREATE_RESULT,
  CardRegistry,
} from './registry.js';
export type { CardBinding } from './registry.js';
export { WaiverStore } from './waivers.js';
export type { ApprovalWaiver } from './waivers.js';
export {
  MICROS_PER_MINOR_UNIT,
  isSupportedCardCurrency,
  microsToMinorUnitsFloor,
  minorUnitsToMicros,
} from './amounts.js';
