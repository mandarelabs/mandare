/**
 * @mandarelabs/gateway — local LLM proxy door (AGPL-3.0-only).
 */

export { buildGateway } from './server.js';
export type { GatewayDeps, SpendLedgerWriter } from './server.js';
export { loadConfigFromEnv, loadMandate } from './config.js';
export type { GatewayConfig, ProviderEndpoint } from './config.js';
export {
  DEFAULT_PRICING,
  REQUEST_OVERHEAD_TOKENS,
  costUsdMicros,
  estimateRequest,
  estimateTokensFromUtf8Bytes,
  estimateUsdMicros,
  findPricing,
  loadPricingTable,
  usdMicrosToLedgerMicros,
} from './pricing.js';
export type { ModelPricing, RequestEstimate, UsageTokens } from './pricing.js';
export { planReservation } from './reservation.js';
export type { ReservationPlan } from './reservation.js';
export { anthropicAdapter } from './providers/anthropic.js';
export { createOpenAiLikeAdapter, openaiAdapter, openrouterAdapter } from './providers/openai-like.js';
export type {
  FetchLike,
  ParsedUsage,
  ProfileResult,
  ProviderAdapter,
  ProviderName,
  RequestProfile,
  StreamUsageParser,
} from './providers/types.js';
export { SseParser } from './sse.js';
export type { SseEvent } from './sse.js';
export { ApprovalService, FileNotifier, NtfyNotifier } from './approvals.js';
export type {
  ApprovalOutcome,
  ApprovalRequestNotification,
  CreatedApproval,
  Notifier,
  PendingApprovalInput,
} from './approvals.js';
export {
  OpenRouterProvisioningClient,
  OpenRouterProvisioningError,
} from './provisioning.js';
export type { AgentKeySpec, ProvisionedKey } from './provisioning.js';
