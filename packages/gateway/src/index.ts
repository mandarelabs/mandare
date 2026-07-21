/**
 * @mandarelabs/gateway — local LLM proxy door (AGPL-3.0-only).
 */

export { buildGateway } from './server.js';
export type { GatewayDeps, LedgerWriter } from './server.js';
export { loadConfigFromEnv } from './config.js';
export type { GatewayConfig } from './config.js';
export { forwardChatCompletion } from './openrouter.js';
export type { FetchLike, ProviderResponse, ProviderUsage } from './openrouter.js';
