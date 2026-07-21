import { readFileSync } from 'node:fs';

import { parseMandate, type MandateV1 } from '@mandarelabs/spec';

/**
 * Gateway configuration from environment. Provider keys come from env in S2
 * — S3 moves credentials into the vault (agents never see them, and neither
 * does the environment of anything agent-reachable). R2 applies everywhere:
 * keys must never appear in logs, errors, or ledger entries.
 */

export interface ProviderEndpoint {
  baseUrl: string;
  /** null = no credential → that provider's spend path stays closed (R1). */
  apiKey: string | null;
}

/**
 * Door-local authentication mode for the spend routes (S3, closing the S2
 * review's deferred MEDIUM). `token` requires a vault-issued proof-of-
 * possession token; `none` is the S2 localhost-only behavior; `auto`
 * (default) requires a token IFF a vault is wired — "if you have a vault, the
 * door authenticates." Full actor identity is still S4 (passports): a valid
 * token proves an authorized holder minted it for this door, not yet WHO.
 */
export type GatewayAuthMode = 'auto' | 'token' | 'none';

export interface GatewayConfig {
  host: string;
  port: number;
  ledgerDbPath: string;
  doorId: string;
  /** S2: static door actor identity; real passports land in S4. */
  actor: string;
  /** Spend-route auth mode (see GatewayAuthMode). */
  authMode: GatewayAuthMode;
  /**
   * Extra Host-header values allowed on top of the localhost defaults
   * (DNS-rebinding defense). The gateway is a local door; a browser tricked
   * into POSTing to a rebound hostname must not reach the spend routes.
   */
  allowedHosts: string[];
  /** Path to the mandate JSON; null = NO mandate → spend path closed (R1). */
  mandatePath: string | null;
  /** Currency every ledger cost/budget is denominated in. */
  ledgerCurrency: string;
  /**
   * How many USD one ledger-currency unit buys (e.g. 1.16 for EUR). Fixed,
   * operator-set, auditable. null with a non-USD ledger currency = cannot
   * convert provider USD costs → spend path closed. Never defaulted.
   */
  usdPerLedgerUnit: number | null;
  maxIntentsPerMinute: number;
  /** Optional operator pricing table (JSON) merged over the defaults. */
  pricingPath: string | null;
  anthropic: ProviderEndpoint;
  openai: ProviderEndpoint;
  openrouter: ProviderEndpoint;
  /** Which provider serves /v1/chat/completions. */
  chatProvider: 'openrouter' | 'openai';
}

const DEFAULT_PORT = 8484;
const DEFAULT_MAX_INTENTS_PER_MINUTE = 60;

function stripSlashes(url: string): string {
  return url.replace(/\/+$/, '');
}

function positiveNumber(raw: string | undefined, name: string): number | null {
  if (raw === undefined || raw === '') {
    return null;
  }
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`invalid ${name}: must be a positive number`);
  }
  return value;
}

export function loadConfigFromEnv(env: Record<string, string | undefined>): GatewayConfig {
  const port = env.MANDARE_GATEWAY_PORT === undefined ? DEFAULT_PORT : Number(env.MANDARE_GATEWAY_PORT);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error(`invalid MANDARE_GATEWAY_PORT: ${env.MANDARE_GATEWAY_PORT}`);
  }
  const maxPerMinute =
    env.MANDARE_MAX_CALLS_PER_MINUTE === undefined
      ? DEFAULT_MAX_INTENTS_PER_MINUTE
      : Number(env.MANDARE_MAX_CALLS_PER_MINUTE);
  if (!Number.isInteger(maxPerMinute) || maxPerMinute < 1) {
    throw new Error('invalid MANDARE_MAX_CALLS_PER_MINUTE: must be a positive integer');
  }
  const ledgerCurrency = env.MANDARE_LEDGER_CURRENCY ?? 'EUR';
  if (!/^[A-Z]{3}$/.test(ledgerCurrency)) {
    throw new Error(`invalid MANDARE_LEDGER_CURRENCY: ${env.MANDARE_LEDGER_CURRENCY}`);
  }
  // USD ledgers convert 1:1 by definition; anything else needs an explicit,
  // operator-audited rate — Mandare never invents an FX rate (R1).
  const usdPerLedgerUnit =
    ledgerCurrency === 'USD'
      ? 1
      : positiveNumber(env.MANDARE_USD_PER_LEDGER_UNIT, 'MANDARE_USD_PER_LEDGER_UNIT');

  const authModeRaw = env.MANDARE_GATEWAY_AUTH ?? 'auto';
  if (authModeRaw !== 'auto' && authModeRaw !== 'token' && authModeRaw !== 'none') {
    throw new Error(`invalid MANDARE_GATEWAY_AUTH: ${authModeRaw} (expected 'auto', 'token', or 'none')`);
  }
  const allowedHosts = (env.MANDARE_GATEWAY_ALLOWED_HOSTS ?? '')
    .split(',')
    .map((host) => host.trim().toLowerCase())
    .filter((host) => host.length > 0);

  const openrouterKey = env.OPENROUTER_API_KEY ?? null;
  const chatProvider =
    env.MANDARE_CHAT_PROVIDER === 'openai' || env.MANDARE_CHAT_PROVIDER === 'openrouter'
      ? env.MANDARE_CHAT_PROVIDER
      : openrouterKey !== null
        ? 'openrouter'
        : 'openai';

  return {
    // Localhost by design: the gateway is a local door, not a public service.
    host: env.MANDARE_GATEWAY_HOST ?? '127.0.0.1',
    port,
    ledgerDbPath: env.MANDARE_LEDGER_DB ?? './mandare-ledger.db',
    doorId: env.MANDARE_DOOR_ID ?? 'gateway:local',
    actor: env.MANDARE_ACTOR ?? 'did:mandare:dev-agent',
    authMode: authModeRaw,
    allowedHosts,
    mandatePath: env.MANDARE_MANDATE_PATH ?? null,
    ledgerCurrency,
    usdPerLedgerUnit,
    maxIntentsPerMinute: maxPerMinute,
    pricingPath: env.MANDARE_PRICING_PATH ?? null,
    // Base-URL conventions follow each provider's own SDK: Anthropic's
    // ANTHROPIC_BASE_URL excludes /v1 (the adapter path carries it), while
    // OpenAI/OpenRouter base URLs include their /v1.
    anthropic: {
      baseUrl: stripSlashes(env.ANTHROPIC_BASE_URL ?? 'https://api.anthropic.com'),
      apiKey: env.ANTHROPIC_API_KEY ?? null,
    },
    openai: {
      baseUrl: stripSlashes(env.OPENAI_BASE_URL ?? 'https://api.openai.com/v1'),
      apiKey: env.OPENAI_API_KEY ?? null,
    },
    openrouter: {
      baseUrl: stripSlashes(env.OPENROUTER_BASE_URL ?? 'https://openrouter.ai/api/v1'),
      apiKey: openrouterKey,
    },
    chatProvider,
  };
}

/**
 * Load and schema-validate the mandate the gateway enforces. v0 trusts the
 * operator-configured file (owner-signature verification arrives with
 * SD-JWT transport in S4); schema validation still applies in full (R4).
 */
export function loadMandate(path: string): MandateV1 {
  return parseMandate(JSON.parse(readFileSync(path, 'utf8')));
}
