import { readFileSync } from 'node:fs';

import { parseMandate, type MandateV1 } from '@mandarelabs/spec';
import { verifyMandateVc } from '@mandarelabs/passport';

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
 * Door-local authentication mode for the spend routes. `token` requires a
 * vault-issued proof-of-possession token (S3); `none` is the S2
 * localhost-only behavior; `auto` (default) requires a token IFF a vault is
 * wired — "if you have a vault, the door authenticates." `passport` (S4)
 * requires an RFC 9421 request signature by the agent key a verified
 * delegation credential binds — real actor identity, not just an authorized
 * holder; it needs MANDARE_TRUST_AUTHORITY (the attestation authority DID).
 */
export type GatewayAuthMode = 'auto' | 'token' | 'none' | 'passport';

/** Approval push channel (Q10/Q19): ntfy default, file for CI/demos. */
export type NotifierKind = 'none' | 'ntfy' | 'file';

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
  /**
   * The attestation authority DID this door trusts (passport mode). null =
   * passport auth cannot verify any delegation chain → fail closed.
   */
  trustedAuthorityDid: string | null;
  /** Approval push channel; 'none' = above-threshold calls are denied (S2 behavior). */
  notifier: NotifierKind;
  ntfyUrl: string;
  ntfyTopic: string | null;
  notifyFilePath: string | null;
  /** How long a held call waits for the human before fail-closed denial. */
  approvalTimeoutMs: number;
  /** Max calls held awaiting a human decision at once (flood/notification-fatigue guard). */
  maxPendingApprovals: number;
  /** Base URL the approval action buttons POST back to (reachability is deployment-specific). */
  publicBaseUrl: string | null;
  anthropic: ProviderEndpoint;
  openai: ProviderEndpoint;
  openrouter: ProviderEndpoint;
  /** Which provider serves /v1/chat/completions. */
  chatProvider: 'openrouter' | 'openai';
  /**
   * Card rail (S5, Q11). The rail mounts IFF a webhook secret is present —
   * signature verification is mandatory, so without the secret there is no
   * webhook route at all (fail-closed, not fail-open).
   */
  stripe: {
    /** API key for card creation/cancel; null = those ops stay closed. */
    apiKey: string | null;
    /** Webhook signing secret; null = the card rail does not mount. */
    webhookSecret: string | null;
    /** Injectable base URL: mock server in CI, api.stripe.com live. */
    apiBase: string;
    /** Optional pinned Stripe-Version for outbound calls. */
    apiVersion: string | null;
    /** Issuing cardholder new cards belong to; null = creation closed. */
    cardholderId: string | null;
    webhookToleranceSeconds: number;
    /** How long a granted step-up waiver stays redeemable (ms). */
    waiverTtlMs: number;
  };
}

const DEFAULT_PORT = 8484;
const DEFAULT_MAX_INTENTS_PER_MINUTE = 60;
const DEFAULT_APPROVAL_TIMEOUT_MS = 120_000;
const DEFAULT_MAX_PENDING_APPROVALS = 8;
const DEFAULT_NTFY_URL = 'https://ntfy.sh';
const DEFAULT_STRIPE_API_BASE = 'https://api.stripe.com';
const DEFAULT_WEBHOOK_TOLERANCE_SECONDS = 300;
const DEFAULT_CARD_WAIVER_TTL_MS = 10 * 60_000;

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
  if (
    authModeRaw !== 'auto' &&
    authModeRaw !== 'token' &&
    authModeRaw !== 'none' &&
    authModeRaw !== 'passport'
  ) {
    throw new Error(
      `invalid MANDARE_GATEWAY_AUTH: ${authModeRaw} (expected 'auto', 'token', 'none', or 'passport')`
    );
  }
  const notifierRaw = env.MANDARE_NOTIFIER ?? 'none';
  if (notifierRaw !== 'none' && notifierRaw !== 'ntfy' && notifierRaw !== 'file') {
    throw new Error(`invalid MANDARE_NOTIFIER: ${notifierRaw} (expected 'none', 'ntfy', or 'file')`);
  }
  const approvalTimeoutMs =
    env.MANDARE_APPROVAL_TIMEOUT_MS === undefined
      ? DEFAULT_APPROVAL_TIMEOUT_MS
      : Number(env.MANDARE_APPROVAL_TIMEOUT_MS);
  if (!Number.isInteger(approvalTimeoutMs) || approvalTimeoutMs < 1_000) {
    throw new Error('invalid MANDARE_APPROVAL_TIMEOUT_MS: must be an integer ≥ 1000');
  }
  const maxPendingApprovals =
    env.MANDARE_MAX_PENDING_APPROVALS === undefined
      ? DEFAULT_MAX_PENDING_APPROVALS
      : Number(env.MANDARE_MAX_PENDING_APPROVALS);
  if (!Number.isInteger(maxPendingApprovals) || maxPendingApprovals < 1) {
    throw new Error('invalid MANDARE_MAX_PENDING_APPROVALS: must be a positive integer');
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
    trustedAuthorityDid: env.MANDARE_TRUST_AUTHORITY ?? null,
    notifier: notifierRaw,
    ntfyUrl: env.MANDARE_NTFY_URL ?? DEFAULT_NTFY_URL,
    ntfyTopic: env.MANDARE_NTFY_TOPIC ?? null,
    notifyFilePath: env.MANDARE_NOTIFY_FILE ?? null,
    approvalTimeoutMs,
    maxPendingApprovals,
    publicBaseUrl: env.MANDARE_GATEWAY_PUBLIC_URL ?? null,
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
    stripe: {
      apiKey: env.STRIPE_SECRET_KEY ?? null,
      webhookSecret: env.STRIPE_WEBHOOK_SECRET ?? null,
      apiBase: stripSlashes(env.STRIPE_API_BASE ?? DEFAULT_STRIPE_API_BASE),
      apiVersion: env.STRIPE_API_VERSION ?? null,
      cardholderId: env.STRIPE_CARDHOLDER_ID ?? null,
      webhookToleranceSeconds: parseWebhookTolerance(env.STRIPE_WEBHOOK_TOLERANCE_SECONDS),
      waiverTtlMs: parseWaiverTtl(env.MANDARE_CARD_WAIVER_TTL_MS),
    },
  };
}

function parseWebhookTolerance(raw: string | undefined): number {
  if (raw === undefined || raw === '') {
    return DEFAULT_WEBHOOK_TOLERANCE_SECONDS;
  }
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 1) {
    throw new Error('invalid STRIPE_WEBHOOK_TOLERANCE_SECONDS: must be a positive integer');
  }
  return value;
}

function parseWaiverTtl(raw: string | undefined): number {
  if (raw === undefined || raw === '') {
    return DEFAULT_CARD_WAIVER_TTL_MS;
  }
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 1_000) {
    throw new Error('invalid MANDARE_CARD_WAIVER_TTL_MS: must be an integer ≥ 1000');
  }
  return value;
}

/**
 * Load the mandate the gateway enforces.
 *
 * - SD-JWT VC file (S4, the real path): FULL verification — envelope owner
 *   signature (key derived from the principal's did:key), frozen-schema
 *   parse, and the detached owner signature over the canonical payload. A
 *   mandate that does not verify does not load (R1).
 * - Legacy JSON file (S0–S3 dev mandates, frozen demos): schema validation
 *   only — the operator-configured file is trusted, as documented since S2.
 *   Legacy principals are not did:key, so there is no key to verify against.
 */
export async function loadMandate(path: string): Promise<MandateV1> {
  const content = readFileSync(path, 'utf8').trim();
  if (content.startsWith('{')) {
    return parseMandate(JSON.parse(content));
  }
  return verifyMandateVc(content);
}
