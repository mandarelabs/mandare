import { createHash } from 'node:crypto';

import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import { Type } from '@sinclair/typebox';

import {
  LLM_CALL_INTENT,
  LLM_CALL_RESULT,
  canonicalJson,
  sha256Hex,
  type LedgerEntryV1,
  type MandateV1,
} from '@mandarelabs/spec';
import {
  APPROVAL_DENIED,
  APPROVAL_EXPIRED,
  APPROVAL_GRANTED,
  APPROVAL_REQUESTED,
  LLM_CALL_DENIED,
  agentSubject,
  doorSubject,
  mandateSubject,
  readSpendSnapshot,
  spendProjector,
  type AppendInput,
  type AppendProjectedResult,
  type ProjectionRunner,
  type Projector,
  type RevocationRecord,
  type SpendGuardView,
} from '@mandarelabs/ledger';
import { InMemoryNonceStore, isDidKey, type NonceStore } from '@mandarelabs/passport';
import {
  MandatePolicyEngine,
  checkBudgets,
  selectGatewaySpendScope,
  spendLimitsFromScope,
  type PolicyEngine,
} from '@mandarelabs/policy-engine';
import { StripeClient, WaiverStore, registerCardRail } from '@mandarelabs/card-rail';
import type { CardRailStatus, CreateAuthenticator } from '@mandarelabs/card-rail';
import type { SpendScope } from '@mandarelabs/spec';

import type { GatewayConfig, ProviderEndpoint } from './config.js';
import { ApprovalService, type Notifier } from './approvals.js';
import {
  buildAllowedHosts,
  extractRequestClaims,
  isHostAllowed,
  type GatewayVault,
} from './auth.js';
import { authenticatePassportRequest } from './passport-auth.js';
import {
  estimateUsdMicros,
  findPricing,
  costUsdMicros,
  estimateTokensFromChars,
  usdMicrosToLedgerMicros,
  DEFAULT_PRICING,
  type ModelPricing,
} from './pricing.js';
import { anthropicAdapter } from './providers/anthropic.js';
import { openaiAdapter, openrouterAdapter } from './providers/openai-like.js';
import type { FetchLike, ParsedUsage, ProviderAdapter } from './providers/types.js';
import { SseParser } from './sse.js';

/** The ledger surface the gateway needs — narrow so tests can fake it. */
export interface SpendLedgerWriter extends ProjectionRunner {
  appendProjected(input: AppendInput, project: Projector): Promise<AppendProjectedResult>;
}

export interface GatewayDeps {
  config: GatewayConfig;
  ledger: SpendLedgerWriter;
  policy: PolicyEngine;
  /** null = no mandate → the spend path is CLOSED (R1), never allow-all. */
  mandate: MandateV1 | null;
  /**
   * The vault door (S3). When present, spend routes require a valid
   * proof-of-possession token minted by it (unless authMode='none'). When
   * absent, auth falls back to authMode (S2 localhost-only for 'none'/'auto').
   */
  vault?: GatewayVault;
  /**
   * Approval push channel (S4). Absent ⇒ above-threshold calls are DENIED
   * outright (the S2 fail-closed behavior) — no channel, no hold.
   */
  notifier?: Notifier;
  /**
   * Single-use nonce claims for RFC 9421 signatures (passport mode). Wire the
   * vault-backed store in production so door restarts cannot reopen a replay
   * window; defaults to in-memory (tests, dev).
   */
  nonceStore?: NonceStore;
  pricingTable?: readonly ModelPricing[];
  fetchImpl?: FetchLike;
  /** Test hook: production values are the module constants. */
  timeouts?: { nonStreamMs: number; streamIdleMs: number };
}

/**
 * S2 request flow (rules R1/R3/R4 — the shape every later door copies):
 *
 *   validate (R4) → estimate cost → policy check (SPEC §5 order; deny ⇒
 *   DENIED entry + 403) → RESERVE: intent entry carrying the estimate,
 *   budget-guarded inside the SAME ledger transaction (refusal ⇒ DENIED
 *   entry + 403; concurrent overshoot is impossible by construction)
 *   → forward (streaming passes through while a tee parses usage)
 *   → SETTLE: result entry with the true cost releases the reservation
 *   (fails ⇒ gateway HALTS: executed-but-unrecorded is the one state we
 *   refuse to continue from) → response to caller.
 */

const NON_STREAM_TIMEOUT_MS = 120_000;
const STREAM_IDLE_TIMEOUT_MS = 120_000;
/**
 * A killed agent's process may keep looping (SPEC: the process runs, the doors
 * close). We record the kill-refusal for evidence, but coalesce it so a fast
 * loop cannot flood the append-only ledger with one fsync'd DENIED per retry:
 * at most one recorded kill-refusal per this window; the rest are refused
 * without a ledger write.
 */
const REVOKED_DENIED_THROTTLE_MS = 1_000;

const chatCompletionsBodySchema = Type.Object(
  {
    model: Type.String({ minLength: 1 }),
    messages: Type.Array(Type.Unknown(), { minItems: 1 }),
    stream: Type.Optional(Type.Boolean()),
    max_tokens: Type.Optional(Type.Integer({ minimum: 1 })),
    max_completion_tokens: Type.Optional(Type.Integer({ minimum: 1 })),
  },
  { additionalProperties: true }
);

const anthropicMessagesBodySchema = Type.Object(
  {
    model: Type.String({ minLength: 1 }),
    messages: Type.Array(Type.Unknown(), { minItems: 1 }),
    // Anthropic requires max_tokens — which also bounds our reservation.
    max_tokens: Type.Integer({ minimum: 1 }),
    stream: Type.Optional(Type.Boolean()),
  },
  { additionalProperties: true }
);

interface CallPlan {
  adapter: ProviderAdapter;
  endpoint: ProviderEndpoint;
  body: Record<string, unknown>;
  model: string;
  stream: boolean;
  requestHash: string;
  pricing: ModelPricing | null;
  estimateLedgerMicros: number;
  scope: SpendScope;
  usdPerLedgerUnit: number;
}

export function buildGateway(deps: GatewayDeps): FastifyInstance {
  const { config, ledger, policy, mandate, vault, notifier } = deps;
  const pricingTable = deps.pricingTable ?? DEFAULT_PRICING;
  const fetchImpl = deps.fetchImpl ?? (fetch as FetchLike);
  const timeouts = deps.timeouts ?? {
    nonStreamMs: NON_STREAM_TIMEOUT_MS,
    streamIdleMs: STREAM_IDLE_TIMEOUT_MS,
  };
  let halted = false;
  // Last time a kill-refusal was recorded to the ledger (throttle, see above).
  let lastRevokedDeniedAt = 0;
  // Set when the card rail mounts (populated during plugin registration).
  let cardRailStatus: CardRailStatus | null = null;

  // "If you have a vault, the door authenticates." authMode='token' forces it
  // even without a vault (⇒ every spend request fails closed until one is
  // wired); 'none' is the S2 localhost-only behavior; 'passport' (S4)
  // replaces the HMAC token with the passport chain + RFC 9421 signature.
  const passportMode = config.authMode === 'passport';
  const requireToken =
    config.authMode === 'token' || (config.authMode === 'auto' && vault !== undefined);
  const allowedHosts = buildAllowedHosts(config);
  const nonceStore = deps.nonceStore ?? new InMemoryNonceStore();
  const approvals = new ApprovalService(config.approvalTimeoutMs);
  const rawBodies = new WeakMap<object, Buffer>();

  // coerceTypes OFF: this is a policy boundary — `stream: "true"` must be a
  // 400, not a silent boolean (R4; caught by the hostile-input red-team).
  const app = Fastify({ logger: false, ajv: { customOptions: { coerceTypes: false } } });

  if (passportMode) {
    // RFC 9421 Content-Digest must be checked against the EXACT bytes the
    // client signed, so passport mode parses JSON itself and keeps the raw
    // buffer alongside (schema validation still applies to the parsed body).
    app.addContentTypeParser('application/json', { parseAs: 'buffer' }, (request, body, done) => {
      const bytes = body as Buffer;
      rawBodies.set(request, bytes);
      try {
        done(null, JSON.parse(bytes.toString('utf8')));
      } catch {
        const parseError = new Error('body is not valid JSON') as Error & { statusCode: number };
        parseError.statusCode = 400;
        done(parseError, undefined);
      }
    });
  }

  // DNS-rebinding defense: reject any request whose Host header is not a
  // known-local name before it can reach a route (S2 review hardening).
  app.addHook('onRequest', (request, reply, done) => {
    if (!isHostAllowed(request.headers.host, allowedHosts)) {
      reply.code(403).send({ error: 'host not allowed' });
      return;
    }
    done();
  });

  // No raw exception text ever reaches a caller: 5xx bodies are generic
  // (an unaudited error channel is how secrets leak, R2); 4xx keep
  // Fastify's own client-facing messages (validation, parse, body-size).
  app.setErrorHandler((error: { statusCode?: number; message?: string }, request, reply) => {
    const statusCode = typeof error.statusCode === 'number' ? error.statusCode : 500;
    if (statusCode >= 500) {
      request.log?.error?.(error);
      return reply.code(500).send({ error: 'internal error' });
    }
    return reply.code(statusCode).send({ error: error.message ?? 'request error' });
  });

  const spendPathOpen = (): boolean =>
    !halted &&
    mandate !== null &&
    config.usdPerLedgerUnit !== null &&
    (config.anthropic.apiKey !== null ||
      config.openai.apiKey !== null ||
      config.openrouter.apiKey !== null);

  app.get('/healthz', () => ({
    ok: !halted && cardRailStatus?.isHalted() !== true,
    halted,
    door_id: config.doorId,
    mandate_id: mandate?.id ?? null,
    spend_path_open: spendPathOpen(),
    providers: {
      anthropic: config.anthropic.apiKey !== null,
      openai: config.openai.apiKey !== null,
      openrouter: config.openrouter.apiKey !== null,
    },
    card_rail:
      cardRailStatus === null
        ? { mounted: false }
        : {
            mounted: true,
            halted: cardRailStatus.isHalted(),
            registered_cards: cardRailStatus.registeredCards(),
          },
  }));

  // Human decision endpoint — the target of the push's Approve/Deny action
  // buttons. Auth here is the single-use capability token from the push
  // itself (constant-time compared, hash-stored, bound to one approval, dead
  // after first use); agent tokens/passports play no role — the HUMAN decides.
  app.post(
    '/approvals/:id',
    {
      schema: {
        params: Type.Object({ id: Type.String({ minLength: 1 }) }, { additionalProperties: false }),
        body: Type.Object({ token: Type.String({ minLength: 1 }) }, { additionalProperties: false }),
      },
    },
    async (request, reply) => {
      const { id } = request.params as { id: string };
      const { token } = request.body as { token: string };
      const result = approvals.decide(id, token);
      if (!result.ok) {
        const status =
          result.refusal === 'UNKNOWN_APPROVAL' ? 404 : result.refusal === 'ALREADY_DECIDED' ? 409 : 403;
        return reply.code(status).send({ error: 'approval decision rejected', code: result.refusal });
      }
      return reply.send({ ok: true, decision: result.outcome });
    }
  );

  app.post(
    '/v1/chat/completions',
    { schema: { body: chatCompletionsBodySchema } },
    async (request, reply) => {
      const chat = config.chatProvider === 'openrouter' ? config.openrouter : config.openai;
      const adapter = config.chatProvider === 'openrouter' ? openrouterAdapter : openaiAdapter;
      return handleLlmCall(adapter, chat, request, reply);
    }
  );

  app.post(
    '/v1/messages',
    { schema: { body: anthropicMessagesBodySchema } },
    async (request, reply) => handleLlmCall(anthropicAdapter, config.anthropic, request, reply)
  );

  // Card-creation authentication: the gateway owns the auth modes, so the
  // card rail borrows them. Same order and checks as the spend routes; the
  // webhook route never uses this (Stripe is authenticated by signature).
  const authenticateCreate: CreateAuthenticator = async (requestRaw) => {
    const request = requestRaw as FastifyRequest;
    if (passportMode) {
      if (config.trustedAuthorityDid === null) {
        return {
          ok: false,
          status: 503,
          body: { error: 'passport auth requires MANDARE_TRUST_AUTHORITY — refusing (fail-closed)' },
        };
      }
      const auth = await authenticatePassportRequest({
        request,
        rawBody: rawBodies.get(request) ?? Buffer.alloc(0),
        trustedAuthorityDid: config.trustedAuthorityDid,
        nonceStore,
      });
      if (!auth.ok) {
        return {
          ok: false,
          status: auth.refusal.status,
          body: { error: 'passport rejected', code: auth.refusal.code },
        };
      }
      if (
        mandate !== null &&
        isDidKey(mandate.principal) &&
        auth.passport.ownerDid !== mandate.principal
      ) {
        return { ok: false, status: 403, body: { error: 'passport rejected', code: 'OWNER_MISMATCH' } };
      }
      if (mandate !== null && auth.passport.mandateRef !== null && auth.passport.mandateRef !== mandate.id) {
        return { ok: false, status: 403, body: { error: 'passport rejected', code: 'MANDATE_MISMATCH' } };
      }
      return { ok: true, actor: auth.passport.agentDid };
    }
    if (requireToken) {
      if (vault === undefined) {
        return {
          ok: false,
          status: 503,
          body: { error: 'token auth required but no vault is configured — refusing (fail-closed)' },
        };
      }
      const claims = extractRequestClaims(request);
      if (claims === null) {
        return {
          ok: false,
          status: 401,
          body: { error: 'missing proof-of-possession token headers (x-mandare-token/timestamp/nonce/pop)' },
        };
      }
      const verdict = vault.verifyRequest(claims);
      if (!verdict.ok) {
        return { ok: false, status: 401, body: { error: 'token rejected', code: verdict.refusal.code } };
      }
      if (verdict.verified.actor !== config.actor || (mandate !== null && verdict.verified.mandateId !== mandate.id)) {
        return {
          ok: false,
          status: 403,
          body: { error: 'token is scoped to a different actor/mandate than this door' },
        };
      }
      return { ok: true, actor: config.actor };
    }
    return { ok: true, actor: config.actor };
  };

  // Card rail (S5, Q11): mounts IFF a webhook secret AND a mandate exist —
  // signature verification is mandatory, and a door without a mandate has no
  // authority to approve anything (fail-closed on both counts). Same door
  // process, same ledger, same ApprovalService: one mandate, one cap, both
  // rails, and card approvals decide through the same /approvals endpoint.
  if (config.stripe.webhookSecret !== null && mandate !== null) {
    const webhookSecret = config.stripe.webhookSecret;
    const stripeClient =
      config.stripe.apiKey === null
        ? null
        : new StripeClient({
            secretKey: config.stripe.apiKey,
            baseUrl: config.stripe.apiBase,
            ...(config.stripe.apiVersion === null ? {} : { apiVersion: config.stripe.apiVersion }),
          });
    const cardPolicy = new MandatePolicyEngine({
      mandate,
      velocity: { maxIntentsPerMinute: config.maxIntentsPerMinute },
      rail: 'card',
    });
    void app.register(async (cardScope) => {
      cardRailStatus = await registerCardRail(cardScope, {
        config: {
          doorId: config.doorId,
          ledgerCurrency: config.ledgerCurrency,
          maxIntentsPerMinute: config.maxIntentsPerMinute,
          maxPendingApprovals: config.maxPendingApprovals,
          approvalBaseUrl: config.publicBaseUrl ?? `http://127.0.0.1:${config.port}`,
          webhookSecret,
          webhookToleranceSeconds: config.stripe.webhookToleranceSeconds,
          waiverTtlMs: config.stripe.waiverTtlMs,
          cardholderId: config.stripe.cardholderId,
        },
        ledger,
        policy: cardPolicy,
        mandate,
        stripe: stripeClient,
        approvals,
        ...(notifier === undefined ? {} : { notifier }),
        waivers: new WaiverStore(config.stripe.waiverTtlMs),
        authenticateCreate,
      });
    });
  }

  return app;

  async function handleLlmCall(
    adapter: ProviderAdapter,
    endpoint: ProviderEndpoint,
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<unknown> {
    if (halted) {
      return reply.code(503).send({
        error: 'gateway halted: a result entry failed to persist; restart after investigating',
      });
    }
    // R1 fail-closed: every precondition of metered spend must hold, or the
    // spend path simply does not exist.
    if (mandate === null) {
      return reply
        .code(503)
        .send({ error: 'no mandate configured — spend path closed (fail-closed)' });
    }
    if (endpoint.apiKey === null) {
      return reply.code(503).send({ error: 'no provider credential configured (fail-closed)' });
    }
    if (config.usdPerLedgerUnit === null) {
      return reply.code(503).send({
        error: `no USD rate configured for ledger currency ${config.ledgerCurrency} — cannot meter provider costs (fail-closed); set MANDARE_USD_PER_LEDGER_UNIT`,
      });
    }

    const scopeSelection = selectGatewaySpendScope(mandate);
    if (scopeSelection === 'none' || scopeSelection === 'ambiguous') {
      return reply.code(503).send({
        error: `mandate has ${scopeSelection === 'none' ? 'no' : 'ambiguous'} gateway spend scope — spend path closed (fail-closed)`,
      });
    }
    if (scopeSelection.currency !== config.ledgerCurrency) {
      return reply.code(503).send({
        error: `mandate budgets ${scopeSelection.currency} but the ledger runs ${config.ledgerCurrency} — refusing (fail-closed)`,
      });
    }

    const body = request.body as Record<string, unknown>;
    const stream = body.stream === true;
    const model = String(body.model);

    // canonicalJson rejects values JSON.parse can still produce (1e400 →
    // Infinity) — hostile bodies get a 400, not an unhandled 500 (R4).
    let requestHash: string;
    try {
      requestHash = sha256Hex(canonicalJson(body));
    } catch {
      return reply.code(400).send({ error: 'request body is not canonicalizable JSON' });
    }

    const pricing = findPricing(model, pricingTable);
    const providerHost = new URL(endpoint.baseUrl).host;

    // Identity + kill switch. Two mode-dependent shapes with one outcome: a
    // verified (or asserted) `actor`, checked against the LOCAL revocation
    // projection — never the cloud — before any spend work (S3 authority).
    //
    // - Legacy/token modes (S2/S3, frozen demos): the kill check runs BEFORE
    //   token auth so a killed agent's refusal lands on the ledger even when
    //   the vault has also revoked its token; the actor is the configured one
    //   (a valid token proves an authorized HOLDER, not WHO).
    // - Passport mode (S4): the door check still runs pre-auth (self-
    //   knowledge, no attribution problem), then the passport chain + RFC
    //   9421 signature PROVE the actor, and only then are the agent and
    //   MANDATE subjects checked — so the kill-refusal is attributed to a
    //   cryptographically verified identity, not to whatever a rando claims.
    //   (Kill does not invalidate the agent's key, so a killed agent still
    //   authenticates — and its refusal is recorded, same as S3.)
    let actor = config.actor;
    if (passportMode) {
      const doorRevoked = await readRevocation(doorSubject(config.doorId));
      if (doorRevoked === 'unavailable') {
        return replyRevocationUnavailable(reply);
      }
      if (doorRevoked?.revoked === true) {
        return await refuseRevoked(reply, {
          requestHash,
          target: providerHost,
          code: 'DOOR_REVOKED',
          reason: `door '${config.doorId}' has been killed (kill --all) — every credential is revoked (fail-closed)`,
          actor,
        });
      }
      if (config.trustedAuthorityDid === null) {
        return reply.code(503).send({
          error:
            'passport auth requires MANDARE_TRUST_AUTHORITY (attestation authority DID) — spend path closed (fail-closed)',
        });
      }
      const rawBody = rawBodies.get(request);
      if (rawBody === undefined) {
        return reply.code(401).send({ error: 'request body bytes unavailable for signature check' });
      }
      const auth = await authenticatePassportRequest({
        request,
        rawBody,
        trustedAuthorityDid: config.trustedAuthorityDid,
        nonceStore,
      });
      if (!auth.ok) {
        return reply
          .code(auth.refusal.status)
          .send({ error: 'passport rejected', code: auth.refusal.code, reason: auth.refusal.reason });
      }
      // Bind the verified delegation chain to THIS mandate (MEDIUM-1): the
      // credential's owner must be the mandate principal, and if the
      // credential names a mandate it must be this one. Otherwise the chain
      // the door records for the spend ("verified owner → agent") would not
      // be the chain the mandate names — an accountability laundering gap.
      if (isDidKey(mandate.principal) && auth.passport.ownerDid !== mandate.principal) {
        return reply.code(403).send({
          error: 'passport rejected',
          code: 'OWNER_MISMATCH',
          reason: "the delegation credential's owner is not this mandate's principal",
        });
      }
      if (auth.passport.mandateRef !== null && auth.passport.mandateRef !== mandate.id) {
        return reply.code(403).send({
          error: 'passport rejected',
          code: 'MANDATE_MISMATCH',
          reason: 'the delegation credential is bound to a different mandate than this door enforces',
        });
      }
      actor = auth.passport.agentDid;
      const agentRevoked = await readRevocation(agentSubject(actor));
      const mandateRevoked = await readRevocation(mandateSubject(mandate.id));
      if (agentRevoked === 'unavailable' || mandateRevoked === 'unavailable') {
        return replyRevocationUnavailable(reply);
      }
      if (agentRevoked?.revoked === true || mandateRevoked?.revoked === true) {
        const mandateKilled = mandateRevoked?.revoked === true && agentRevoked?.revoked !== true;
        return await refuseRevoked(reply, {
          requestHash,
          target: providerHost,
          code: mandateKilled ? 'MANDATE_REVOKED' : 'AGENT_REVOKED',
          reason: mandateKilled
            ? `mandate '${mandate.id}' has been revoked — the permission slip is dead paper (fail-closed)`
            : `agent '${actor}' has been killed — its credentials are revoked (fail-closed)`,
          actor,
        });
      }
    } else {
      const revoked = await readRevocations();
      if (revoked === 'unavailable') {
        return replyRevocationUnavailable(reply);
      }
      if (
        revoked.agent?.revoked === true ||
        revoked.door?.revoked === true ||
        revoked.mandate?.revoked === true
      ) {
        const killedDoor = revoked.door?.revoked === true;
        const killedMandate = revoked.mandate?.revoked === true && revoked.agent?.revoked !== true;
        const code = killedDoor ? 'DOOR_REVOKED' : killedMandate ? 'MANDATE_REVOKED' : 'AGENT_REVOKED';
        const reason = killedDoor
          ? `door '${config.doorId}' has been killed (kill --all) — every credential is revoked (fail-closed)`
          : killedMandate
            ? `mandate '${mandate.id}' has been revoked — the permission slip is dead paper (fail-closed)`
            : `agent '${config.actor}' has been killed — its credentials are revoked (fail-closed)`;
        return await refuseRevoked(reply, {
          requestHash,
          target: providerHost,
          code,
          reason,
          actor,
        });
      }

      // Door-local token authentication (S3). Auth failures are pre-
      // authorization rejections (401/403), not policy denials, so they do
      // not enter the ledger (no verified actor to attribute them to).
      if (requireToken) {
        if (vault === undefined) {
          return reply.code(503).send({
            error: 'token auth required but no vault is configured — spend path closed (fail-closed)',
          });
        }
        const claims = extractRequestClaims(request);
        if (claims === null) {
          return reply.code(401).send({
            error: 'missing proof-of-possession token headers (x-mandare-token/timestamp/nonce/pop)',
          });
        }
        const verdict = vault.verifyRequest(claims);
        if (!verdict.ok) {
          return reply
            .code(401)
            .send({ error: 'token rejected', code: verdict.refusal.code, reason: verdict.refusal.reason });
        }
        if (verdict.verified.actor !== config.actor || verdict.verified.mandateId !== mandate.id) {
          return reply.code(403).send({
            error: 'token is scoped to a different actor/mandate than this door',
          });
        }
      }
    }

    if (pricing === null && adapter.name !== 'openrouter') {
      // No price → no metering → no spend (R1). OpenRouter is exempt: its
      // response cost is authoritative, so we reserve the full per-tx cap.
      return await recordDenied(reply, {
        actor,
        requestHash,
        target: providerHost,
        estimateLedgerMicros: 0,
        code: 'MODEL_UNPRICED',
        reasons: [
          `model '${model}' has no pricing entry — cannot meter it (fail-closed); extend MANDARE_PRICING_PATH`,
        ],
      });
    }

    const plan: CallPlan = {
      adapter,
      endpoint,
      body,
      model,
      stream,
      requestHash,
      pricing,
      estimateLedgerMicros:
        pricing === null
          ? scopeSelection.per_tx_max
          : usdMicrosToLedgerMicros(
              estimateUsdMicros({ body, pricing }),
              config.usdPerLedgerUnit
            ),
      scope: scopeSelection,
      usdPerLedgerUnit: config.usdPerLedgerUnit,
    };

    // Pre-call policy evaluation: full SPEC §5 order over a counter snapshot.
    // Advisory for budgets (the reservation re-checks under the lock), and
    // authoritative for everything else (identity, window, scope,
    // counterparty, approvals). A throwing engine = deny (R1).
    const evaluatePolicy = async (approvedEntryHash?: string) => {
      const snapshot = await readSpendSnapshot(ledger, {
        mandateId: mandate.id,
        actor,
        nowIso: new Date().toISOString(),
      });
      return policy.evaluate({
        principal: actor,
        action: 'llm.call',
        resource: model,
        context: {
          estimateMicros: plan.estimateLedgerMicros,
          currency: config.ledgerCurrency,
          counterparty: providerHost,
          counters: {
            minuteIntents: snapshot.minuteIntents,
            day: {
              reservedMicros: snapshot.day.reservedMicros,
              settledMicros: snapshot.day.settledMicros,
            },
            // One mandate = one task until task attribution lands (S5+).
            task: {
              reservedMicros: snapshot.total.reservedMicros,
              settledMicros: snapshot.total.settledMicros,
            },
            total: {
              reservedMicros: snapshot.total.reservedMicros,
              settledMicros: snapshot.total.settledMicros,
            },
          },
          ...(approvedEntryHash === undefined ? {} : { approvedEntryHash }),
        },
      });
    };

    let decision;
    try {
      decision = await evaluatePolicy();
    } catch {
      return reply.code(503).send({ error: 'policy denied or unavailable (fail-closed)' });
    }
    if (decision.decision !== 'allow' && decision.code === 'APPROVAL_REQUIRED') {
      // The S4 unlock: instead of a flat refusal, HOLD the call and push the
      // decision to the human (SPEC §5, CIBA-style). No notifier configured ⇒
      // the S2 fail-closed denial stands.
      if (notifier === undefined) {
        return await recordDenied(reply, {
          actor,
          requestHash,
          target: providerHost,
          estimateLedgerMicros: plan.estimateLedgerMicros,
          code: 'APPROVAL_REQUIRED',
          reasons: [...decision.reasons, 'no approval push channel configured — refusing (fail-closed)'],
        });
      }
      // Held calls reserve nothing, so they escape the velocity counter — cap
      // concurrent holds so a looping agent can't flood the human with pushes
      // (notification fatigue is a phishing vector), pin sockets, or amplify
      // fsync'd approval.requested entries (MEDIUM-2).
      if (approvals.pendingCount() >= config.maxPendingApprovals) {
        return await recordDenied(reply, {
          actor,
          requestHash,
          target: providerHost,
          estimateLedgerMicros: plan.estimateLedgerMicros,
          code: 'APPROVAL_BACKLOG',
          reasons: [
            `too many approvals already awaiting a human decision (≥${config.maxPendingApprovals}) — refusing (fail-closed)`,
          ],
        });
      }
      const outcome = await holdForApproval(reply, plan, { actor, providerHost });
      if (outcome.kind !== 'approved') {
        return outcome.reply;
      }
      // A kill (agent / mandate / door) may have landed WHILE the call was
      // held. Re-check revocation before resuming — an approved-but-since-
      // revoked call must still fail closed (HIGH-2: the hold window can be
      // long, and "revoked instantly" must mean instantly).
      const heldRevocation = await revocationRefusal(actor);
      if (heldRevocation === 'unavailable') {
        return replyRevocationUnavailable(reply);
      }
      if (heldRevocation !== null) {
        return await refuseRevoked(reply, {
          actor,
          requestHash,
          target: providerHost,
          code: heldRevocation.code,
          reason: heldRevocation.reason,
        });
      }
      // Re-evaluate the FULL policy order with the recorded grant: time
      // passed while the call was held (window, budgets, velocity may have
      // moved); only the satisfied approval threshold is waived.
      try {
        decision = await evaluatePolicy(outcome.grantedEntryHash);
      } catch {
        return reply.code(503).send({ error: 'policy denied or unavailable (fail-closed)' });
      }
    }
    if (decision.decision !== 'allow') {
      return await recordDenied(reply, {
        actor,
        requestHash,
        target: providerHost,
        estimateLedgerMicros: plan.estimateLedgerMicros,
        code: decision.code ?? 'POLICY_DENIED',
        reasons: [...decision.reasons],
      });
    }

    // RESERVE (log-before-act, R3): the intent entry carries the estimate and
    // is budget-guarded INSIDE the append transaction — the authoritative
    // check that makes concurrent cap overshoot impossible by construction.
    const limits = spendLimitsFromScope(plan.scope);
    const guard = (view: SpendGuardView) =>
      checkBudgets({
        limits,
        velocity: { maxIntentsPerMinute: config.maxIntentsPerMinute },
        counters: {
          minuteIntents: view.minuteIntents,
          day: { reservedMicros: view.day.reservedMicros, settledMicros: view.day.settledMicros },
          task: {
            reservedMicros: view.total.reservedMicros,
            settledMicros: view.total.settledMicros,
          },
          total: {
            reservedMicros: view.total.reservedMicros,
            settledMicros: view.total.settledMicros,
          },
        },
        estimateMicros: view.estimateMicros,
        currency: view.currency,
      });

    let reservation: AppendProjectedResult;
    try {
      reservation = await ledger.appendProjected(
        {
          actor,
          mandate_id: mandate.id,
          action: { type: LLM_CALL_INTENT, target: providerHost, request_hash: requestHash },
          cost: {
            amount: plan.estimateLedgerMicros,
            currency: config.ledgerCurrency,
            tokens_in: 0,
            tokens_out: 0,
          },
        },
        spendProjector(guard)
      );
    } catch (error) {
      request.log?.error?.(error);
      return reply
        .code(503)
        .send({ error: 'ledger unavailable — refusing to act (fail-closed)' });
    }
    if (reservation.kind === 'refused') {
      return await recordDenied(reply, {
        actor,
        requestHash,
        target: providerHost,
        estimateLedgerMicros: plan.estimateLedgerMicros,
        code: reservation.refusal.code,
        reasons: [`reservation refused: ${reservation.refusal.reason}`],
      });
    }
    const intent = reservation.entry;

    // Execute.
    let upstream: Response;
    const abort = new AbortController();
    try {
      upstream = await fetchImpl(`${endpoint.baseUrl}${adapter.endpointPath}`, {
        method: 'POST',
        headers: adapter.headers(endpoint.apiKey),
        body: JSON.stringify(adapter.prepareBody(body, stream)),
        // Streaming: the caller's abort plus a header-phase timeout, so a
        // provider that accepts the socket but never responds cannot pin the
        // request (and its reservation) forever. The per-chunk idle timeout
        // takes over once the stream body starts.
        signal: stream
          ? AbortSignal.any([abort.signal, AbortSignal.timeout(timeouts.streamIdleMs)])
          : AbortSignal.timeout(timeouts.nonStreamMs),
      });
    } catch (error) {
      // The fetch failed — but that does NOT prove nothing executed: a
      // timeout can mean the provider received (and billed) the request.
      // Settle CONSERVATIVELY at the reserved estimate (never 0 — the cap
      // must not reopen on unknowns, R1); a Storno correction entry can
      // reconcile later against provider billing.
      const errorName = error instanceof Error ? error.name : 'UnknownError';
      const settled = await settleOrHalt(intent, requestHash, {
        responseHash: sha256Hex(`provider-error:${errorName}:outcome-unknown`),
        costMicros: plan.estimateLedgerMicros,
        tokensIn: 0,
        tokensOut: 0,
      });
      if (settled === null) {
        return replyHalted(reply, intent);
      }
      return reply.code(502).send({
        error: `provider unreachable (${errorName}); outcome unknown — settled at the reserved estimate pending reconciliation`,
      });
    }

    const contentType = upstream.headers.get('content-type') ?? 'application/json';
    if (stream && upstream.status === 200 && contentType.includes('text/event-stream')) {
      return streamThrough(plan, intent, upstream, request, reply, abort);
    }
    return respondBuffered(plan, intent, upstream, reply);
  }

  /** Non-streaming (and streaming-refused/error) responses: buffer, settle, relay. */
  async function respondBuffered(
    plan: CallPlan,
    intent: LedgerEntryV1,
    upstream: Response,
    reply: FastifyReply
  ): Promise<unknown> {
    let bodyText: string;
    try {
      bodyText = await upstream.text();
    } catch (error) {
      // Headers arrived but the body read died (timeout mid-body, socket
      // reset) — the provider executed and may have billed. Same conservative
      // contract as a failed fetch: settle at the reserved estimate, never
      // leave an intent unpaired (R3) and never treat unknown as free (R1).
      const errorName = error instanceof Error ? error.name : 'UnknownError';
      const settled = await settleOrHalt(intent, plan.requestHash, {
        responseHash: sha256Hex(`provider-body-read-error:${errorName}:outcome-unknown`),
        costMicros: plan.estimateLedgerMicros,
        tokensIn: 0,
        tokensOut: 0,
      });
      if (settled === null) {
        return replyHalted(reply, intent);
      }
      return reply.code(502).send({
        error: `provider response body could not be read (${errorName}); outcome unknown — settled at the reserved estimate pending reconciliation`,
      });
    }
    const usage = upstream.ok ? plan.adapter.parseUsageFromJson(bodyText) : null;
    // Provider errors (4xx/5xx) are not billed — settle 0 and release the
    // reservation. A 200 with no parseable usage settles at the estimate
    // (Q16: estimation for usage-less endpoints; never settle a success at 0).
    const costMicros = !upstream.ok
      ? 0
      : usage === null
        ? plan.estimateLedgerMicros
        : settlementMicros(usage, plan);
    const settled = await settleOrHalt(intent, plan.requestHash, {
      responseHash: sha256Hex(bodyText),
      costMicros,
      tokensIn: usage === null ? 0 : usage.tokensIn + usage.cacheWriteTokens + usage.cacheReadTokens,
      tokensOut: usage?.tokensOut ?? 0,
    });
    if (settled === null) {
      return replyHalted(reply, intent);
    }
    return reply
      .code(upstream.status)
      .header('content-type', upstream.headers.get('content-type') ?? 'application/json')
      .header('x-mandare-intent-entry', intent.entry_hash)
      .header('x-mandare-result-entry', settled.entry_hash)
      .send(bodyText);
  }

  /** Streaming: bytes pass through untouched while a tee parses usage (Q16). */
  async function streamThrough(
    plan: CallPlan,
    intent: LedgerEntryV1,
    upstream: Response,
    request: FastifyRequest,
    reply: FastifyReply,
    abort: AbortController
  ): Promise<unknown> {
    reply.hijack();
    const raw = reply.raw;
    raw.writeHead(200, {
      'content-type': upstream.headers.get('content-type') ?? 'text/event-stream',
      'cache-control': 'no-cache',
      'x-mandare-intent-entry': intent.entry_hash,
    });

    const sse = new SseParser();
    const usageParser = plan.adapter.newStreamParser();
    const responseHasher = createHash('sha256');
    const decoder = new TextDecoder();
    let clientGone = false;
    let aborted = false;
    request.raw.on('close', () => {
      clientGone = true;
      abort.abort();
    });

    let idleTimer: NodeJS.Timeout | null = null;
    const resetIdle = (): void => {
      if (idleTimer !== null) {
        clearTimeout(idleTimer);
      }
      idleTimer = setTimeout(() => abort.abort(), timeouts.streamIdleMs);
    };

    try {
      resetIdle();
      if (upstream.body === null) {
        throw new Error('provider returned no stream body');
      }
      for await (const chunk of upstream.body as AsyncIterable<Uint8Array>) {
        resetIdle();
        responseHasher.update(chunk);
        for (const event of sse.push(decoder.decode(chunk, { stream: true }))) {
          usageParser.onEvent(event);
        }
        if (!clientGone && !raw.write(chunk)) {
          await new Promise<void>((resolve) => raw.once('drain', resolve));
        }
      }
    } catch {
      aborted = true;
    } finally {
      if (idleTimer !== null) {
        clearTimeout(idleTimer);
      }
    }

    // SETTLE. Complete stream: provider usage (or estimate if the stream
    // carried none). Aborted stream: tokenizer estimate over what was
    // actually observed (Q16), floored at the input share of the estimate.
    const usage = usageParser.usage();
    let costMicros: number;
    let tokensIn = 0;
    let tokensOut = 0;
    if (usage !== null && !aborted) {
      costMicros = settlementMicros(usage, plan);
      tokensIn = usage.tokensIn + usage.cacheWriteTokens + usage.cacheReadTokens;
      tokensOut = usage.tokensOut;
    } else if (plan.pricing !== null) {
      tokensIn = usage?.tokensIn ?? estimateTokensFromChars(JSON.stringify(plan.body.messages ?? '').length);
      // An aborted stream's usage (if any) predates the final delta — its
      // output count is stale, so the observed text is the better floor.
      tokensOut = Math.max(
        usage?.tokensOut ?? 0,
        estimateTokensFromChars(usageParser.observedTextChars())
      );
      costMicros = usdMicrosToLedgerMicros(
        costUsdMicros(
          { tokensIn, tokensOut, cacheWriteTokens: 0, cacheReadTokens: 0 },
          plan.pricing
        ),
        plan.usdPerLedgerUnit
      );
    } else {
      // Unpriced OpenRouter stream that died before its usage chunk:
      // conservative — the reservation (per-tx cap) stands as settled.
      costMicros = plan.estimateLedgerMicros;
    }

    const settled = await settleOrHalt(intent, plan.requestHash, {
      responseHash: responseHasher.digest('hex'),
      costMicros,
      tokensIn,
      tokensOut,
    });
    if (!clientGone) {
      if (settled !== null) {
        // SSE comment line — protocol-legal, ignored by clients, and it puts
        // the result entry hash in the captured stream for auditability.
        raw.write(`: x-mandare-result-entry ${settled.entry_hash}\n\n`);
      }
      raw.end();
    }
    return reply;
  }

  function settlementMicros(usage: ParsedUsage, plan: CallPlan): number {
    if (usage.costUsdMicros !== null) {
      // OpenRouter's reported cost is authoritative (Q14).
      return usdMicrosToLedgerMicros(usage.costUsdMicros, plan.usdPerLedgerUnit);
    }
    if (plan.pricing !== null) {
      return usdMicrosToLedgerMicros(costUsdMicros(usage, plan.pricing), plan.usdPerLedgerUnit);
    }
    return plan.estimateLedgerMicros;
  }

  /** One revocation record, or 'unavailable' when the projection cannot be read. */
  async function readRevocation(subject: string): Promise<RevocationRecord | null | 'unavailable'> {
    try {
      return await ledger.runProjection((tx) => tx.getRevocation(subject));
    } catch {
      return 'unavailable';
    }
  }

  /** Legacy modes read agent + door + mandate in one projection pass. */
  async function readRevocations(): Promise<
    | { agent: RevocationRecord | null; door: RevocationRecord | null; mandate: RevocationRecord | null }
    | 'unavailable'
  > {
    try {
      return await ledger.runProjection(async (tx) => ({
        agent: await tx.getRevocation(agentSubject(config.actor)),
        door: await tx.getRevocation(doorSubject(config.doorId)),
        mandate: mandate === null ? null : await tx.getRevocation(mandateSubject(mandate.id)),
      }));
    } catch {
      return 'unavailable';
    }
  }

  function replyRevocationUnavailable(reply: FastifyReply): unknown {
    return reply
      .code(503)
      .send({ error: 'revocation status unavailable — refusing to act (fail-closed)' });
  }

  /**
   * Evaluate door + agent + mandate revocation for one actor. Returns a
   * refusal descriptor if any subject is killed, 'unavailable' if the
   * projection can't be read (fail closed), or null if all clear. Used both
   * at request entry AND again when a HELD call resumes — a kill that lands
   * during the approval hold must still close the door (HIGH-2).
   */
  async function revocationRefusal(
    actorDid: string
  ): Promise<{ code: string; reason: string } | 'unavailable' | null> {
    const door = await readRevocation(doorSubject(config.doorId));
    const agent = await readRevocation(agentSubject(actorDid));
    const mandateRec = mandate === null ? null : await readRevocation(mandateSubject(mandate.id));
    if (door === 'unavailable' || agent === 'unavailable' || mandateRec === 'unavailable') {
      return 'unavailable';
    }
    if (door?.revoked === true) {
      return {
        code: 'DOOR_REVOKED',
        reason: `door '${config.doorId}' has been killed (kill --all) — every credential is revoked (fail-closed)`,
      };
    }
    if (agent?.revoked === true) {
      return {
        code: 'AGENT_REVOKED',
        reason: `agent '${actorDid}' has been killed — its credentials are revoked (fail-closed)`,
      };
    }
    if (mandateRec?.revoked === true) {
      return {
        code: 'MANDATE_REVOKED',
        reason: `mandate '${mandate?.id}' has been revoked — the permission slip is dead paper (fail-closed)`,
      };
    }
    return null;
  }

  /**
   * Refuse a revoked subject, recording the refusal — but coalesced so a
   * post-kill loop cannot amplify into an unbounded stream of fsync'd DENIED
   * entries (at most one recorded kill-refusal per throttle window).
   */
  async function refuseRevoked(
    reply: FastifyReply,
    args: { requestHash: string; target: string; code: string; reason: string; actor: string }
  ): Promise<unknown> {
    const nowMs = Date.now();
    if (nowMs - lastRevokedDeniedAt < REVOKED_DENIED_THROTTLE_MS) {
      return reply.code(403).send({ error: 'denied by policy', code: args.code, reasons: [args.reason] });
    }
    lastRevokedDeniedAt = nowMs;
    return await recordDenied(reply, {
      actor: args.actor,
      requestHash: args.requestHash,
      target: args.target,
      estimateLedgerMicros: 0,
      code: args.code,
      reasons: [args.reason],
    });
  }

  /**
   * The held-call approval flow (SPEC §5): approval.requested entry (log-
   * before-act) → push with Approve/Deny capability buttons → wait → the
   * decision entry lands BEFORE the call resumes or is refused. Every exit
   * is fail-closed: no channel, failed push, failed entry, timeout — deny.
   */
  async function holdForApproval(
    reply: FastifyReply,
    plan: CallPlan,
    ctx: { actor: string; providerHost: string }
  ): Promise<{ kind: 'approved'; grantedEntryHash: string } | { kind: 'refused'; reply: unknown }> {
    const activeMandate = mandate as MandateV1;
    const thresholds = activeMandate.approvals.rules
      .filter((rule) => plan.estimateLedgerMicros > rule.above)
      .map((rule) => rule.above);
    const thresholdMicros = thresholds.length === 0 ? 0 : Math.min(...thresholds);

    let requested: LedgerEntryV1;
    try {
      const appended = await ledger.appendProjected(
        {
          actor: ctx.actor,
          mandate_id: activeMandate.id,
          action: {
            type: APPROVAL_REQUESTED,
            target: ctx.providerHost,
            request_hash: plan.requestHash,
          },
          // The amount is the HELD estimate — informational; approval entries
          // never touch the spend counters.
          cost: {
            amount: plan.estimateLedgerMicros,
            currency: config.ledgerCurrency,
            tokens_in: 0,
            tokens_out: 0,
          },
        },
        spendProjector()
      );
      if (appended.kind !== 'appended') {
        throw new Error('approval.requested append refused');
      }
      requested = appended.entry;
    } catch {
      return {
        kind: 'refused',
        reply: reply
          .code(503)
          .send({ error: 'could not record the approval request — refusing to act (fail-closed)' }),
      };
    }

    const created = approvals.create({
      requestHash: plan.requestHash,
      estimateMicros: plan.estimateLedgerMicros,
      currency: config.ledgerCurrency,
      model: plan.model,
      target: ctx.providerHost,
      actor: ctx.actor,
      mandateId: activeMandate.id,
      thresholdMicros,
    });
    const baseUrl = config.publicBaseUrl ?? `http://127.0.0.1:${config.port}`;
    const amount = (plan.estimateLedgerMicros / 1_000_000).toFixed(4);
    const threshold = (thresholdMicros / 1_000_000).toFixed(2);
    try {
      await (notifier as Notifier).send({
        approvalId: created.id,
        title: `Mandare: approve ~${amount} ${config.ledgerCurrency}?`,
        message:
          `Agent ${ctx.actor} wants ${plan.model} via ${ctx.providerHost} — estimated ` +
          `${amount} ${config.ledgerCurrency}, above your ${threshold} ${config.ledgerCurrency} ` +
          `threshold (mandate ${activeMandate.id}). No decision by ${created.expiresAtIso} = deny.`,
        approveUrl: `${baseUrl}/approvals/${created.id}`,
        denyUrl: `${baseUrl}/approvals/${created.id}`,
        approveBody: JSON.stringify({ token: created.approveToken }),
        denyBody: JSON.stringify({ token: created.denyToken }),
        expiresAt: created.expiresAtIso,
      });
    } catch {
      const refusal = await recordDenied(reply, {
        actor: ctx.actor,
        requestHash: plan.requestHash,
        target: ctx.providerHost,
        estimateLedgerMicros: plan.estimateLedgerMicros,
        code: 'APPROVAL_PUSH_FAILED',
        reasons: ['the approval push could not be delivered — refusing (fail-closed)'],
      });
      return { kind: 'refused', reply: refusal };
    }

    const outcome = await created.outcome;
    const decisionType =
      outcome === 'approved'
        ? APPROVAL_GRANTED
        : outcome === 'denied'
          ? APPROVAL_DENIED
          : APPROVAL_EXPIRED;
    // The decision is committed via request_hash (same pattern as kill
    // reasons): approval id + outcome + the held call's hash, tamper-evident.
    const decisionHash = sha256Hex(
      canonicalJson({ approval_id: created.id, decision: outcome, request_hash: plan.requestHash })
    );
    let decisionEntry: LedgerEntryV1 | null = null;
    try {
      const appended = await ledger.appendProjected(
        {
          // Human decisions are attributed to the accountable human — the
          // mandate principal (timeouts too: the principal's window lapsed).
          actor: activeMandate.principal,
          mandate_id: activeMandate.id,
          action: { type: decisionType, target: ctx.providerHost, request_hash: decisionHash },
          cost: { amount: 0, currency: config.ledgerCurrency, tokens_in: 0, tokens_out: 0 },
          outcome_ref: requested.entry_hash,
        },
        spendProjector()
      );
      decisionEntry = appended.kind === 'appended' ? appended.entry : null;
    } catch {
      decisionEntry = null;
    }

    if (outcome === 'approved') {
      if (decisionEntry === null) {
        // An approval that cannot be recorded does not exist (R3: the entry
        // gates the act, not the human's click).
        return {
          kind: 'refused',
          reply: reply
            .code(503)
            .send({ error: 'approval granted but could not be recorded — refusing to act (fail-closed)' }),
        };
      }
      return { kind: 'approved', grantedEntryHash: decisionEntry.entry_hash };
    }
    const refusal = await recordDenied(reply, {
      actor: ctx.actor,
      requestHash: plan.requestHash,
      target: ctx.providerHost,
      estimateLedgerMicros: plan.estimateLedgerMicros,
      code: outcome === 'denied' ? 'APPROVAL_DENIED' : 'APPROVAL_TIMEOUT',
      reasons: [
        outcome === 'denied'
          ? 'the human denied this call'
          : `no human decision within ${config.approvalTimeoutMs}ms — refusing (fail-closed)`,
      ],
    });
    return { kind: 'refused', reply: refusal };
  }

  /** Record a refusal as a DENIED ledger entry, then 403. */
  async function recordDenied(
    reply: FastifyReply,
    args: {
      actor: string;
      requestHash: string;
      target: string;
      estimateLedgerMicros: number;
      code: string;
      reasons: string[];
    }
  ): Promise<unknown> {
    let deniedEntry: LedgerEntryV1 | null = null;
    try {
      const appended = await ledger.appendProjected(
        {
          actor: args.actor,
          mandate_id: mandate?.id ?? 'mnd_unconfigured',
          action: { type: LLM_CALL_DENIED, target: args.target, request_hash: args.requestHash },
          // A denied entry's amount is the REFUSED estimate — never spend,
          // and the projection ignores it. It exists so `mandare verify`
          // shows the refusal in the trail.
          cost: {
            amount: args.estimateLedgerMicros,
            currency: config.ledgerCurrency,
            tokens_in: 0,
            tokens_out: 0,
          },
        },
        spendProjector()
      );
      deniedEntry = appended.kind === 'appended' ? appended.entry : null;
    } catch {
      // The refusal stands even if it cannot be recorded; the ledger being
      // down never opens the spend path.
    }
    return reply.code(403).send({
      error: 'denied by policy',
      code: args.code,
      reasons: args.reasons,
      ...(deniedEntry === null ? {} : { denied_entry: deniedEntry.entry_hash }),
    });
  }

  async function settleOrHalt(
    intent: LedgerEntryV1,
    requestHash: string,
    result: { responseHash: string; costMicros: number; tokensIn: number; tokensOut: number }
  ): Promise<LedgerEntryV1 | null> {
    try {
      const appended = await ledger.appendProjected(
        {
          actor: intent.actor,
          mandate_id: intent.mandate_id,
          action: {
            type: LLM_CALL_RESULT,
            target: intent.action.target,
            request_hash: requestHash,
            response_hash: result.responseHash,
          },
          cost: {
            amount: result.costMicros,
            currency: config.ledgerCurrency,
            tokens_in: result.tokensIn,
            tokens_out: result.tokensOut,
          },
          outcome_ref: intent.entry_hash,
        },
        spendProjector()
      );
      if (appended.kind !== 'appended') {
        halted = true;
        return null;
      }
      return appended.entry;
    } catch {
      halted = true;
      return null;
    }
  }

  function replyHalted(reply: FastifyReply, intent: LedgerEntryV1): unknown {
    return reply.code(502).send({
      error: 'call executed but the result entry could not be persisted — gateway halted',
      intent_entry: intent.entry_hash,
    });
  }
}
