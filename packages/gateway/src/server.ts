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
  LLM_CALL_DENIED,
  agentSubject,
  doorSubject,
  readSpendSnapshot,
  spendProjector,
  type AppendInput,
  type AppendProjectedResult,
  type ProjectionRunner,
  type Projector,
  type RevocationRecord,
  type SpendGuardView,
} from '@mandarelabs/ledger';
import {
  checkBudgets,
  selectGatewaySpendScope,
  spendLimitsFromScope,
  type PolicyEngine,
} from '@mandarelabs/policy-engine';
import type { SpendScope } from '@mandarelabs/spec';

import type { GatewayConfig, ProviderEndpoint } from './config.js';
import {
  buildAllowedHosts,
  extractRequestClaims,
  isHostAllowed,
  type GatewayVault,
} from './auth.js';
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
  const { config, ledger, policy, mandate, vault } = deps;
  const pricingTable = deps.pricingTable ?? DEFAULT_PRICING;
  const fetchImpl = deps.fetchImpl ?? (fetch as FetchLike);
  const timeouts = deps.timeouts ?? {
    nonStreamMs: NON_STREAM_TIMEOUT_MS,
    streamIdleMs: STREAM_IDLE_TIMEOUT_MS,
  };
  let halted = false;
  // Last time a kill-refusal was recorded to the ledger (throttle, see above).
  let lastRevokedDeniedAt = 0;

  // "If you have a vault, the door authenticates." authMode='token' forces it
  // even without a vault (⇒ every spend request fails closed until one is
  // wired); 'none' is the S2 localhost-only behavior.
  const requireToken =
    config.authMode === 'token' || (config.authMode === 'auto' && vault !== undefined);
  const allowedHosts = buildAllowedHosts(config);

  // coerceTypes OFF: this is a policy boundary — `stream: "true"` must be a
  // 400, not a silent boolean (R4; caught by the hostile-input red-team).
  const app = Fastify({ logger: false, ajv: { customOptions: { coerceTypes: false } } });

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
    ok: !halted,
    halted,
    door_id: config.doorId,
    mandate_id: mandate?.id ?? null,
    spend_path_open: spendPathOpen(),
    providers: {
      anthropic: config.anthropic.apiKey !== null,
      openai: config.openai.apiKey !== null,
      openrouter: config.openrouter.apiKey !== null,
    },
  }));

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

    // Kill switch (S3): a revoked agent — or a killed door (kill --all) —
    // fails closed on its very next call, ahead of any spend work. This is
    // the LOCAL, offline, un-jammable authority: the gateway reads the ledger
    // revocation projection directly, never the cloud. Fail closed if it
    // cannot be read. The refusal is recorded so `mandare verify` shows it.
    let revoked: { agent: RevocationRecord | null; door: RevocationRecord | null };
    try {
      revoked = await ledger.runProjection(async (tx) => ({
        agent: await tx.getRevocation(agentSubject(config.actor)),
        door: await tx.getRevocation(doorSubject(config.doorId)),
      }));
    } catch {
      return reply
        .code(503)
        .send({ error: 'revocation status unavailable — refusing to act (fail-closed)' });
    }
    if (revoked.agent?.revoked === true || revoked.door?.revoked === true) {
      const killedDoor = revoked.door?.revoked === true;
      const code = killedDoor ? 'DOOR_REVOKED' : 'AGENT_REVOKED';
      const reasons = [
        killedDoor
          ? `door '${config.doorId}' has been killed (kill --all) — every credential is revoked (fail-closed)`
          : `agent '${config.actor}' has been killed — its credentials are revoked (fail-closed)`,
      ];
      // Coalesce: record the refusal for evidence, but don't let a post-kill
      // loop amplify into an unbounded stream of fsync'd DENIED entries.
      const nowMs = Date.now();
      if (nowMs - lastRevokedDeniedAt < REVOKED_DENIED_THROTTLE_MS) {
        return reply.code(403).send({ error: 'denied by policy', code, reasons });
      }
      lastRevokedDeniedAt = nowMs;
      return await recordDenied(reply, {
        requestHash,
        target: providerHost,
        estimateLedgerMicros: 0,
        code,
        reasons,
      });
    }

    // Door-local authentication (S3): AFTER the kill check (the kill switch is
    // the highest-priority gate, and its refusal must land on the ledger even
    // when the vault has also revoked the token). The caller must present a
    // valid vault proof-of-possession token scoped to THIS door's actor and
    // mandate — a leaked token id without its secret is dead paper. Auth
    // failures are pre-authorization rejections (401/403), not policy denials,
    // so they do not enter the ledger (no known actor to attribute them to).
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

    if (pricing === null && adapter.name !== 'openrouter') {
      // No price → no metering → no spend (R1). OpenRouter is exempt: its
      // response cost is authoritative, so we reserve the full per-tx cap.
      return await recordDenied(reply, {
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
    let snapshot;
    try {
      snapshot = await readSpendSnapshot(ledger, {
        mandateId: mandate.id,
        actor: config.actor,
        nowIso: new Date().toISOString(),
      });
    } catch {
      return reply
        .code(503)
        .send({ error: 'spend counters unavailable — refusing to act (fail-closed)' });
    }
    let decision;
    try {
      decision = await policy.evaluate({
        principal: config.actor,
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
            // One mandate = one task until task attribution lands (S4).
            task: {
              reservedMicros: snapshot.total.reservedMicros,
              settledMicros: snapshot.total.settledMicros,
            },
            total: {
              reservedMicros: snapshot.total.reservedMicros,
              settledMicros: snapshot.total.settledMicros,
            },
          },
        },
      });
    } catch {
      return reply.code(503).send({ error: 'policy engine unavailable (fail-closed)' });
    }
    if (decision.decision !== 'allow') {
      return await recordDenied(reply, {
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
          actor: config.actor,
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

  /** Record a refusal as a DENIED ledger entry, then 403. */
  async function recordDenied(
    reply: FastifyReply,
    args: {
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
          actor: config.actor,
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
          actor: config.actor,
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
