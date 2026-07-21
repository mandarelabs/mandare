import Fastify, { type FastifyInstance } from 'fastify';
import { Type } from '@sinclair/typebox';

import {
  LLM_CALL_INTENT,
  LLM_CALL_RESULT,
  canonicalJson,
  sha256Hex,
  type LedgerEntryV1,
} from '@mandarelabs/spec';
import type { AppendInput } from '@mandarelabs/ledger';
import type { PolicyEngine } from '@mandarelabs/policy-engine';

import type { GatewayConfig } from './config.js';
import { forwardChatCompletion, type FetchLike } from './openrouter.js';

/** The slice of the Ledger API the gateway needs — narrow so tests can fake it. */
export interface LedgerWriter {
  append(input: AppendInput): LedgerEntryV1;
}

export interface GatewayDeps {
  config: GatewayConfig;
  ledger: LedgerWriter;
  policy: PolicyEngine;
  fetchImpl?: FetchLike;
}

/**
 * Walking-skeleton request flow (rules R1/R3 — the shape every later door copies):
 *
 *   validate (R4) → policy check (deny/throw ⇒ 403/503, nothing happens)
 *   → INTENT entry chained (fails ⇒ 503, nothing forwarded — no entry, no action)
 *   → forward to provider
 *   → RESULT entry chained (fails ⇒ gateway HALTS: executed-but-unrecorded is
 *     the one state we refuse to continue from)
 *   → response to caller.
 */

// Validate what we rely on; pass the rest through untouched (proxy semantics).
// stream is rejected until S2 implements streaming usage true-up.
const chatCompletionBodySchema = Type.Object(
  {
    model: Type.String({ minLength: 1 }),
    messages: Type.Array(Type.Unknown(), { minItems: 1 }),
    stream: Type.Optional(Type.Literal(false)),
  },
  { additionalProperties: true }
);

export function buildGateway(deps: GatewayDeps): FastifyInstance {
  const { config, ledger, policy } = deps;
  const app = Fastify({ logger: false });
  const providerHost = new URL(config.openrouterBaseUrl).host;
  let halted = false;

  app.get('/healthz', () => ({
    ok: !halted,
    halted,
    door_id: config.doorId,
    spend_path_open: config.openrouterApiKey !== null && !halted,
  }));

  app.post(
    '/v1/chat/completions',
    { schema: { body: chatCompletionBodySchema } },
    async (request, reply) => {
      if (halted) {
        return reply.code(503).send({
          error: 'gateway halted: a result entry failed to persist; restart after investigating',
        });
      }
      // R1 fail-closed: no credential → the spend path does not exist.
      if (config.openrouterApiKey === null) {
        return reply.code(503).send({ error: 'no provider credential configured (fail-closed)' });
      }

      const body = request.body as Record<string, unknown>;

      // Policy check BEFORE anything happens. A throwing engine = deny (R1).
      let decision;
      try {
        decision = await policy.evaluate({
          principal: config.actor,
          action: 'llm.call',
          resource: String(body.model),
          context: { provider: providerHost },
        });
      } catch {
        return reply.code(503).send({ error: 'policy engine unavailable (fail-closed)' });
      }
      if (decision.decision !== 'allow') {
        return reply.code(403).send({ error: 'denied by policy', reasons: decision.reasons });
      }

      // Log-before-act (R3): intent entry first. No entry → no action.
      // canonicalJson rejects values JSON.parse can still produce (e.g. 1e400
      // → Infinity) — hostile bodies get a 400, not an unhandled 500 (R4).
      let requestHash: string;
      try {
        requestHash = sha256Hex(canonicalJson(body));
      } catch {
        return reply.code(400).send({ error: 'request body is not canonicalizable JSON' });
      }
      let intent: LedgerEntryV1;
      try {
        intent = ledger.append({
          actor: config.actor,
          mandate_id: config.mandateId,
          action: { type: LLM_CALL_INTENT, target: providerHost, request_hash: requestHash },
          cost: { amount: 0, currency: 'USD', tokens_in: 0, tokens_out: 0 },
        });
      } catch (error) {
        request.log?.error?.(error);
        return reply.code(503).send({ error: 'ledger unavailable — refusing to act (fail-closed)' });
      }

      // Execute.
      let upstream;
      try {
        upstream = await forwardChatCompletion({
          baseUrl: config.openrouterBaseUrl,
          apiKey: config.openrouterApiKey,
          body,
          ...(deps.fetchImpl === undefined ? {} : { fetchImpl: deps.fetchImpl }),
        });
      } catch (error) {
        // The fetch failed — but that does NOT prove nothing executed: a
        // timeout can mean the provider received (and billed) the request
        // while the response was lost. Record cost 0 as a floor and mark the
        // outcome unknown; S2's usage true-up reconciles against provider
        // billing (BUILD-DECISIONS Q16). Never treat this as free & certain.
        const errorName = error instanceof Error ? error.name : 'UnknownError';
        const errorResult = appendResultOrHalt(ledger, config, intent, requestHash, {
          responseHash: sha256Hex(`provider-error:${errorName}:outcome-unknown`),
          costMicros: 0,
          tokensIn: 0,
          tokensOut: 0,
        });
        if (errorResult === null) {
          halted = true;
          return reply.code(502).send({
            error:
              'provider call failed AND its result entry could not be persisted — gateway halted',
            intent_entry: intent.entry_hash,
          });
        }
        return reply
          .code(502)
          .send({ error: `provider unreachable (${errorName}); outcome recorded as unknown` });
      }

      // Log the result. If THIS write fails, we executed without recording —
      // halt the gateway rather than keep acting off the record.
      const resultEntry = appendResultOrHalt(ledger, config, intent, requestHash, {
        responseHash: sha256Hex(upstream.bodyText),
        costMicros: upstream.usage?.costMicros ?? 0,
        tokensIn: upstream.usage?.tokensIn ?? 0,
        tokensOut: upstream.usage?.tokensOut ?? 0,
      });
      if (resultEntry === null) {
        halted = true;
        return reply.code(502).send({
          error: 'call executed but the result entry could not be persisted — gateway halted',
          intent_entry: intent.entry_hash,
        });
      }

      return reply
        .code(upstream.status)
        .header('content-type', 'application/json')
        .header('x-mandare-intent-entry', intent.entry_hash)
        .header('x-mandare-result-entry', resultEntry.entry_hash)
        .send(upstream.bodyText);
    }
  );

  return app;
}

function appendResultOrHalt(
  ledger: LedgerWriter,
  config: GatewayConfig,
  intent: LedgerEntryV1,
  requestHash: string,
  result: { responseHash: string; costMicros: number; tokensIn: number; tokensOut: number }
): LedgerEntryV1 | null {
  try {
    return ledger.append({
      actor: config.actor,
      mandate_id: config.mandateId,
      action: {
        type: LLM_CALL_RESULT,
        target: intent.action.target,
        request_hash: requestHash,
        response_hash: result.responseHash,
      },
      cost: {
        amount: result.costMicros,
        currency: 'USD',
        tokens_in: result.tokensIn,
        tokens_out: result.tokensOut,
      },
      outcome_ref: intent.entry_hash,
    });
  } catch {
    return null;
  }
}
