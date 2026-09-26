import { Type, type TObject, type TProperties } from '@sinclair/typebox';

/**
 * Spend-route request schemas (R4, S-2). The reservation must bound
 * everything a provider can bill for a request, so the door forwards ONLY the
 * fields it knows how to price: each field below is either priced by the
 * estimator (text billed as input, `n`, predicted outputs, media, cache
 * writes), bounded by the output cap (`max_tokens` covers thinking and tool
 * calls), or cost-neutral (sampling knobs, metadata). Anything else — a new
 * provider feature, a premium tier, a server-side tool with per-use fees —
 * is rejected with a 400 naming the field, never passed through unpriced.
 *
 * Values the door does not interpret stay `Unknown`: the provider validates
 * their shape, and the estimator counts their bytes.
 */

const unknown = Type.Unknown();

/** Anthropic Messages API (`/v1/messages`). */
const anthropicFields: TProperties = {
  model: Type.String({ minLength: 1 }),
  messages: Type.Array(unknown, { minItems: 1 }),
  // Required by Anthropic — and the reservation's output bound.
  max_tokens: Type.Integer({ minimum: 1 }),
  stream: Type.Optional(Type.Boolean()),
  system: Type.Optional(unknown),
  metadata: Type.Optional(unknown),
  stop_sequences: Type.Optional(unknown),
  temperature: Type.Optional(unknown),
  top_p: Type.Optional(unknown),
  top_k: Type.Optional(unknown),
  // Custom tools are text; built-in and server tools are vetted by the adapter profile.
  tools: Type.Optional(Type.Array(unknown)),
  tool_choice: Type.Optional(unknown),
  // Thinking and effort shape output that max_tokens already bounds.
  thinking: Type.Optional(unknown),
  output_config: Type.Optional(unknown),
  // Automatic prompt caching: input priced at the cache-write rate.
  cache_control: Type.Optional(unknown),
  // US-only inference is billed at 1.1× (Claude 4.6+); priced by the profile.
  inference_geo: Type.Optional(Type.Union([Type.Literal('global'), Type.Literal('us')])),
  service_tier: Type.Optional(Type.Union([Type.Literal('auto'), Type.Literal('standard_only')])),
};

/** OpenAI Chat Completions (`/v1/chat/completions`, direct OpenAI). */
const openaiFields: TProperties = {
  model: Type.String({ minLength: 1 }),
  messages: Type.Array(unknown, { minItems: 1 }),
  stream: Type.Optional(Type.Boolean()),
  stream_options: Type.Optional(unknown),
  max_tokens: Type.Optional(Type.Integer({ minimum: 1 })),
  max_completion_tokens: Type.Optional(Type.Integer({ minimum: 1 })),
  // Every completion can use the full output budget: priced as n × the cap.
  n: Type.Optional(Type.Integer({ minimum: 1, maximum: 128 })),
  temperature: Type.Optional(unknown),
  top_p: Type.Optional(unknown),
  frequency_penalty: Type.Optional(unknown),
  presence_penalty: Type.Optional(unknown),
  logit_bias: Type.Optional(unknown),
  logprobs: Type.Optional(unknown),
  top_logprobs: Type.Optional(unknown),
  seed: Type.Optional(unknown),
  stop: Type.Optional(unknown),
  user: Type.Optional(unknown),
  safety_identifier: Type.Optional(unknown),
  prompt_cache_key: Type.Optional(unknown),
  metadata: Type.Optional(unknown),
  store: Type.Optional(unknown),
  tools: Type.Optional(Type.Array(unknown)),
  tool_choice: Type.Optional(unknown),
  parallel_tool_calls: Type.Optional(unknown),
  functions: Type.Optional(unknown),
  function_call: Type.Optional(unknown),
  response_format: Type.Optional(unknown),
  reasoning_effort: Type.Optional(unknown),
  verbosity: Type.Optional(unknown),
  // Rejected predictions are billed at the OUTPUT rate: priced there.
  prediction: Type.Optional(unknown),
  // Text out only: audio tokens are billed at rates the table does not hold.
  modalities: Type.Optional(Type.Array(Type.Literal('text'))),
  // Priority processing bills above the table; flex bills below it.
  service_tier: Type.Optional(
    Type.Union([Type.Literal('auto'), Type.Literal('default'), Type.Literal('flex')])
  ),
};

/** OpenRouter speaks the OpenAI shape plus its routing fields. */
const openrouterFields: TProperties = {
  ...openaiFields,
  // Fallback models: the reservation prices the most expensive one.
  models: Type.Optional(Type.Array(Type.String({ minLength: 1 }), { maxItems: 16 })),
  route: Type.Optional(unknown),
  // Routing preferences; the door merges its price ceiling into `max_price`.
  provider: Type.Optional(Type.Object({}, { additionalProperties: true })),
  transforms: Type.Optional(unknown),
  reasoning: Type.Optional(unknown),
  // Overwritten by the adapter (usage accounting stays on — meter-blinding red-team).
  usage: Type.Optional(unknown),
  top_a: Type.Optional(unknown),
  min_p: Type.Optional(unknown),
  repetition_penalty: Type.Optional(unknown),
};

const closed = (fields: TProperties): TObject => Type.Object(fields, { additionalProperties: false });

export const anthropicMessagesBodySchema = closed(anthropicFields);
export const openaiChatBodySchema = closed(openaiFields);
export const openrouterChatBodySchema = closed(openrouterFields);

interface AjvError {
  instancePath?: string;
  keyword?: string;
  message?: string;
  params?: { additionalProperty?: unknown };
}

/**
 * Names the rejected field so an operator can see WHY a request was refused
 * (Fastify's default says only "must NOT have additional properties").
 */
export function spendRouteSchemaError(errors: readonly AjvError[], dataVar: string): Error {
  const first = errors[0];
  const extra = first?.params?.additionalProperty;
  if (first?.keyword === 'additionalProperties' && typeof extra === 'string') {
    return new Error(
      `${dataVar}${first.instancePath ?? ''}/${extra.slice(0, 64)} is not a field this door can meter — refusing (R4: only priced fields pass)`
    );
  }
  return new Error(`${dataVar}${first?.instancePath ?? ''} ${first?.message ?? 'is invalid'}`);
}
