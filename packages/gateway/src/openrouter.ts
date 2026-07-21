/**
 * OpenRouter adapter (BUILD-DECISIONS Q14: rail #1 — its response carries an
 * authoritative `usage.cost` in USD, so ledger cost fields are real without
 * local pricing tables). S2 adds Anthropic/OpenAI adapters and streaming
 * true-up per Q15/Q16.
 */

export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

export interface ProviderUsage {
  costMicros: number;
  tokensIn: number;
  tokensOut: number;
}

export interface ProviderResponse {
  status: number;
  bodyText: string;
  /** null when the response carried no parseable usage block. */
  usage: ProviderUsage | null;
}

const REQUEST_TIMEOUT_MS = 120_000;
const MICROS_PER_USD = 1_000_000;

export async function forwardChatCompletion(options: {
  baseUrl: string;
  apiKey: string;
  body: Record<string, unknown>;
  fetchImpl?: FetchLike;
}): Promise<ProviderResponse> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const response = await fetchImpl(`${options.baseUrl}/chat/completions`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${options.apiKey}`,
      'content-type': 'application/json',
    },
    // usage.include asks OpenRouter to return cost + token accounting inline.
    body: JSON.stringify({ ...options.body, usage: { include: true } }),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  const bodyText = await response.text();
  return { status: response.status, bodyText, usage: extractUsage(bodyText) };
}

function extractUsage(bodyText: string): ProviderUsage | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null || !('usage' in parsed)) {
    return null;
  }
  const usage = (parsed as { usage: unknown }).usage;
  if (typeof usage !== 'object' || usage === null) {
    return null;
  }
  const record = usage as Record<string, unknown>;
  return {
    costMicros: usdToMicros(record.cost),
    tokensIn: nonNegativeInt(record.prompt_tokens),
    tokensOut: nonNegativeInt(record.completion_tokens),
  };
}

function usdToMicros(cost: unknown): number {
  if (typeof cost !== 'number' || !Number.isFinite(cost) || cost < 0) {
    return 0;
  }
  return Math.round(cost * MICROS_PER_USD);
}

function nonNegativeInt(value: unknown): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    return 0;
  }
  return value;
}
