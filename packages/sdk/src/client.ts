import { createMandareFetch, type FetchLike, type MandareAuth } from './fetch.js';

/**
 * A thin, typed client for talking to a Mandare gateway door. It adds no
 * policy of its own — the door decides; this just makes calling it and
 * reading its refusals ergonomic.
 */

/** The gateway's 403 refusal body — the door saying no, with the ledger ref. */
export interface MandareRefusal {
  code: string;
  reasons: string[];
  /** Ledger entry hash of the recorded refusal, when one was written. */
  denied_entry?: string;
}

export class MandareRefusedError extends Error {
  readonly refusal: MandareRefusal;
  readonly status: number;

  constructor(status: number, refusal: MandareRefusal) {
    super(`mandare door refused (${refusal.code}): ${refusal.reasons.join('; ')}`);
    this.name = 'MandareRefusedError';
    this.status = status;
    this.refusal = refusal;
  }
}

/**
 * Parse a refusal body if the response is one; null otherwise. The door has
 * two refusal shapes: 403 policy denials carry `reasons: string[]` (+ the
 * refusal's own ledger hash in `denied_entry`), 401 auth refusals carry a
 * singular `reason: string` (BAD_POP, TOKEN_REVOKED, …). Both normalize
 * into one MandareRefusal — the Python client does the same.
 */
export async function parseRefusal(response: Response): Promise<MandareRefusal | null> {
  if (response.status !== 403 && response.status !== 401) {
    return null;
  }
  try {
    const body: unknown = await response.clone().json();
    if (typeof body === 'object' && body !== null && typeof (body as { code?: unknown }).code === 'string') {
      const raw = body as { code: string; reasons?: unknown; reason?: unknown; denied_entry?: unknown };
      const reasons = Array.isArray(raw.reasons)
        ? raw.reasons.filter((reason): reason is string => typeof reason === 'string')
        : typeof raw.reason === 'string'
          ? [raw.reason]
          : [];
      return {
        code: raw.code,
        reasons,
        ...(typeof raw.denied_entry === 'string' ? { denied_entry: raw.denied_entry } : {}),
      };
    }
  } catch {
    // Not JSON — not a structured refusal.
  }
  return null;
}

export interface MandareGatewayOptions {
  /** e.g. http://127.0.0.1:8484 */
  baseUrl: string;
  auth?: MandareAuth;
  fetch?: FetchLike;
}

export interface GatewayHealth {
  status: string;
  [key: string]: unknown;
}

export class MandareGateway {
  readonly baseUrl: string;
  /** The signed fetch — hand this to an Anthropic/OpenAI SDK as its `fetch`. */
  readonly fetch: FetchLike;

  constructor(options: MandareGatewayOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.fetch = createMandareFetch({
      auth: options.auth ?? { mode: 'none' },
      ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
    });
  }

  async health(): Promise<GatewayHealth> {
    const response = await this.fetch(`${this.baseUrl}/healthz`);
    if (!response.ok) {
      throw new Error(`gateway /healthz returned ${response.status}`);
    }
    return (await response.json()) as GatewayHealth;
  }

  /**
   * POST a JSON body to a door route (`/v1/messages`, `/v1/chat/completions`).
   * Throws MandareRefusedError on a door refusal so callers can read the
   * code + ledger reference instead of pattern-matching status text.
   */
  async post<T = unknown>(path: string, body: unknown): Promise<T> {
    const response = await this.fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const refusal = await parseRefusal(response);
    if (refusal !== null) {
      throw new MandareRefusedError(response.status, refusal);
    }
    if (!response.ok) {
      throw new Error(`gateway ${path} returned ${response.status}: ${await response.text()}`);
    }
    return (await response.json()) as T;
  }

  /** Anthropic-native door route. */
  async messages<T = unknown>(body: unknown): Promise<T> {
    return this.post<T>('/v1/messages', body);
  }

  /** OpenAI/OpenRouter-native door route. */
  async chatCompletions<T = unknown>(body: unknown): Promise<T> {
    return this.post<T>('/v1/chat/completions', body);
  }
}
