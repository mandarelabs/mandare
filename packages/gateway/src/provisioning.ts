import type { FetchLike } from './providers/types.js';

/**
 * OpenRouter provisioning rail (BUILD-DECISIONS Q14): per-agent runtime keys
 * with USD credit caps enforced BY OPENROUTER before any provider is hit —
 * belt-and-suspenders with our own gateway metering. Cap at OpenRouter AND
 * meter in the gateway; either alone failing must not open spend.
 *
 * NAMING (2026-07-22): OpenRouter renamed "provisioning keys" to
 * "Management keys" — same function, elevated privileges, and a Management
 * key "cannot be used to make API calls" to completion endpoints (admin
 * only). The REST surface is UNCHANGED by the rename: base
 * `https://openrouter.ai/api/v1/keys`, `POST` (create, 201), `GET` (list),
 * `PATCH /{hash}` (update/disable), `DELETE /{hash}`. Create returns
 * `{ key: "<runtime key>", data: { hash, name, label, limit, disabled, … } }`
 * — the runtime key is the top-level `key`; `data.label` is only a MASKED
 * display label. Verified live against the Management API 2026-07-22
 * (scripts/provisioning-smoke.mjs). We keep the env var name
 * `OPENROUTER_PROVISIONING_KEY` for continuity.
 *
 * R2: the returned runtime key is secret material. It goes to the vault
 * (S3) and NOWHERE else — never logs, never ledger entries, never errors.
 * This module never stores or prints it.
 */

export interface ProvisionedKey {
  /** The runtime API key — returned ONCE by OpenRouter at creation. */
  key: string;
  /** Stable identifier used for rotation/disable/delete. */
  hash: string;
  name: string;
  limitUsd: number;
  disabled: boolean;
}

export interface AgentKeySpec {
  /** e.g. 'mandare:agent:did:mandare:dev-agent'. */
  name: string;
  /** USD credit cap OpenRouter enforces on this key. */
  limitUsd: number;
  /** Optional cap reset cadence. */
  limitReset?: 'daily' | 'weekly' | 'monthly';
}

export class OpenRouterProvisioningError extends Error {
  readonly status: number;
  constructor(status: number, operation: string) {
    // No response bodies in the message — they could echo key material (R2).
    super(`openrouter provisioning ${operation} failed with status ${status}`);
    this.name = 'OpenRouterProvisioningError';
    this.status = status;
  }
}

interface KeyRecord {
  hash: string;
  name: string;
  limit: number;
  disabled: boolean;
}

function asKeyRecord(value: unknown): KeyRecord {
  const record = (typeof value === 'object' && value !== null ? value : {}) as Record<
    string,
    unknown
  >;
  return {
    hash: typeof record.hash === 'string' ? record.hash : '',
    name: typeof record.name === 'string' ? record.name : '',
    limit: typeof record.limit === 'number' ? record.limit : 0,
    disabled: record.disabled === true,
  };
}

function keyStateFromRecord(record: KeyRecord): Omit<ProvisionedKey, 'key'> {
  return { hash: record.hash, name: record.name, limitUsd: record.limit, disabled: record.disabled };
}

export class OpenRouterProvisioningClient {
  private readonly baseUrl: string;
  private readonly provisioningKey: string;
  private readonly fetchImpl: FetchLike;

  constructor(options: {
    provisioningKey: string;
    baseUrl?: string;
    fetchImpl?: FetchLike;
  }) {
    this.provisioningKey = options.provisioningKey;
    this.baseUrl = (options.baseUrl ?? 'https://openrouter.ai/api/v1').replace(/\/+$/, '');
    this.fetchImpl = options.fetchImpl ?? (fetch as FetchLike);
  }

  private async call(
    method: string,
    path: string,
    body?: unknown,
    allow404 = false
  ): Promise<unknown> {
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method,
      headers: {
        authorization: `Bearer ${this.provisioningKey}`,
        'content-type': 'application/json',
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: AbortSignal.timeout(30_000),
    });
    if (response.status === 404 && allow404) {
      return null;
    }
    if (!response.ok) {
      throw new OpenRouterProvisioningError(response.status, `${method} ${path}`);
    }
    return response.json() as Promise<unknown>;
  }

  /** Create a capped per-agent runtime key. The key is returned exactly once. */
  async createAgentKey(spec: AgentKeySpec): Promise<ProvisionedKey> {
    const payload = await this.call('POST', '/keys', {
      name: spec.name,
      limit: spec.limitUsd,
      ...(spec.limitReset === undefined ? {} : { limit_reset: spec.limitReset }),
    });
    const record = (payload ?? {}) as Record<string, unknown>;
    const key = typeof record.key === 'string' ? record.key : '';
    const data = asKeyRecord(record.data ?? record);
    if (key === '' || data.hash === '') {
      throw new OpenRouterProvisioningError(502, 'create (malformed response)');
    }
    return { key, hash: data.hash, name: data.name, limitUsd: data.limit, disabled: data.disabled };
  }

  /**
   * The most recent 100 keys. NOTE: OpenRouter's list is EVENTUALLY
   * CONSISTENT — a just-created or just-updated key may be missing or show a
   * stale `disabled` here (verified live 2026-07-22). For authoritative
   * per-key state, confirm from a mutation's own response or `getKey`, never
   * by re-listing.
   */
  async listKeys(): Promise<Omit<ProvisionedKey, 'key'>[]> {
    const payload = (await this.call('GET', '/keys')) as Record<string, unknown>;
    const rows = Array.isArray(payload.data) ? payload.data : [];
    return rows.map((row) => keyStateFromRecord(asKeyRecord(row)));
  }

  /** Single-key read — immediately consistent (unlike the list). null on 404. */
  async getKey(hash: string): Promise<Omit<ProvisionedKey, 'key'> | null> {
    const payload = await this.call('GET', `/keys/${encodeURIComponent(hash)}`, undefined, true);
    if (payload === null) {
      return null;
    }
    const record = (payload as Record<string, unknown>).data ?? payload;
    return keyStateFromRecord(asKeyRecord(record));
  }

  /**
   * Gateway-side kill assist: a disabled key stops spending AT OPENROUTER.
   * Returns the AUTHORITATIVE updated state from the PATCH response (the
   * list lags; do not re-list to confirm).
   */
  async disableKey(hash: string): Promise<Omit<ProvisionedKey, 'key'>> {
    const payload = await this.call('PATCH', `/keys/${encodeURIComponent(hash)}`, {
      disabled: true,
    });
    const record = (payload as Record<string, unknown>).data ?? payload;
    return keyStateFromRecord(asKeyRecord(record));
  }

  async deleteKey(hash: string): Promise<void> {
    await this.call('DELETE', `/keys/${encodeURIComponent(hash)}`);
  }

  /**
   * Rotation = create the replacement FIRST, then delete the old key — an
   * agent is never left keyless if the second call fails; the old key dies
   * at the latest when its cap runs out.
   */
  async rotateAgentKey(oldHash: string, spec: AgentKeySpec): Promise<ProvisionedKey> {
    const replacement = await this.createAgentKey(spec);
    await this.deleteKey(oldHash);
    return replacement;
  }
}
