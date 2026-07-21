import { describe, expect, test } from 'vitest';

import { OpenRouterProvisioningClient, OpenRouterProvisioningError } from '../src/provisioning.js';
import type { FetchLike } from '../src/providers/types.js';

/**
 * Q14 provisioning-key rail, mocked only: live OpenRouter smoke waits for the
 * founder's account. R2 assertions matter most here — provisioning errors
 * must never echo key material.
 */

interface Call {
  url: string;
  method: string;
  body: unknown;
  auth: string | undefined;
}

function mockApi(responses: Record<string, () => Response>): { fetchImpl: FetchLike; calls: Call[] } {
  const calls: Call[] = [];
  const fetchImpl: FetchLike = (url, init) => {
    const method = init.method ?? 'GET';
    calls.push({
      url,
      method,
      body: typeof init.body === 'string' ? JSON.parse(init.body) : undefined,
      auth: (init.headers as Record<string, string>).authorization,
    });
    const key = `${method} ${new URL(url).pathname}`;
    const responder = responses[key];
    if (responder === undefined) {
      return Promise.resolve(new Response('{}', { status: 404 }));
    }
    return Promise.resolve(responder());
  };
  return { fetchImpl, calls };
}

const createdKey = {
  key: 'sk-or-v1-runtime-key-not-a-real-secret',
  data: { hash: 'hash-1', name: 'mandare:agent:test', limit: 25, disabled: false },
};

describe('OpenRouterProvisioningClient', () => {
  test('creates a capped per-agent key and authenticates with the provisioning key', async () => {
    const api = mockApi({
      'POST /api/v1/keys': () => new Response(JSON.stringify(createdKey), { status: 200 }),
    });
    const client = new OpenRouterProvisioningClient({
      provisioningKey: 'prov-key-not-a-secret',
      baseUrl: 'https://openrouter.example/api/v1',
      fetchImpl: api.fetchImpl,
    });
    const provisioned = await client.createAgentKey({
      name: 'mandare:agent:test',
      limitUsd: 25,
      limitReset: 'monthly',
    });
    expect(provisioned).toEqual({
      key: 'sk-or-v1-runtime-key-not-a-real-secret',
      hash: 'hash-1',
      name: 'mandare:agent:test',
      limitUsd: 25,
      disabled: false,
    });
    expect(api.calls[0]?.auth).toBe('Bearer prov-key-not-a-secret');
    expect(api.calls[0]?.body).toEqual({
      name: 'mandare:agent:test',
      limit: 25,
      limit_reset: 'monthly',
    });
  });

  test('lists keys without ever seeing key material', async () => {
    const api = mockApi({
      'GET /api/v1/keys': () =>
        new Response(
          JSON.stringify({
            data: [
              { hash: 'h1', name: 'a', limit: 10, disabled: false },
              { hash: 'h2', name: 'b', limit: 5, disabled: true },
            ],
          }),
          { status: 200 }
        ),
    });
    const client = new OpenRouterProvisioningClient({
      provisioningKey: 'p',
      baseUrl: 'https://openrouter.example/api/v1',
      fetchImpl: api.fetchImpl,
    });
    const keys = await client.listKeys();
    expect(keys).toHaveLength(2);
    expect(keys[0]).not.toHaveProperty('key');
  });

  test('disable returns the authoritative updated state (not a re-list)', async () => {
    const api = mockApi({
      'PATCH /api/v1/keys/h1': () =>
        new Response(
          JSON.stringify({ data: { hash: 'h1', name: 'a', limit: 10, disabled: true } }),
          { status: 200 }
        ),
      'DELETE /api/v1/keys/h1': () => new Response('{}', { status: 200 }),
    });
    const client = new OpenRouterProvisioningClient({
      provisioningKey: 'p',
      baseUrl: 'https://openrouter.example/api/v1',
      fetchImpl: api.fetchImpl,
    });
    const state = await client.disableKey('h1');
    expect(state).toEqual({ hash: 'h1', name: 'a', limitUsd: 10, disabled: true });
    await client.deleteKey('h1');
    expect(api.calls.map((call) => call.method)).toEqual(['PATCH', 'DELETE']);
    expect(api.calls[0]?.body).toEqual({ disabled: true });
  });

  test('getKey reads a single key (immediately consistent) and returns null on 404', async () => {
    const api = mockApi({
      'GET /api/v1/keys/h1': () =>
        new Response(
          JSON.stringify({ data: { hash: 'h1', name: 'a', limit: 5, disabled: true } }),
          { status: 200 }
        ),
      'GET /api/v1/keys/gone': () => new Response('{"error":"not found"}', { status: 404 }),
    });
    const client = new OpenRouterProvisioningClient({
      provisioningKey: 'p',
      baseUrl: 'https://openrouter.example/api/v1',
      fetchImpl: api.fetchImpl,
    });
    expect(await client.getKey('h1')).toEqual({
      hash: 'h1',
      name: 'a',
      limitUsd: 5,
      disabled: true,
    });
    expect(await client.getKey('gone')).toBeNull();
  });

  test('rotation creates the replacement BEFORE deleting the old key', async () => {
    const api = mockApi({
      'POST /api/v1/keys': () => new Response(JSON.stringify(createdKey), { status: 200 }),
      'DELETE /api/v1/keys/old-hash': () => new Response('{}', { status: 200 }),
    });
    const client = new OpenRouterProvisioningClient({
      provisioningKey: 'p',
      baseUrl: 'https://openrouter.example/api/v1',
      fetchImpl: api.fetchImpl,
    });
    const rotated = await client.rotateAgentKey('old-hash', {
      name: 'mandare:agent:test',
      limitUsd: 25,
    });
    expect(rotated.hash).toBe('hash-1');
    expect(api.calls.map((call) => `${call.method} ${new URL(call.url).pathname}`)).toEqual([
      'POST /api/v1/keys',
      'DELETE /api/v1/keys/old-hash',
    ]);
  });

  test('errors carry status + operation but NEVER response bodies (R2)', async () => {
    const api = mockApi({
      'POST /api/v1/keys': () =>
        new Response(JSON.stringify({ echo: 'sk-or-v1-leaky-secret' }), { status: 402 }),
    });
    const client = new OpenRouterProvisioningClient({
      provisioningKey: 'p',
      baseUrl: 'https://openrouter.example/api/v1',
      fetchImpl: api.fetchImpl,
    });
    const failure = await client
      .createAgentKey({ name: 'x', limitUsd: 1 })
      .catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(OpenRouterProvisioningError);
    expect(String(failure)).not.toContain('leaky-secret');
    expect((failure as OpenRouterProvisioningError).status).toBe(402);
  });

  test('a malformed create response (no key) fails loudly instead of provisioning nothing', async () => {
    const api = mockApi({
      'POST /api/v1/keys': () => new Response(JSON.stringify({ data: { hash: 'h' } }), { status: 200 }),
    });
    const client = new OpenRouterProvisioningClient({
      provisioningKey: 'p',
      baseUrl: 'https://openrouter.example/api/v1',
      fetchImpl: api.fetchImpl,
    });
    await expect(client.createAgentKey({ name: 'x', limitUsd: 1 })).rejects.toThrow(/malformed/);
  });
});
