import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync, statSync, readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

import { createMandareMcpServer, loadMcpConfig } from '../src/server.js';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

/**
 * The S7 MCP acceptance: an MCP client drives REAL gateway actions end to
 * end — spend shows up in budget status, `mandare_kill` closes a LIVE door,
 * and the verification tool proves the whole trail. The gateway is the real
 * `start.js` process; only the LLM provider is mocked (no secrets, R2).
 */

interface TextContent {
  type: string;
  text?: string;
}

function toolText(result: unknown): string {
  const content = ((result as { content?: unknown }).content ?? []) as TextContent[];
  return content
    .filter((item) => item.type === 'text')
    .map((item) => item.text ?? '')
    .join('\n');
}

async function connectedClient(env: Record<string, string | undefined>): Promise<Client> {
  const server = createMandareMcpServer(loadMcpConfig(env));
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: 'test-host', version: '0.0.0' });
  await client.connect(clientTransport);
  return client;
}

describe('mandare MCP server drives a real gateway', () => {
  const workDir = mkdtempSync(join(tmpdir(), 'mandare-mcp-'));
  const dbPath = join(workDir, 'ledger.db');
  const mandatePath = join(workDir, 'mandate.json');
  let mock: Server;
  let gateway: ChildProcess;
  let gatewayUrl = '';
  let client: Client;
  let env: Record<string, string | undefined>;

  beforeAll(async () => {
    execFileSync('node', [
      join(repoRoot, 'scripts/dev-mandate.mjs'),
      '--out', mandatePath,
      '--per-tx', '5',
      '--per-day', '20',
      '--per-task', '20',
      '--total', '100',
      '--approval-above', '5',
    ]);

    mock = createServer((_req, res) => {
      res.setHeader('content-type', 'application/json');
      res.end(
        JSON.stringify({
          id: 'msg-mcp-test',
          type: 'message',
          content: [{ type: 'text', text: 'ok' }],
          usage: { input_tokens: 10, output_tokens: 500 },
        })
      );
    });
    await new Promise<void>((resolve) => mock.listen(0, '127.0.0.1', () => resolve()));
    const mockPort = (mock.address() as { port: number }).port;

    gateway = spawn('node', [join(repoRoot, 'packages/gateway/dist/start.js')], {
      env: {
        ...process.env,
        ANTHROPIC_BASE_URL: `http://127.0.0.1:${mockPort}`,
        ANTHROPIC_API_KEY: 'test-key-not-a-secret',
        MANDARE_MANDATE_PATH: mandatePath,
        MANDARE_LEDGER_DB: dbPath,
        MANDARE_GATEWAY_PORT: '0',
        MANDARE_LEDGER_CURRENCY: 'EUR',
        MANDARE_USD_PER_LEDGER_UNIT: '1.08',
        MANDARE_GATEWAY_AUTH: 'none',
        MANDARE_VAULT: undefined,
      },
      stdio: ['ignore', 'pipe', 'inherit'],
    });
    gatewayUrl = await new Promise<string>((resolve, reject) => {
      let output = '';
      gateway.stdout?.on('data', (chunk: Buffer) => {
        output += chunk.toString();
        const match = output.match(/listening on (http:\/\/[\d.]+:\d+)/);
        if (match !== null) {
          resolve(match[1] as string);
        }
      });
      gateway.on('exit', (code) => reject(new Error(`gateway exited early (${code})`)));
    });

    env = {
      PATH: process.env.PATH,
      MANDARE_LEDGER_DB: dbPath,
      MANDARE_MCP_HOME: workDir,
      MANDARE_GATEWAY_URL: gatewayUrl,
    };
    client = await connectedClient(env);
  }, 30_000);

  afterAll(async () => {
    await client?.close();
    gateway?.kill('SIGKILL');
    await new Promise<void>((resolve) => mock.close(() => resolve()));
    rmSync(workDir, { recursive: true, force: true });
  });

  async function callGateway(): Promise<number> {
    const response = await fetch(`${gatewayUrl}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        model: 'claude-haiku-4-5',
        max_tokens: 100,
        messages: [{ role: 'user', content: 'hi' }],
      }),
    });
    await response.text();
    return response.status;
  }

  test('spend through the door shows up in mandare_budget_status', async () => {
    expect(await callGateway()).toBe(200);
    const result = await client.callTool({ name: 'mandare_budget_status', arguments: {} });
    const parsed = JSON.parse(toolText(result)) as {
      result: { ok: boolean };
      spend: { mandates: Record<string, { settled_micros: number; intents: number }> };
    };
    expect(parsed.result.ok).toBe(true);
    const mandates = Object.values(parsed.spend.mandates);
    expect(mandates.length).toBeGreaterThan(0);
    expect(mandates.some((mandate) => mandate.settled_micros > 0)).toBe(true);
  });

  test('gateway health tool reads the live door', async () => {
    const result = await client.callTool({ name: 'mandare_gateway_health', arguments: {} });
    const parsed = JSON.parse(toolText(result)) as { status: number };
    expect(parsed.status).toBe(200);
  });

  test('mandare_kill closes the LIVE door; the refusal lands on the ledger', async () => {
    const kill = await client.callTool({
      name: 'mandare_kill',
      arguments: { agent_did: 'did:mandare:dev-agent', reason: 'mcp e2e' },
    });
    expect(kill.isError ?? false).toBe(false);
    expect(toolText(kill)).toContain('KILLED');

    expect(await callGateway()).toBe(403);

    const verify = await client.callTool({
      name: 'mandare_verify',
      arguments: {},
    });
    const parsed = JSON.parse(toolText(verify)) as {
      result: { ok: boolean };
      revocations?: unknown;
    };
    expect(parsed.result.ok).toBe(true);
    const revoked = JSON.stringify(parsed);
    expect(revoked).toContain('did:mandare:dev-agent');
  });

  test('kill requires exactly one target', async () => {
    const result = await client.callTool({ name: 'mandare_kill', arguments: {} });
    expect(result.isError).toBe(true);
  });

  test('witness-dependent tools fail loudly (isError) when no witness is configured', async () => {
    const certify = await client.callTool({ name: 'mandare_certify', arguments: {} });
    expect(certify.isError).toBe(true);
    expect(toolText(certify)).toContain('no witness configured');
    const verify = await client.callTool({ name: 'mandare_verify', arguments: { check_witness: true } });
    expect(verify.isError).toBe(true);
    expect(toolText(verify)).toContain('no witness configured');
  });

  test('reinstate is NOT exposed unless explicitly enabled', async () => {
    const tools = await client.listTools();
    expect(tools.tools.map((tool) => tool.name)).not.toContain('mandare_reinstate');

    const withReinstate = await connectedClient({ ...env, MANDARE_MCP_ALLOW_REINSTATE: '1' });
    const enabled = await withReinstate.listTools();
    expect(enabled.tools.map((tool) => tool.name)).toContain('mandare_reinstate');
    await withReinstate.close();
  });
});

describe('token issuance keeps the secret out of model context (R2)', () => {
  const workDir = mkdtempSync(join(tmpdir(), 'mandare-mcp-vault-'));

  afterAll(() => {
    rmSync(workDir, { recursive: true, force: true });
  });

  test('the grant goes to a 0600 file; the tool result only references it', async () => {
    const env: Record<string, string | undefined> = {
      PATH: process.env.PATH,
      MANDARE_LEDGER_DB: join(workDir, 'ledger.db'),
      MANDARE_MCP_HOME: workDir,
      MANDARE_VAULT_BACKEND: 'file',
      MANDARE_VAULT_DB: join(workDir, 'vault.db'),
      MANDARE_VAULT_KEY_FILE: join(workDir, 'vault.masterkey'),
    };
    const client = await connectedClient(env);
    const result = await client.callTool({
      name: 'mandare_issue_token',
      arguments: { actor_did: 'did:mandare:dev-agent', mandate_id: 'mnd_test', ttl_seconds: 300 },
    });
    const text = toolText(result);
    expect(result.isError ?? false).toBe(false);
    expect(text).not.toContain('pop_secret":');
    const parsed = JSON.parse(text) as { token_id: string; credentials_file: string };
    expect(parsed.token_id.length).toBeGreaterThan(0);

    const mode = statSync(parsed.credentials_file).mode & 0o777;
    expect(mode).toBe(0o600);
    const grant = JSON.parse(readFileSync(parsed.credentials_file, 'utf8')) as {
      pop_secret: string;
    };
    expect(grant.pop_secret.length).toBeGreaterThan(0);
    await client.close();
  });
});
