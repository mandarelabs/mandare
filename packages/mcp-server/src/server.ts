import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { runCli, type CliResult } from './cli.js';

/**
 * Mandare MCP server (S7, BUILD-DECISIONS Q17): stdio, env-configured,
 * exposing the door's LOCAL authority surface as MCP tools.
 *
 * Security posture:
 * - Paths/ledger/vault/witness settings come from the OPERATOR's environment
 *   only. No tool accepts a filesystem path (R4).
 * - Issued token/passport secrets are written 0600 to the operator-configured
 *   home directory and referenced BY PATH in tool results — a live spend
 *   credential never enters model context (R2).
 * - `kill` (closes doors) is always available; `reinstate` (reopens one) must
 *   be explicitly enabled with MANDARE_MCP_ALLOW_REINSTATE=1 — an MCP host
 *   compromise should not be able to un-kill an agent by default.
 */

export interface McpEnvConfig {
  ledgerDb: string;
  /** Where issued artifacts (mandates, credentials, token grants) land. */
  home: string;
  witnessUrl: string | null;
  witnessPublicKey: string | null;
  gatewayUrl: string | null;
  allowReinstate: boolean;
  /** Full process env forwarded to CLI children (vault settings etc.). */
  processEnv: Record<string, string | undefined>;
}

export function loadMcpConfig(env: Record<string, string | undefined>): McpEnvConfig {
  const witnessUrl = env.MANDARE_WITNESS_URL ?? null;
  // Same two sources the dashboard accepts: the hex directly, or a file
  // holding it (the compose stack's shared-volume handoff).
  let witnessPublicKey = env.MANDARE_WITNESS_PUBLIC_KEY ?? null;
  const witnessKeyFile = env.MANDARE_WITNESS_PUBLIC_HEX;
  if (witnessPublicKey === null && witnessKeyFile !== undefined && witnessKeyFile !== '' && existsSync(witnessKeyFile)) {
    witnessPublicKey = readFileSync(witnessKeyFile, 'utf8').trim();
  }
  if (witnessUrl !== null && (witnessPublicKey === null || !/^[0-9a-f]{64}$/.test(witnessPublicKey))) {
    throw new Error(
      'MANDARE_WITNESS_URL is set but MANDARE_WITNESS_PUBLIC_KEY (or a readable MANDARE_WITNESS_PUBLIC_HEX file) ' +
        'is missing/malformed — refusing to trust an unverifiable witness (the key travels out-of-band)'
    );
  }
  return {
    ledgerDb: env.MANDARE_LEDGER_DB ?? './mandare-ledger.db',
    // K-6: default outside any checkout — issued keys/grants must not land
    // where `git add -A` or a docker build context can pick them up.
    home: resolve(env.MANDARE_MCP_HOME ?? join(homedir(), '.mandare', 'mcp')),
    witnessUrl,
    witnessPublicKey,
    gatewayUrl: env.MANDARE_GATEWAY_URL ?? null,
    allowReinstate: env.MANDARE_MCP_ALLOW_REINSTATE === '1',
    processEnv: env,
  };
}

interface ToolText {
  [key: string]: unknown;
  content: { type: 'text'; text: string }[];
  isError?: boolean;
}

function textResult(text: string, isError = false): ToolText {
  return isError ? { content: [{ type: 'text', text }], isError: true } : { content: [{ type: 'text', text }] };
}

/** CLI output → tool result: JSON body when parseable, raw text otherwise. */
function cliResult(result: CliResult, okCodes: number[] = [0]): ToolText {
  const ok = okCodes.includes(result.code);
  const body = result.stdout.trim().length > 0 ? result.stdout.trim() : result.stderr.trim();
  if (!ok) {
    return textResult(`exit ${result.code}\n${body}`, true);
  }
  return textResult(body);
}

const AGENT_NAME = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[A-Za-z0-9][A-Za-z0-9_.-]*$/, 'letters, digits, dot, dash, underscore');
const DID = z.string().min(4).max(512).regex(/^did:[a-z0-9]+:[A-Za-z0-9._:%-]+$/, 'a DID');
/**
 * K-4: every model-chosen string becomes a discrete argv entry, so none may
 * start with `-` — a value like `--help` or `--all` must never be read by the
 * CLI as a flag.
 */
const NOT_A_FLAG = (value: string): boolean => !value.startsWith('-');
const NOT_A_FLAG_MESSAGE = 'must not start with "-" (it would be read as a CLI flag)';
const MANDATE_ID = z.string().min(1).max(256).regex(/^[A-Za-z0-9:_.-]+$/).refine(NOT_A_FLAG, NOT_A_FLAG_MESSAGE);
const REASON = z.string().min(1).max(500).refine(NOT_A_FLAG, NOT_A_FLAG_MESSAGE);
const CAP = z.number().positive().finite().max(1_000_000);

function timestampSlug(): string {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

export function createMandareMcpServer(config: McpEnvConfig): McpServer {
  const server = new McpServer({ name: 'mandare', version: '0.1.0' });
  const env = config.processEnv;

  const withDb = (args: string[]): string[] => ['--db', config.ledgerDb, ...args];
  const witnessArgs = (): string[] => {
    if (config.witnessUrl === null || config.witnessPublicKey === null) {
      throw new Error(
        'no witness configured — set MANDARE_WITNESS_URL and MANDARE_WITNESS_PUBLIC_KEY in the MCP server environment'
      );
    }
    return ['--witness', config.witnessUrl, '--witness-key', config.witnessPublicKey];
  };

  server.registerTool(
    'mandare_verify',
    {
      title: 'Verify the Mandare ledger',
      description:
        'Verify the local ledger: hash chain, door signatures, RFC 6962 tree head, spend trail and ' +
        'budget-counter replay, approval trail, and revocation state. With check_witness=true also ' +
        'checks the chain against the externally witnessed head history (catches truncation and ' +
        'rewrites). Returns the machine-readable verification report. Read-only.',
      inputSchema: {
        check_witness: z
          .boolean()
          .optional()
          .describe('Also verify against the configured witness (detects truncation/rewrites)'),
      },
      annotations: { readOnlyHint: true },
    },
    async ({ check_witness }) => {
      const args = ['verify', ...withDb(['--spend', '--json'])];
      if (check_witness === true) {
        args.push(...witnessArgs());
      }
      return cliResult(await runCli(args, env), [0, 1]);
    }
  );

  server.registerTool(
    'mandare_budget_status',
    {
      title: 'Budget status',
      description:
        'Per-mandate spend from the ledger: settled and reserved amounts (integer micro-units of the ' +
        'ledger currency), intent counts, refusal count, and whether the live budget counters equal a ' +
        'fresh replay of the ledger. Use before starting expensive work. Read-only.',
      inputSchema: {},
      annotations: { readOnlyHint: true },
    },
    async () => {
      const result = await runCli(['verify', ...withDb(['--spend', '--json'])], env);
      if (result.code !== 0 && result.code !== 1) {
        return cliResult(result);
      }
      try {
        const parsed = JSON.parse(result.stdout) as { spend?: unknown; result?: unknown };
        return textResult(
          JSON.stringify({ result: parsed.result ?? null, spend: parsed.spend ?? null }, null, 2)
        );
      } catch {
        return cliResult(result, [0, 1]);
      }
    }
  );

  server.registerTool(
    'mandare_issue_passport',
    {
      title: 'Issue an agent passport',
      description:
        'Issue an Agent Delegation Credential (SD-JWT VC) for a NEW agent: owner + local attestation ' +
        'authority keys from the vault, fresh agent did:key, revocation slot registered on the ledger. ' +
        'The credential and the agent private key are written to the operator-configured home ' +
        'directory; the result references them by path and never contains key material.',
      inputSchema: {
        agent_name: AGENT_NAME.describe('Label for the new agent (also the artifact file prefix)'),
        valid_days: z.number().int().positive().max(3650).optional(),
      },
    },
    async ({ agent_name, valid_days }) => {
      mkdirSync(config.home, { recursive: true });
      const out = join(config.home, `${agent_name}.passport.sdjwt`);
      const keyOut = join(config.home, `${agent_name}.agent-key.json`);
      const args = [
        'passport',
        'issue',
        '--agent-name',
        agent_name,
        '--out',
        out,
        '--agent-key-out',
        keyOut,
        '--json',
      ];
      if (valid_days !== undefined) {
        args.push('--valid-days', String(valid_days));
      }
      const result = await runCli(args, env);
      if (result.code !== 0) {
        return cliResult(result);
      }
      return textResult(redactSecrets(result.stdout));
    }
  );

  server.registerTool(
    'mandare_issue_mandate',
    {
      title: 'Issue a mandate',
      description:
        'Issue an owner-signed mandate (SD-JWT VC) for an agent: spend caps in WHOLE currency units ' +
        '(per transaction / day / task / total), optional human-approval threshold, validity window. ' +
        'The mandate file path is returned; point the gateway at it (MANDARE_MANDATE_PATH).',
      inputSchema: {
        agent_did: DID.describe("The agent's did:key (from mandare_issue_passport)"),
        purpose: z.string().min(1).max(200).refine(NOT_A_FLAG, NOT_A_FLAG_MESSAGE).optional(),
        currency: z.string().regex(/^[A-Z]{3}$/).optional(),
        per_tx: CAP.optional().describe('Max per single call/transaction, whole currency units'),
        per_day: CAP.optional(),
        per_task: CAP.optional(),
        total: CAP.optional(),
        approval_above: CAP.optional().describe('Spends above this wait for an async human approval'),
        valid_hours: z.number().positive().max(24 * 365).optional(),
      },
    },
    async (input) => {
      mkdirSync(config.home, { recursive: true });
      const out = join(config.home, `mandate-${timestampSlug()}.sdjwt`);
      const args = ['mandate', 'issue', '--agent', input.agent_did, '--out', out, '--json'];
      const flagMap: [string, number | string | undefined][] = [
        ['--purpose', input.purpose],
        ['--currency', input.currency],
        ['--per-tx', input.per_tx],
        ['--per-day', input.per_day],
        ['--per-task', input.per_task],
        ['--total', input.total],
        ['--approval-above', input.approval_above],
        ['--valid-hours', input.valid_hours],
      ];
      for (const [flag, value] of flagMap) {
        if (value !== undefined) {
          args.push(flag, String(value));
        }
      }
      return cliResult(await runCli(args, env));
    }
  );

  server.registerTool(
    'mandare_issue_token',
    {
      title: 'Issue a scoped access token',
      description:
        'Mint a short-lived proof-of-possession token an agent presents to the gateway (TTL ≤ 30 ' +
        'minutes). The grant INCLUDING ITS ONE-TIME SECRET is written 0600 to the operator-configured ' +
        'home directory; the result references it by path only — hand the FILE to the agent process ' +
        '(e.g. @mandarelabs/sdk tokenCredentialsFromIssueJson), never paste its contents into chat.',
      inputSchema: {
        actor_did: DID.describe('The agent DID the token is scoped to'),
        mandate_id: MANDATE_ID,
        ttl_seconds: z.number().int().positive().max(1800).optional(),
      },
    },
    async ({ actor_did, mandate_id, ttl_seconds }) => {
      const args = ['token', 'issue', '--actor', actor_did, '--mandate', mandate_id, '--json'];
      if (ttl_seconds !== undefined) {
        args.push('--ttl', String(ttl_seconds));
      }
      const result = await runCli(args, env);
      if (result.code !== 0) {
        return cliResult(result);
      }
      // R2: the pop_secret must not reach model context. Persist the grant
      // 0600 and return only public fields + the file path.
      mkdirSync(config.home, { recursive: true });
      const grant = JSON.parse(result.stdout) as Record<string, unknown>;
      const tokenId = typeof grant.token_id === 'string' ? grant.token_id : `token-${timestampSlug()}`;
      const grantPath = join(config.home, `${tokenId}.token.json`);
      const { writeFileSync } = await import('node:fs');
      writeFileSync(grantPath, `${JSON.stringify(grant, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
      const publicView = { ...grant };
      delete publicView.pop_secret;
      return textResult(
        JSON.stringify({ ...publicView, credentials_file: grantPath, note: 'pop_secret is in the 0600 file only' }, null, 2)
      );
    }
  );

  server.registerTool(
    'mandare_kill',
    {
      title: 'Kill switch',
      description:
        'The LOCAL, offline, fail-closed kill: revoke ONE agent, ONE mandate (the agent survives, the ' +
        'permission slip dies), or --all (halts the whole door). Writes the revocation to the ledger; ' +
        'the gateway refuses the subject on its very next request. Bound virtual cards are revoked ' +
        'too. Kills only CLOSE doors — reversing one requires the operator (mandare reinstate).',
      inputSchema: {
        agent_did: DID.optional(),
        mandate_id: MANDATE_ID.optional(),
        all: z.boolean().optional().describe('Revoke the whole door (every subject it governs)'),
        reason: REASON.optional(),
      },
    },
    async ({ agent_did, mandate_id, all, reason }) => {
      const modes = [agent_did !== undefined, mandate_id !== undefined, all === true].filter(Boolean);
      if (modes.length !== 1) {
        return textResult('exactly one of agent_did, mandate_id, or all=true is required', true);
      }
      const args = ['kill'];
      if (all === true) {
        args.push('--all');
      } else if (mandate_id !== undefined) {
        args.push('--mandate', mandate_id);
      } else {
        args.push(agent_did as string);
      }
      if (reason !== undefined) {
        args.push('--reason', reason);
      }
      const result = await runCli(args, env);
      // Success means the CLI said so: an exit 0 without the KILLED
      // confirmation (help text, a no-op) is not a kill (K-4).
      if (result.code === 0 && !/^KILLED /m.test(result.stdout)) {
        return textResult(`kill NOT confirmed — the CLI printed no KILLED line\n${result.stdout.trim()}`, true);
      }
      return cliResult(result);
    }
  );

  if (config.allowReinstate) {
    server.registerTool(
      'mandare_reinstate',
      {
        title: 'Reinstate a killed agent',
        description:
          'Reverse an agent kill (enabled by MANDARE_MCP_ALLOW_REINSTATE=1). New tokens are honored ' +
          'again; previously-killed tokens stay dead.',
        inputSchema: { agent_did: DID, reason: REASON.optional() },
      },
      async ({ agent_did, reason }) => {
        const args = ['reinstate', agent_did];
        if (reason !== undefined) {
          args.push('--reason', reason);
        }
        return cliResult(await runCli(args, env));
      }
    );
  }

  server.registerTool(
    'mandare_certify',
    {
      title: 'Export an integrity certificate',
      description:
        'Build the selective-disclosure integrity certificate (chain valid · witnessed · anchored) a ' +
        'third party can verify WITHOUT ledger access. Optionally disclose specific entries by seq; ' +
        'undisclosed entries stay salted hashes. Requires a configured witness.',
      inputSchema: {
        disclose_seqs: z.array(z.number().int().positive()).max(100).optional(),
      },
      annotations: { readOnlyHint: true },
    },
    async ({ disclose_seqs }) => {
      mkdirSync(config.home, { recursive: true });
      const out = join(config.home, `certificate-${timestampSlug()}.json`);
      const args = ['certify', ...withDb([...witnessArgs(), '--out', out, '--json'])];
      if (disclose_seqs !== undefined && disclose_seqs.length > 0) {
        args.push('--disclose', disclose_seqs.join(','));
      }
      return cliResult(await runCli(args, env));
    }
  );

  server.registerTool(
    'mandare_gateway_health',
    {
      title: 'Gateway health',
      description:
        'Read the running gateway door /healthz (halted state, card rail, witness gating). Requires ' +
        'MANDARE_GATEWAY_URL in the MCP server environment. Read-only.',
      inputSchema: {},
      annotations: { readOnlyHint: true },
    },
    async () => {
      if (config.gatewayUrl === null) {
        return textResult('no gateway configured — set MANDARE_GATEWAY_URL in the MCP server environment', true);
      }
      try {
        const response = await fetch(`${config.gatewayUrl.replace(/\/+$/, '')}/healthz`, {
          signal: AbortSignal.timeout(5_000),
        });
        return textResult(JSON.stringify({ status: response.status, body: await response.json() }, null, 2));
      } catch (error) {
        return textResult(`gateway unreachable: ${error instanceof Error ? error.message : String(error)}`, true);
      }
    }
  );

  return server;
}

/**
 * Belt over R2: even though issuance results reference secrets by path, scan
 * outbound text for accidental JWK/PEM material and refuse to relay it.
 */
function redactSecrets(text: string): string {
  if (text.includes('"d"') || text.includes('PRIVATE KEY')) {
    return text
      .split('\n')
      .filter((line) => !line.includes('"d"') && !line.includes('PRIVATE KEY'))
      .join('\n');
  }
  return text;
}
