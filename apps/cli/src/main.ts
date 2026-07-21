#!/usr/bin/env node
import { buildDirectory } from './directory.js';
import { runKill, runReinstate } from './kill.js';
import { runTokenIssue } from './token.js';
import { runVaultImportEnv, runVaultList } from './vault-cmd.js';
import { parsePrevHead, runVerify, type VerifyOptions } from './verify.js';

const USAGE = `mandare — the accountability stack for AI agent fleets

Usage:
  mandare verify --db <path> [options]
      Verify a ledger's hash chain, door signatures, and RFC 6962 tree head.
      --door-key <hex>          raw Ed25519 door public key (64 hex chars)
                                from an INDEPENDENT source
      --key-directory <p|url>   out-of-band key directory (JWKS file or URL);
                                enables multi-door and key-rotation checks
      --prev-head <size>:<root> previously recorded tree head; detects
                                rollback to an older copy and rewrites
      --prove <seq>             emit an RFC 6962 inclusion proof for one entry
                                (selective disclosure); full proof in --json
      --spend                   spend trail (intents, settlements, REFUSED
                                reservations) + budget-counter invariant check
                                (counters must equal a fresh ledger replay)
      --json                    machine-readable output
      Without --door-key/--key-directory, verification is self-anchored: it
      proves internal consistency, not authorship.

  mandare kill <agent> [--reason <text>]
  mandare kill --all [--reason <text>]
      Revoke an agent's credentials (or ALL, halting the door) — the LOCAL,
      offline, fail-closed authority. Writes an agent.revoke entry to the
      ledger and stops the vault honoring the actor's tokens. The gateway
      fails closed on its next request. Reads the door from the vault
      (MANDARE_VAULT_*), the ledger from MANDARE_LEDGER_DB, door from
      MANDARE_DOOR_ID.

  mandare reinstate <agent> [--reason <text>]
      Reverse a kill (authorized un-revocation). New tokens are honored again;
      previously-killed tokens stay dead.

  mandare token issue --actor <did> --mandate <id> [--ttl <seconds>] [--json]
      Mint a short-lived proof-of-possession scoped token for an agent to
      present to the gateway. The pop secret prints ONCE. TTL ≤ 30 min.

  mandare vault import-env
      One-time .env → vault bootstrap of provider keys. Remove them from .env
      afterwards (the vault is their home).
  mandare vault list
      List the accounts the vault holds (names only, never values).

  mandare directory --key <pem> [--key <pem>...] [options]
      Build the key directory (JWKS, RFC 9421 message-signatures-directory
      profile) from door key PEMs. Publish it out-of-band; verifiers pass it
      to --key-directory.
      --role <role>   set "mnd:role" on every key (e.g. door)
      --nbf <secs>    validity start (epoch seconds) on every key
      --exp <secs>    validity end (epoch seconds) on every key
      --out <path>    write to a file instead of stdout

Exit codes:
  0  success / chain valid
  1  chain invalid, consistency failure, or error
  2  usage error
`;

interface ParsedArgs {
  command: string | undefined;
  positionals: string[];
  flags: Map<string, (string | true)[]>;
}

function parseArgs(argv: string[]): ParsedArgs {
  const [command, ...rest] = argv;
  const positionals: string[] = [];
  const flags = new Map<string, (string | true)[]>();
  for (let i = 0; i < rest.length; i += 1) {
    const token = rest[i] as string;
    if (!token.startsWith('--')) {
      positionals.push(token);
      continue;
    }
    const name = token.slice(2);
    const next = rest[i + 1];
    const value: string | true = next !== undefined && !next.startsWith('--') ? next : true;
    if (value !== true) {
      i += 1;
    }
    const existing = flags.get(name);
    if (existing === undefined) {
      flags.set(name, [value]);
    } else {
      existing.push(value);
    }
  }
  return { command, positionals, flags };
}

class UsageError extends Error {}

function getString(flags: ParsedArgs['flags'], name: string): string | undefined {
  const values = flags.get(name);
  if (values === undefined) {
    return undefined;
  }
  if (values.length > 1) {
    throw new UsageError(`--${name} may only be given once`);
  }
  if (typeof values[0] !== 'string') {
    throw new UsageError(`--${name} requires a value`);
  }
  return values[0];
}

function getStrings(flags: ParsedArgs['flags'], name: string): string[] {
  const values = flags.get(name) ?? [];
  return values.map((value) => {
    if (typeof value !== 'string') {
      throw new UsageError(`--${name} requires a value`);
    }
    return value;
  });
}

function getEpochSeconds(flags: ParsedArgs['flags'], name: string): number | undefined {
  const raw = getString(flags, name);
  if (raw === undefined) {
    return undefined;
  }
  const value = Number.parseInt(raw, 10);
  if (!Number.isInteger(value) || value < 0 || String(value) !== raw) {
    throw new UsageError(`--${name} must be a non-negative integer (epoch seconds)`);
  }
  return value;
}

async function runVerifyCommand(flags: ParsedArgs['flags']): Promise<number> {
  const db = getString(flags, 'db');
  if (db === undefined) {
    throw new UsageError('verify requires --db <path>');
  }
  const doorKey = getString(flags, 'door-key');
  if (doorKey !== undefined && !/^[0-9a-f]{64}$/.test(doorKey)) {
    throw new UsageError('--door-key must be 64 lowercase hex chars (raw Ed25519 public key)');
  }
  const keyDirectory = getString(flags, 'key-directory');
  if (doorKey !== undefined && keyDirectory !== undefined) {
    throw new UsageError('--door-key and --key-directory are mutually exclusive');
  }
  const options: VerifyOptions = {
    ...(doorKey === undefined ? {} : { doorPublicKey: doorKey }),
    ...(keyDirectory === undefined ? {} : { keyDirectory }),
  };
  const prevHead = getString(flags, 'prev-head');
  if (prevHead !== undefined) {
    try {
      options.prevHead = parsePrevHead(prevHead);
    } catch (error) {
      throw new UsageError(error instanceof Error ? error.message : String(error));
    }
  }
  const proveSeq = getString(flags, 'prove');
  if (proveSeq !== undefined) {
    const seq = Number.parseInt(proveSeq, 10);
    if (!Number.isInteger(seq) || seq < 1 || String(seq) !== proveSeq) {
      throw new UsageError('--prove must be a positive integer seq');
    }
    options.proveSeq = seq;
  }
  if (flags.has('spend')) {
    options.spend = true;
  }

  const output = await runVerify(db, options);
  if (flags.has('json')) {
    process.stdout.write(`${JSON.stringify(output.json, null, 2)}\n`);
  } else {
    process.stdout.write(`${output.lines.join('\n')}\n`);
  }
  return output.exitCode;
}

async function runDirectoryCommand(flags: ParsedArgs['flags']): Promise<number> {
  const keyPaths = getStrings(flags, 'key');
  if (keyPaths.length === 0) {
    throw new UsageError('directory requires at least one --key <pem>');
  }
  const role = getString(flags, 'role');
  const outPath = getString(flags, 'out');
  const nbf = getEpochSeconds(flags, 'nbf');
  const exp = getEpochSeconds(flags, 'exp');
  if (nbf !== undefined && exp !== undefined && exp <= nbf) {
    throw new UsageError('--exp must be after --nbf');
  }

  const output = await buildDirectory({
    keyPaths,
    ...(role === undefined ? {} : { role }),
    ...(nbf === undefined ? {} : { nbf }),
    ...(exp === undefined ? {} : { exp }),
    ...(outPath === undefined ? {} : { outPath }),
  });
  for (const line of output.infoLines) {
    process.stderr.write(`${line}\n`);
  }
  if (outPath === undefined) {
    process.stdout.write(output.directoryJson);
  }
  return output.exitCode;
}

function getReason(flags: ParsedArgs['flags']): string | undefined {
  return getString(flags, 'reason');
}

async function runKillCommand(args: ParsedArgs): Promise<number> {
  const all = args.flags.has('all');
  if (args.positionals.length > 1) {
    throw new UsageError('kill takes at most one <agent> positional argument');
  }
  const agent = args.positionals[0];
  if (all && agent !== undefined) {
    throw new UsageError('kill takes EITHER <agent> OR --all, not both');
  }
  const reason = getReason(args.flags);
  return runKill(process.env, {
    ...(agent === undefined ? {} : { agent }),
    all,
    ...(reason === undefined ? {} : { reason }),
  });
}

async function runReinstateCommand(args: ParsedArgs): Promise<number> {
  if (args.positionals.length !== 1) {
    throw new UsageError('reinstate requires exactly one <agent> positional argument');
  }
  const reason = getReason(args.flags);
  return runReinstate(process.env, {
    agent: args.positionals[0] as string,
    ...(reason === undefined ? {} : { reason }),
  });
}

function runTokenCommand(args: ParsedArgs): number {
  if (args.positionals[0] !== 'issue') {
    throw new UsageError("token subcommand must be 'issue'");
  }
  const actor = getString(args.flags, 'actor');
  const mandate = getString(args.flags, 'mandate');
  const ttlRaw = getString(args.flags, 'ttl');
  const ttlSeconds = ttlRaw === undefined ? undefined : Number.parseInt(ttlRaw, 10);
  if (ttlRaw !== undefined && (ttlSeconds === undefined || String(ttlSeconds) !== ttlRaw)) {
    throw new UsageError('--ttl must be an integer number of seconds');
  }
  return runTokenIssue(process.env, {
    ...(actor === undefined ? {} : { actor }),
    ...(mandate === undefined ? {} : { mandate }),
    ...(ttlSeconds === undefined ? {} : { ttlSeconds }),
    json: args.flags.has('json'),
  });
}

function runVaultCommand(args: ParsedArgs): number {
  const sub = args.positionals[0];
  if (sub === 'import-env') {
    return runVaultImportEnv(process.env);
  }
  if (sub === 'list') {
    return runVaultList(process.env);
  }
  throw new UsageError("vault subcommand must be 'import-env' or 'list'");
}

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));
  const { command, flags } = args;

  if (command === undefined || command === 'help' || flags.has('help')) {
    process.stdout.write(USAGE);
    return command === undefined ? 2 : 0;
  }
  if (command === 'verify') {
    return runVerifyCommand(flags);
  }
  if (command === 'directory') {
    return runDirectoryCommand(flags);
  }
  if (command === 'kill') {
    return runKillCommand(args);
  }
  if (command === 'reinstate') {
    return runReinstateCommand(args);
  }
  if (command === 'token') {
    return runTokenCommand(args);
  }
  if (command === 'vault') {
    return runVaultCommand(args);
  }
  throw new UsageError(`unknown command: ${command}`);
}

try {
  process.exitCode = await main();
} catch (error) {
  if (error instanceof UsageError) {
    process.stderr.write(`error: ${error.message}\n\n${USAGE}`);
    process.exitCode = 2;
  } else {
    process.stderr.write(`error: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
