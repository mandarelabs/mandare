#!/usr/bin/env node
import { runVerify } from './verify.js';

const USAGE = `mandare — the accountability stack for AI agent fleets

Usage:
  mandare verify --db <path> [--door-key <hex>] [--json]
      Verify a ledger's hash chain and door signatures.
      --door-key: raw Ed25519 door public key (64 hex chars) from an
      INDEPENDENT source. Without it, verification is self-anchored: it proves
      internal consistency, not authorship.

Exit codes:
  0  chain valid
  1  chain invalid or verification error
  2  usage error
`;

interface ParsedArgs {
  command: string | undefined;
  flags: Map<string, string | true>;
}

function parseArgs(argv: string[]): ParsedArgs {
  const [command, ...rest] = argv;
  const flags = new Map<string, string | true>();
  for (let i = 0; i < rest.length; i += 1) {
    const token = rest[i] as string;
    if (!token.startsWith('--')) {
      throw new UsageError(`unexpected argument: ${token}`);
    }
    const name = token.slice(2);
    const next = rest[i + 1];
    if (next !== undefined && !next.startsWith('--')) {
      flags.set(name, next);
      i += 1;
    } else {
      flags.set(name, true);
    }
  }
  return { command, flags };
}

class UsageError extends Error {}

async function main(): Promise<number> {
  const { command, flags } = parseArgs(process.argv.slice(2));

  if (command === undefined || command === 'help' || flags.has('help')) {
    process.stdout.write(USAGE);
    return command === undefined ? 2 : 0;
  }

  if (command === 'verify') {
    const db = flags.get('db');
    if (typeof db !== 'string') {
      throw new UsageError('verify requires --db <path>');
    }
    const doorKey = flags.get('door-key');
    if (doorKey !== undefined && (typeof doorKey !== 'string' || !/^[0-9a-f]{64}$/.test(doorKey))) {
      throw new UsageError('--door-key must be 64 lowercase hex chars (raw Ed25519 public key)');
    }
    const output = await runVerify(db, typeof doorKey === 'string' ? { doorPublicKey: doorKey } : {});
    if (flags.has('json')) {
      process.stdout.write(`${JSON.stringify(output.json, null, 2)}\n`);
    } else {
      process.stdout.write(`${output.lines.join('\n')}\n`);
    }
    return output.exitCode;
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
