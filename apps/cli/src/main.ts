#!/usr/bin/env node
import { buildDirectory } from './directory.js';
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
  flags: Map<string, (string | true)[]>;
}

function parseArgs(argv: string[]): ParsedArgs {
  const [command, ...rest] = argv;
  const flags = new Map<string, (string | true)[]>();
  for (let i = 0; i < rest.length; i += 1) {
    const token = rest[i] as string;
    if (!token.startsWith('--')) {
      throw new UsageError(`unexpected argument: ${token}`);
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
  return { command, flags };
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

async function main(): Promise<number> {
  const { command, flags } = parseArgs(process.argv.slice(2));

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
