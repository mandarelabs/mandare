#!/usr/bin/env node
import { runCertify, runCertifyVerify } from './certify.js';
import { buildDirectory } from './directory.js';
import { runKill, runReinstate } from './kill.js';
import { runMandateIssue, runPassportIssue } from './passport-cmd.js';
import { runTokenIssue } from './token.js';
import { runVaultImportEnv, runVaultList } from './vault-cmd.js';
import { parsePrevHead, runVerify, type VerifyOptions } from './verify.js';
import { runWitnessServe } from './witness-cmd.js';

const USAGE = `mandare — the accountability stack for AI agent fleets

Usage:
  mandare verify --db <path> [options]
      Verify a ledger's hash chain, door signatures, and RFC 6962 tree head.
      --door-key <hex>          raw Ed25519 door public key (64 hex chars)
                                from an INDEPENDENT source
      --key-directory <p|url>   out-of-band key directory (JWKS file or https
                                URL); enables multi-door and key-rotation checks
      --insecure-directory      allow an http:// key directory (trusted,
                                isolated networks only — cleartext is
                                substitutable in transit)
      --prev-head <size>:<root> previously recorded tree head; detects
                                rollback to an older copy and rewrites
      --prove <seq>             emit an RFC 6962 inclusion proof for one entry
                                (selective disclosure); full proof in --json
      --spend                   spend trail (intents, settlements, REFUSED
                                reservations) + budget-counter invariant check
                                (counters must equal a fresh ledger replay)
      --witness <url>           check the chain against the externally
                                witnessed head history — catches truncation
                                and rewrites that self-anchored verification
                                cannot. The history is the VERIFYING key's
                                (--door-key / --key-directory); without one
                                it is the source the file names, labeled
                                self-declared. Requires --witness-key.
      --witness-key <hex>       the witness's raw Ed25519 public key (64 hex),
                                obtained OUT-OF-BAND
      --json                    machine-readable output
      Without --door-key/--key-directory, verification is self-anchored: it
      proves internal consistency, not authorship.

  mandare certify --db <path> --witness <url> --witness-key <hex>
                  [--disclose <seq,seq,...>] [--out <path>] [--json]
      Emit the integrity certificate (SPEC §9.4): chain valid · sequence
      complete · heads match the witnessed history · root publicly anchored —
      over owner-SELECTED entries with inclusion proofs. Undisclosed entries
      stay salted hashes. Signed by the door key.

  mandare certify verify <file> --witness-key <hex> [--door-key <hex>] [--json]
      Third-party check of a certificate: NO ledger access needed. Every
      proof-backed check is re-derived; recorder-attested claims are labeled.

  mandare witness serve [--db <path>] [--host 127.0.0.1] [--port 9411]
                        [--key <pem>] [--anchor ots|mock]
                        [--anchor-interval-hours <n>]
                        [--serve-directory <path>] [--serve-status-list <path>]
      Run the open reference witness server: records salted chain-head
      fingerprints per source (zero ledger content), refuses non-append-only
      submissions, aggregates all sources into one Merkle tree, anchors the
      root via OpenTimestamps. Prints its public key for out-of-band
      distribution. Optionally hosts the key directory + IETF status list.

  mandare kill <agent> [--reason <text>]
  mandare kill --mandate <id> [--reason <text>]
  mandare kill --all [--reason <text>]
      Revoke an agent's credentials, ONE mandate (the agent survives, the
      permission slip dies), or ALL (halting the door) — the LOCAL, offline,
      fail-closed authority. Writes a revoke entry to the ledger and stops
      the vault honoring the actor's tokens. The gateway fails closed on its
      next request. Reads the door from the vault (MANDARE_VAULT_*), the
      ledger from MANDARE_LEDGER_DB, door from MANDARE_DOOR_ID.

  mandare passport issue --agent-name <label> [--valid-days <n>]
                         [--out <path>] [--agent-key-out <path>] [--json]
      Issue an Agent Delegation Credential (SD-JWT VC): owner + local
      attestation authority keys from the vault (created on first use), mock
      IDV attestation (no PII), fresh agent did:key, revocation slot
      registered on the ledger. Writes the credential and the agent's private
      key (0600, shown once).

  mandare mandate issue --agent <did:key> --out <path> [--purpose <text>]
                        [--currency EUR] [--per-tx 5] [--per-day 20]
                        [--per-task 20] [--total 100] [--approval-above <units>]
                        [--valid-hours 24] [--json]
      Issue an owner-signed mandate as SD-JWT VC (SPEC §5). Cap flags are
      WHOLE currency units. The mandate gets its own revocation slot;
      "mandare kill --mandate <id>" revokes it instantly.

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
  if (flags.has('insecure-directory') && keyDirectory === undefined) {
    throw new UsageError('--insecure-directory only applies to --key-directory');
  }
  const options: VerifyOptions = {
    ...(doorKey === undefined ? {} : { doorPublicKey: doorKey }),
    ...(keyDirectory === undefined ? {} : { keyDirectory }),
    ...(flags.has('insecure-directory') ? { insecureDirectory: true } : {}),
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
  const witnessUrl = getString(flags, 'witness');
  const witnessKey = getString(flags, 'witness-key');
  if (witnessUrl !== undefined) {
    if (witnessKey === undefined || !/^[0-9a-f]{64}$/.test(witnessKey)) {
      throw new UsageError(
        '--witness requires --witness-key <64 lowercase hex chars> (the witness public key, out-of-band)'
      );
    }
    options.witness = { url: witnessUrl.replace(/\/+$/, ''), publicKeyHex: witnessKey };
  } else if (witnessKey !== undefined) {
    throw new UsageError('--witness-key requires --witness <url>');
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
  const mandateId = getString(args.flags, 'mandate');
  const modes = [all, agent !== undefined, mandateId !== undefined].filter(Boolean).length;
  if (modes > 1) {
    throw new UsageError('kill takes EXACTLY one of <agent>, --mandate <id>, or --all');
  }
  const reason = getReason(args.flags);
  return runKill(process.env, {
    ...(agent === undefined ? {} : { agent }),
    ...(mandateId === undefined ? {} : { mandate: mandateId }),
    all,
    ...(reason === undefined ? {} : { reason }),
  });
}

function getNumber(flags: ParsedArgs['flags'], name: string): number | undefined {
  const raw = getString(flags, name);
  if (raw === undefined) {
    return undefined;
  }
  const value = Number(raw);
  if (!Number.isFinite(value) || value < 0) {
    throw new UsageError(`--${name} must be a non-negative number`);
  }
  return value;
}

async function runPassportCommand(args: ParsedArgs): Promise<number> {
  if (args.positionals[0] !== 'issue') {
    throw new UsageError("passport subcommand must be 'issue'");
  }
  const validDays = getNumber(args.flags, 'valid-days');
  const agentName = getString(args.flags, 'agent-name');
  const out = getString(args.flags, 'out');
  const agentKeyOut = getString(args.flags, 'agent-key-out');
  return runPassportIssue(process.env, {
    ...(agentName === undefined ? {} : { agentName }),
    ...(validDays === undefined ? {} : { validDays }),
    ...(out === undefined ? {} : { out }),
    ...(agentKeyOut === undefined ? {} : { agentKeyOut }),
    json: args.flags.has('json'),
  });
}

async function runMandateCommand(args: ParsedArgs): Promise<number> {
  if (args.positionals[0] !== 'issue') {
    throw new UsageError("mandate subcommand must be 'issue'");
  }
  const flags = args.flags;
  const agent = getString(flags, 'agent');
  const out = getString(flags, 'out');
  const purpose = getString(flags, 'purpose');
  const currency = getString(flags, 'currency');
  const perTx = getNumber(flags, 'per-tx');
  const perDay = getNumber(flags, 'per-day');
  const perTask = getNumber(flags, 'per-task');
  const total = getNumber(flags, 'total');
  const approvalAbove = getNumber(flags, 'approval-above');
  const validHours = getNumber(flags, 'valid-hours');
  return runMandateIssue(process.env, {
    ...(agent === undefined ? {} : { agent }),
    ...(out === undefined ? {} : { out }),
    ...(purpose === undefined ? {} : { purpose }),
    ...(currency === undefined ? {} : { currency }),
    ...(perTx === undefined ? {} : { perTx }),
    ...(perDay === undefined ? {} : { perDay }),
    ...(perTask === undefined ? {} : { perTask }),
    ...(total === undefined ? {} : { total }),
    ...(approvalAbove === undefined ? {} : { approvalAbove }),
    ...(validHours === undefined ? {} : { validHours }),
    json: args.flags.has('json'),
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

async function runCertifyCommand(args: ParsedArgs): Promise<number> {
  const flags = args.flags;
  if (args.positionals[0] === 'verify') {
    const file = args.positionals[1];
    if (file === undefined) {
      throw new UsageError('certify verify requires a certificate file path');
    }
    const witnessKey = getString(flags, 'witness-key');
    if (witnessKey === undefined || !/^[0-9a-f]{64}$/.test(witnessKey)) {
      throw new UsageError('certify verify requires --witness-key <64 hex chars> (out-of-band)');
    }
    const doorKey = getString(flags, 'door-key');
    if (doorKey !== undefined && !/^[0-9a-f]{64}$/.test(doorKey)) {
      throw new UsageError('--door-key must be 64 lowercase hex chars');
    }
    return runCertifyVerify(file, {
      witnessPublicKeyHex: witnessKey,
      ...(doorKey === undefined ? {} : { doorPublicKeyHex: doorKey }),
      json: flags.has('json'),
    });
  }
  if (args.positionals.length > 0) {
    throw new UsageError("certify takes no positional arguments (or the 'verify' subcommand)");
  }
  const db = getString(flags, 'db');
  const witnessUrl = getString(flags, 'witness');
  const witnessKey = getString(flags, 'witness-key');
  if (db === undefined || witnessUrl === undefined || witnessKey === undefined) {
    throw new UsageError('certify requires --db <path>, --witness <url>, and --witness-key <hex>');
  }
  if (!/^[0-9a-f]{64}$/.test(witnessKey)) {
    throw new UsageError('--witness-key must be 64 lowercase hex chars');
  }
  const discloseRaw = getString(flags, 'disclose');
  const discloseSeqs: number[] = [];
  if (discloseRaw !== undefined) {
    for (const part of discloseRaw.split(',')) {
      const seq = Number.parseInt(part.trim(), 10);
      if (!Number.isInteger(seq) || seq < 1 || String(seq) !== part.trim()) {
        throw new UsageError(`--disclose must be comma-separated positive seqs, got '${part}'`);
      }
      discloseSeqs.push(seq);
    }
  }
  const out = getString(flags, 'out');
  return runCertify(process.env, db, {
    witnessUrl: witnessUrl.replace(/\/+$/, ''),
    witnessPublicKeyHex: witnessKey,
    discloseSeqs,
    ...(out === undefined ? {} : { outPath: out }),
    json: flags.has('json'),
  });
}

async function runWitnessCommand(args: ParsedArgs): Promise<number> {
  if (args.positionals[0] !== 'serve') {
    throw new UsageError("witness subcommand must be 'serve'");
  }
  const flags = args.flags;
  const portRaw = getString(flags, 'port');
  const port = portRaw === undefined ? 9411 : Number.parseInt(portRaw, 10);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new UsageError('--port must be a valid TCP port');
  }
  const anchorRaw = getString(flags, 'anchor') ?? 'ots';
  if (anchorRaw !== 'ots' && anchorRaw !== 'mock') {
    throw new UsageError("--anchor must be 'ots' or 'mock'");
  }
  const intervalRaw = getString(flags, 'anchor-interval-hours');
  // 'off' or 0 ⇒ on-demand only (POST /v1/anchor/run); anything else must be
  // a positive number of hours.
  let anchorIntervalHours: number | null;
  if (intervalRaw === undefined) {
    anchorIntervalHours = 24;
  } else if (intervalRaw === 'off' || intervalRaw === '0') {
    anchorIntervalHours = null;
  } else {
    anchorIntervalHours = Number(intervalRaw);
    if (!Number.isFinite(anchorIntervalHours) || anchorIntervalHours <= 0) {
      throw new UsageError("--anchor-interval-hours must be a positive number, 0, or 'off'");
    }
  }
  const keyPath = getString(flags, 'key');
  const keyDirectoryPath = getString(flags, 'serve-directory');
  const statusListPath = getString(flags, 'serve-status-list');
  return runWitnessServe({
    dbPath: getString(flags, 'db') ?? './mandare-witness.db',
    host: getString(flags, 'host') ?? '127.0.0.1',
    port,
    ...(keyPath === undefined ? {} : { keyPath }),
    anchor: anchorRaw,
    anchorIntervalHours,
    ...(keyDirectoryPath === undefined ? {} : { keyDirectoryPath }),
    ...(statusListPath === undefined ? {} : { statusListPath }),
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
  if (command === 'passport') {
    return runPassportCommand(args);
  }
  if (command === 'mandate') {
    return runMandateCommand(args);
  }
  if (command === 'vault') {
    return runVaultCommand(args);
  }
  if (command === 'certify') {
    return runCertifyCommand(args);
  }
  if (command === 'witness') {
    return runWitnessCommand(args);
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
