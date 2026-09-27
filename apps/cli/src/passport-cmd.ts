import { existsSync, linkSync, mkdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join } from 'node:path';

import { SUBJECT_REGISTER, agentSubject, mandateSubject, revocationProjector } from '@mandarelabs/ledger';
import {
  AGENT_STATUS_LIST_ID,
  formatRevocationRef,
  Vault,
  loadVaultConfigFromEnv,
} from '@mandarelabs/vault';
import {
  AttestationAuthority,
  MockIdvProvider,
  didFromPublicJwk,
  generateEd25519KeyPair,
  isDidKey,
  issueDelegationCredential,
  issueMandateVc,
  signMandatePayload,
  type Ed25519KeyPairJwk,
} from '@mandarelabs/passport';
import {
  CURRENCY_MICROS_PER_UNIT,
  canonicalJson,
  sha256Hex,
  type MandateV1,
} from '@mandarelabs/spec';

import { closeDoorContext, openDoorContext, type DoorContext } from './door-context.js';

/**
 * `mandare passport issue` / `mandare mandate issue` — the S4 issuance flows.
 *
 * Identity keys (owner + local attestation authority) live in the VAULT as
 * JWK pairs (accounts `identity:owner`, `identity:authority`) — the same
 * encrypted, keychain-anchored home as every other secret. Status-list
 * indices are allocated by REGISTERING the subject on the ledger
 * (`subject.register`), so a credential carries its `revocation_ref` from
 * birth and `mandare kill` later flips the very same slot — one revocation
 * vocabulary, one projection.
 *
 * LOCAL AUTHORITY MODE (founder ruling): the countersigning authority key is
 * self-contained; the cloud attestation authority is a later, separate
 * service. Real IDV is a config swap behind the IdvProvider interface.
 */

export const OWNER_KEY_ACCOUNT = 'identity:owner';
export const AUTHORITY_KEY_ACCOUNT = 'identity:authority';

const DEFAULT_PASSPORT_VALID_DAYS = 90;
const DAY_SECONDS = 86_400;

async function getOrCreateIdentityKey(vault: Vault, account: string): Promise<Ed25519KeyPairJwk> {
  const existing = vault.getIdentityKey(account);
  if (existing !== null) {
    return JSON.parse(existing) as Ed25519KeyPairJwk;
  }
  const pair = await generateEd25519KeyPair();
  vault.putIdentityKey(account, JSON.stringify(pair));
  return pair;
}

/** Register a subject on the ledger and return its status-list index. */
async function registerSubject(ctx: DoorContext, subject: string): Promise<number> {
  const requestHash = sha256Hex(canonicalJson({ op: SUBJECT_REGISTER, subject }));
  const result = await ctx.ledger.appendProjected(
    {
      actor: ctx.killActor,
      mandate_id: 'mandare:issuance',
      action: { type: SUBJECT_REGISTER, target: subject, request_hash: requestHash },
      cost: { amount: 0, currency: ctx.ledgerCurrency, tokens_in: 0, tokens_out: 0 },
    },
    revocationProjector()
  );
  if (result.kind !== 'appended') {
    throw new Error('subject registration append was refused — this should never happen');
  }
  const record = await ctx.ledger.runProjection((tx) => tx.getRevocation(subject));
  if (record === null) {
    throw new Error('subject registration did not materialize in the revocation projection');
  }
  return record.statusIndex;
}

export interface PassportIssueOptions {
  agentName?: string;
  validDays?: number;
  out?: string;
  agentKeyOut?: string;
  json?: boolean;
}

/**
 * Create `path` with `data`, atomically and only if it does not exist: the
 * bytes go to a private temp file beside it, which is then hard-linked into
 * place (link(2) fails with EEXIST instead of replacing, unlike rename(2)).
 */
function createNewFile(path: string, data: string, mode: number): void {
  const temp = join(dirname(path), `.${basename(path)}.${process.pid}.${Date.now()}.tmp`);
  writeFileSync(temp, data, { mode, flag: 'wx' });
  try {
    linkSync(temp, path);
  } finally {
    unlinkSync(temp);
  }
}

function refuseExisting(error: unknown, path: string): number {
  if ((error as { code?: string }).code !== 'EEXIST') {
    throw error;
  }
  process.stderr.write(`error: ${path} already exists — refusing to overwrite agent identity files\n`);
  return 1;
}

export async function runPassportIssue(
  env: Record<string, string | undefined>,
  options: PassportIssueOptions
): Promise<number> {
  const agentName = options.agentName;
  if (agentName === undefined || agentName === '') {
    process.stderr.write('error: passport issue requires --agent-name <label>\n');
    return 2;
  }
  const validDays = options.validDays ?? DEFAULT_PASSPORT_VALID_DAYS;
  // K-6: by default identity files land in ~/.mandare/agents (0700), never
  // in the working directory — a checkout's `git add -A` or a docker build
  // context must not be able to pick up an agent's private key.
  const defaultDir = join(homedir(), '.mandare', 'agents');
  if (options.out === undefined || options.agentKeyOut === undefined) {
    mkdirSync(defaultDir, { recursive: true, mode: 0o700 });
  }
  const outPath = options.out ?? join(defaultDir, `${agentName}.passport.sdjwt`);
  const keyOutPath = options.agentKeyOut ?? join(defaultDir, `${agentName}.agent-key.json`);
  // K-5: refuse BEFORE anything is registered or written — a re-issue must
  // leave an existing passport/key pair (and the ledger) exactly as it was.
  for (const path of [outPath, keyOutPath]) {
    if (existsSync(path)) {
      process.stderr.write(
        `error: ${path} already exists — refusing to overwrite agent identity files (pass --out / --agent-key-out <new path>)\n`
      );
      return 1;
    }
  }

  const vault = Vault.open(loadVaultConfigFromEnv(env));
  const ctx = await openDoorContext(env);
  try {
    const owner = await getOrCreateIdentityKey(vault, OWNER_KEY_ACCOUNT);
    const ownerDid = didFromPublicJwk(owner.publicJwk);
    const authorityKeys = await getOrCreateIdentityKey(vault, AUTHORITY_KEY_ACCOUNT);
    const authority = new AttestationAuthority(authorityKeys);

    // Mock IDV (founder ruling): interface + mock partner; the record carries
    // ONLY {kyc_level, partner_id, date, ref_hash} — never PII.
    const idv = new MockIdvProvider();
    const kyc = await idv.verifyOwner(ownerDid);
    const nowSeconds = Math.floor(Date.now() / 1000);
    const attestation = await authority.attestOwner(ownerDid, kyc, nowSeconds);

    const agent = await generateEd25519KeyPair();
    const agentDid = didFromPublicJwk(agent.publicJwk);
    const statusIndex = await registerSubject(ctx, agentSubject(agentDid));
    const revocationRef = formatRevocationRef(AGENT_STATUS_LIST_ID, statusIndex);

    const credential = await issueDelegationCredential({
      ownerKeyPair: owner,
      agentPublicJwk: agent.publicJwk,
      attestation,
      revocationRef,
      keyProvenance: vault.provenance,
      issuedAtSeconds: nowSeconds,
      notBeforeSeconds: nowSeconds - 60,
      expiresSeconds: nowSeconds + validDays * DAY_SECONDS,
    });

    // The agent's private key is written ONCE, 0600, for the agent process —
    // it never enters the vault (the vault is the DOOR's side; the agent key
    // is the one credential the agent itself legitimately holds). Both files
    // are created atomically and never overwrite (L3, K-5): the key first,
    // then the passport; if the passport path was taken in the meantime the
    // fresh key is removed again, so the pair on disk always matches.
    try {
      createNewFile(keyOutPath, `${JSON.stringify(agent, null, 2)}\n`, 0o600);
    } catch (error) {
      return refuseExisting(error, keyOutPath);
    }
    try {
      createNewFile(outPath, `${credential}\n`, 0o644);
    } catch (error) {
      unlinkSync(keyOutPath);
      return refuseExisting(error, outPath);
    }

    if (options.json === true) {
      process.stdout.write(
        `${JSON.stringify(
          {
            agent_name: agentName,
            agent_did: agentDid,
            owner_did: ownerDid,
            authority_did: authority.did,
            revocation_ref: revocationRef,
            kyc: { level: kyc.kyc_level, partner: kyc.partner_id, date: kyc.date },
            passport_path: outPath,
            agent_key_path: keyOutPath,
            valid_days: validDays,
          },
          null,
          2
        )}\n`
      );
      return 0;
    }
    process.stdout.write(`PASSPORT ISSUED for '${agentName}'\n`);
    process.stdout.write(`  agent:        ${agentDid}\n`);
    process.stdout.write(`  owner:        ${ownerDid}\n`);
    process.stdout.write(`  authority:    ${authority.did}  ← set MANDARE_TRUST_AUTHORITY to this\n`);
    process.stdout.write(
      `  kyc:          level ${kyc.kyc_level} via ${kyc.partner_id} on ${kyc.date} (mock partner; no PII stored)\n`
    );
    process.stdout.write(`  revocation:   ${revocationRef} (registered on the ledger)\n`);
    process.stdout.write(`  credential:   ${outPath}\n`);
    process.stdout.write(`  agent key:    ${keyOutPath} (0600 — shown once, give it to the agent)\n`);
    process.stdout.write(`  valid:        ${validDays} day(s)\n`);
    return 0;
  } finally {
    await closeDoorContext(ctx);
    vault.close();
  }
}

export interface MandateIssueOptions {
  agent?: string;
  purpose?: string;
  currency?: string;
  perTx?: number;
  perDay?: number;
  perTask?: number;
  total?: number;
  approvalAbove?: number;
  validHours?: number;
  out?: string;
  json?: boolean;
}

const DEFAULT_VALID_HOURS = 24;

function unitsToMicros(units: number): number {
  return Math.round(units * CURRENCY_MICROS_PER_UNIT);
}

export async function runMandateIssue(
  env: Record<string, string | undefined>,
  options: MandateIssueOptions
): Promise<number> {
  if (options.agent === undefined || options.agent === '') {
    process.stderr.write('error: mandate issue requires --agent <did:key>\n');
    return 2;
  }
  // The v1 DID profile is did:key; a non-did:key agent yields a mandate the
  // gateway will refuse to load (fail-closed downstream) — catch it here (L6).
  if (!isDidKey(options.agent)) {
    process.stderr.write(
      `error: --agent must be a did:key (v1 DID profile); got '${options.agent.slice(0, 24)}…'\n`
    );
    return 2;
  }
  const outPath = options.out;
  if (outPath === undefined) {
    process.stderr.write('error: mandate issue requires --out <path>\n');
    return 2;
  }
  const currency = options.currency ?? 'EUR';
  const validHours = options.validHours ?? DEFAULT_VALID_HOURS;

  const vault = Vault.open(loadVaultConfigFromEnv(env));
  const ctx = await openDoorContext(env);
  try {
    const owner = await getOrCreateIdentityKey(vault, OWNER_KEY_ACCOUNT);
    const ownerDid = didFromPublicJwk(owner.publicJwk);

    const nowMs = Date.now();
    const mandateId = `mnd_${sha256Hex(canonicalJson({ ownerDid, agent: options.agent, nowMs })).slice(0, 12)}`;
    const statusIndex = await registerSubject(ctx, mandateSubject(mandateId));
    const revocationRef = formatRevocationRef(AGENT_STATUS_LIST_ID, statusIndex);

    const isoNoMillis = (ms: number): string => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
    const unsigned: Omit<MandateV1, 'signature'> = {
      schema_version: 1,
      id: mandateId,
      principal: ownerDid,
      agent: options.agent,
      purpose: options.purpose ?? 'Budgeted LLM calls through the local Mandare gateway',
      scopes: [
        {
          type: 'spend',
          currency,
          per_tx_max: unitsToMicros(options.perTx ?? 5),
          per_day_max: unitsToMicros(options.perDay ?? 20),
          per_task_max: unitsToMicros(options.perTask ?? 20),
          total_cap: unitsToMicros(options.total ?? 100),
          rails: ['gateway'],
          counterparties: 'any',
          categories: ['llm'],
        },
        { type: 'action', classes: ['llm.call'] },
      ],
      approvals: {
        rules:
          options.approvalAbove === undefined
            ? []
            : [{ above: unitsToMicros(options.approvalAbove), currency, method: 'push' }],
      },
      valid_from: isoNoMillis(nowMs - 60_000),
      valid_until: isoNoMillis(nowMs + validHours * 3_600_000),
      revocation_ref: revocationRef,
    };

    const mandate = await signMandatePayload(unsigned, owner, vault.provenance);
    const compact = await issueMandateVc(mandate, owner, Math.floor(nowMs / 1000));
    writeFileSync(outPath, `${compact}\n`);

    if (options.json === true) {
      process.stdout.write(
        `${JSON.stringify(
          { mandate_id: mandateId, principal: ownerDid, agent: options.agent, revocation_ref: revocationRef, path: outPath },
          null,
          2
        )}\n`
      );
      return 0;
    }
    const spend = mandate.scopes[0] as Extract<MandateV1['scopes'][number], { type: 'spend' }>;
    process.stdout.write(`MANDATE ISSUED ${mandateId} → ${outPath} (SD-JWT VC, owner-signed)\n`);
    process.stdout.write(`  principal:    ${ownerDid}\n`);
    process.stdout.write(`  agent:        ${options.agent}\n`);
    process.stdout.write(
      `  caps:         tx ${spend.per_tx_max / CURRENCY_MICROS_PER_UNIT} / day ${spend.per_day_max / CURRENCY_MICROS_PER_UNIT} / total ${spend.total_cap / CURRENCY_MICROS_PER_UNIT} ${currency}\n`
    );
    if (mandate.approvals.rules.length > 0) {
      process.stdout.write(
        `  approvals:    push above ${(mandate.approvals.rules[0]?.above ?? 0) / CURRENCY_MICROS_PER_UNIT} ${currency}\n`
      );
    }
    process.stdout.write(`  revocation:   ${revocationRef} — kill with: mandare kill --mandate ${mandateId}\n`);
    process.stdout.write(`  valid:        ${mandate.valid_from} → ${mandate.valid_until}\n`);
    return 0;
  } finally {
    await closeDoorContext(ctx);
    vault.close();
  }
}
