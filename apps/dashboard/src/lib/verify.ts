import { execFile } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';

import { ledgerDbPath } from './data';
import { cliPath } from './cli-path';

/**
 * The dashboard's verification badge shells to `mandare verify` — the SAME
 * code path an auditor runs, so "VALID" on screen means exactly what it
 * means in the terminal. Results are cached briefly; a fleet view refresh
 * must not re-hash the chain on every request.
 */

export interface VerifyBadge {
  checkedAt: string;
  /**
   * W-1: 'self-anchored' = the door key came from the ledger file itself, so
   * a green witness badge only says the file agrees with a source IT names.
   * Set MANDARE_DOOR_PUBLIC_KEY (out-of-band) to bind the check to the door.
   */
  anchor: 'out-of-band' | 'self-anchored';
  chainOk: boolean;
  entries: number;
  treeSize: number | null;
  treeRoot: string | null;
  countersConsistent: boolean | null;
  witness:
    | { configured: false }
    | { configured: true; consistent: boolean; detail: string };
  failure: string | null;
}

const CACHE_TTL_MS = 10_000;
let cache: { at: number; badge: VerifyBadge } | null = null;

function witnessConfig(): { url: string; keyHex: string } | null {
  const url = process.env.MANDARE_WITNESS_URL;
  if (url === undefined || url === '') {
    return null;
  }
  let keyHex = process.env.MANDARE_WITNESS_PUBLIC_KEY ?? '';
  const keyFile = process.env.MANDARE_WITNESS_PUBLIC_HEX;
  if (keyHex === '' && keyFile !== undefined && existsSync(keyFile)) {
    keyHex = readFileSync(keyFile, 'utf8').trim();
  }
  if (!/^[0-9a-f]{64}$/.test(keyHex)) {
    return null;
  }
  return { url: url.replace(/\/+$/, ''), keyHex };
}

/**
 * The door's public key, supplied OUT-OF-BAND (never read from the ledger
 * file — that is the self-anchored mode this exists to leave). Invalid or
 * absent ⇒ null ⇒ the badge renders the SELF-ANCHORED caveat.
 */
function doorKeyConfig(): string | null {
  const keyHex = process.env.MANDARE_DOOR_PUBLIC_KEY ?? '';
  return /^[0-9a-f]{64}$/.test(keyHex) ? keyHex : null;
}

/** Shape of `mandare verify --json` (apps/cli/src/verify.ts). */
export interface VerifyJson {
  result: { ok: boolean; entries: number; failure?: { code: string; reason: string } };
  tree?: { size: number; root: string };
  spend?: { counters: { status: string } };
  witness?: {
    record: unknown;
    consistency: { status?: string; reason?: string } | null;
    /** W-1: the file's declared source disagrees with the verifying key. */
    source_mismatch?: string | null;
  };
}

/**
 * Witnessed-history verdict from the CLI's TYPED status field. Only
 * 'extended' and 'identical' are healthy; 'rollback'/'inconsistent' are the
 * attacks the witness exists to convict, and an absent record means the
 * witness has never seen this chain — none of those may render green.
 * (S7 review C2: a substring check here showed CONSISTENT during a fork.)
 */
export function witnessVerdict(
  witness: VerifyJson['witness']
): { consistent: boolean; detail: string } {
  const mismatch = witness?.source_mismatch;
  if (typeof mismatch === 'string' && mismatch !== '') {
    return { consistent: false, detail: `source mismatch: ${mismatch}` };
  }
  const status = witness?.consistency?.status;
  if (status === 'extended' || status === 'identical') {
    return { consistent: true, detail: status };
  }
  if (status === 'rollback' || status === 'inconsistent') {
    return {
      consistent: false,
      detail: `${status}: ${witness?.consistency?.reason ?? 'history conflict'}`,
    };
  }
  if (witness?.record === null || witness?.record === undefined) {
    return { consistent: false, detail: 'no witnessed history for this chain (or witness unreachable)' };
  }
  return { consistent: false, detail: 'unrecognized witness verdict' };
}

/** Pure translation of the CLI report → badge (unit-tested with fixtures). */
export function badgeFromVerifyJson(
  parsed: VerifyJson,
  witnessConfigured: boolean,
  checkedAt: string,
  anchor: VerifyBadge['anchor'] = 'self-anchored'
): VerifyBadge {
  const verdict = witnessVerdict(parsed.witness);
  return {
    checkedAt,
    anchor,
    chainOk: parsed.result.ok,
    entries: parsed.result.entries,
    treeSize: parsed.tree?.size ?? null,
    treeRoot: parsed.tree?.root ?? null,
    countersConsistent:
      parsed.spend === undefined ? null : parsed.spend.counters.status === 'consistent',
    witness: witnessConfigured
      ? { configured: true, consistent: verdict.consistent, detail: verdict.detail }
      : { configured: false },
    failure:
      parsed.result.failure === undefined
        ? null
        : `[${parsed.result.failure.code}] ${parsed.result.failure.reason}`,
  };
}

function runVerify(): Promise<VerifyBadge> {
  const db = ledgerDbPath();
  const witness = witnessConfig();
  const doorKey = doorKeyConfig();
  const anchor: VerifyBadge['anchor'] = doorKey === null ? 'self-anchored' : 'out-of-band';
  const args = ['verify', '--db', db, '--spend', '--json'];
  if (doorKey !== null) {
    args.push('--door-key', doorKey);
  }
  if (witness !== null) {
    args.push('--witness', witness.url, '--witness-key', witness.keyHex);
  }
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [cliPath(), ...args],
      { timeout: 30_000, maxBuffer: 32 * 1024 * 1024 },
      (_error, stdout) => {
        const checkedAt = new Date().toISOString();
        try {
          const parsed = JSON.parse(stdout) as VerifyJson;
          resolve(badgeFromVerifyJson(parsed, witness !== null, checkedAt, anchor));
        } catch {
          resolve({
            checkedAt,
            anchor,
            chainOk: false,
            entries: 0,
            treeSize: null,
            treeRoot: null,
            countersConsistent: null,
            witness: witness === null ? { configured: false } : { configured: true, consistent: false, detail: 'verification produced no report' },
            failure: existsSync(db)
              ? 'verification did not produce a report (see server logs)'
              : `no ledger at ${db} yet — start the gateway to create it`,
          });
        }
      }
    );
  });
}

export async function verifyBadge(): Promise<VerifyBadge> {
  const now = Date.now();
  if (cache !== null && now - cache.at < CACHE_TTL_MS) {
    return cache.badge;
  }
  const badge = await runVerify();
  cache = { at: now, badge };
  return badge;
}
