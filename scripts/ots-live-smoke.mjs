#!/usr/bin/env node
/**
 * OpenTimestamps LIVE smoke — founder gate F3. LOCAL ONLY, never CI: it talks
 * to the public OpenTimestamps calendars. Two runs, hours apart, same state:
 *
 *   pnpm ots-live-smoke     1st run — STAMP: a real reference witness anchors
 *                           one epoch root at the calendar pool; the receipt
 *                           is `pending` (exit 0).
 *   pnpm ots-live-smoke     later (typically 3–6 h) — UPGRADE: the same witness
 *                           DB runs its upgrade pass (runUpgrade, audit I-5).
 *                           PASS once a calendar serves the Bitcoin attestation
 *                           (exit 0); otherwise "still pending" (exit 3).
 *
 * What leaves the machine: one 32-byte aggregate root (a hash over salted
 * heads of a throwaway test ledger) — nothing else. State lives OUTSIDE the
 * repo: ~/.mandare/ots-live-smoke, or --state <dir>. --reset starts over;
 * --calendar <url> (repeatable) overrides the default pool.
 *
 * Offline verifiers still grade a Bitcoin attestation recorder-attested
 * (S8/C2): on PASS the .ots is written next to the state so it can be checked
 * against a Bitcoin node with any stock OpenTimestamps client.
 */
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const ledgerLib = await import(join(root, 'packages/ledger/dist/index.js'));
const witnessLib = await import(join(root, 'packages/witness/dist/index.js'));
const protocolLib = await import(join(root, 'packages/witness-protocol/dist/index.js'));
const specLib = await import(join(root, 'packages/spec/dist/index.js'));

const args = process.argv.slice(2);
const stateIndex = args.indexOf('--state');
const stateDir = stateIndex === -1 ? join(homedir(), '.mandare', 'ots-live-smoke') : args[stateIndex + 1];
const calendars = args.flatMap((arg, i) => (arg === '--calendar' ? [args[i + 1]] : []));
if (stateDir === undefined || calendars.includes(undefined)) {
  console.error('usage: ots-live-smoke [--state <dir>] [--calendar <url>]... [--reset]');
  process.exit(1);
}
if (args.includes('--reset')) rmSync(stateDir, { recursive: true, force: true });
mkdirSync(stateDir, { recursive: true, mode: 0o700 });

const witnessDb = join(stateDir, 'witness.db');
const firstRun = !existsSync(witnessDb);
const anchor = new protocolLib.OpenTimestampsAnchor(calendars.length > 0 ? { calendars } : {});
const key = ledgerLib.loadOrCreateDoorKey(join(stateDir, 'witness-key.pem'));
const witness = await witnessLib.buildWitnessServer({ dbPath: witnessDb, key, anchor });
const url = await witness.app.listen({ host: '127.0.0.1', port: 0 });

async function latestEpoch() {
  const response = await fetch(`${url}/v1/epochs/latest`);
  return response.ok ? response.json() : null;
}

async function receipt(epoch) {
  const proof = await protocolLib.parseOtsProof(specLib.base64UrlToBytes(epoch.ots_base64));
  return {
    pending: protocolLib.collectPending(proof.timestamp).map((p) => p.uri),
    bitcoin: protocolLib.collectBitcoin(proof.timestamp).map((b) => b.height),
  };
}

async function stamp() {
  const ledger = ledgerLib.Ledger.open(join(stateDir, 'ledger.db'), { doorId: 'gateway:ots-live-smoke' });
  for (let i = 0; i < 3; i += 1) {
    ledger.append({
      actor: 'did:mandare:ots-live-smoke',
      mandate_id: 'mnd_ots_live_smoke',
      action: { type: 'llm.call.intent', target: 'ots-live-smoke', request_hash: specLib.sha256Hex(`${Date.now()}-${i}`) },
      cost: { amount: 0, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
    });
  }
  await new protocolLib.WitnessClient({
    url,
    signer: ledger.signer(),
    readEntryHashes: () => Promise.resolve(ledger.entryHashes()),
    witnessPublicKeyHex: key.publicKeyHex,
  }).sync();
  ledger.close();

  const run = await witness.runAnchor();
  if (run.status !== 'pending') {
    console.error(`FAIL: anchoring returned '${run.status}' — no calendar accepted the digest (network?). Re-run with --reset.`);
    return 1;
  }
  const epoch = await latestEpoch();
  const { pending } = await receipt(epoch);
  console.log(`STAMPED: epoch ${epoch.epoch} root ${epoch.aggregate.root}`);
  console.log(`  pending at ${pending.length} calendar(s): ${pending.join(', ')}`);
  console.log(`  state: ${stateDir}`);
  console.log('  re-run `pnpm ots-live-smoke` in 3–6 hours to collect the Bitcoin attestation.');
  return 0;
}

async function upgrade() {
  const before = await latestEpoch();
  if (before === null || before.anchor_status === 'none') {
    console.error('FAIL: this state has no pending anchor (the stamp run never reached a calendar). Re-run with --reset.');
    return 1;
  }
  const result = await witness.runUpgrade();
  const epoch = await latestEpoch();
  const { pending, bitcoin } = await receipt(epoch);
  const ageHours = ((Date.now() - Date.parse(epoch.created_at)) / 3_600_000).toFixed(1);
  if ((epoch.anchor_status !== 'confirmed' || bitcoin.length === 0) && result.failures.length > 0) {
    // A calendar answered but the upgrade failed — that is a bug or an outage,
    // never "still pending" (the pre-fix script hid a parser bug this way).
    for (const failure of result.failures) console.error(`UPGRADE FAILED (epoch ${failure.epoch}): ${failure.error}`);
    return 1;
  }
  if (epoch.anchor_status !== 'confirmed' || bitcoin.length === 0) {
    console.log(`STILL PENDING after ${ageHours} h (checked ${result.checked} epoch(s); ${pending.length} calendar(s) waiting).`);
    console.log('  Normal for the first hours — re-run later.');
    return 3;
  }
  const otsPath = join(stateDir, `epoch-${epoch.epoch}.ots`);
  writeFileSync(otsPath, specLib.base64UrlToBytes(epoch.ots_base64));
  console.log(`PASS: epoch ${epoch.epoch} carries a Bitcoin attestation (block ${Math.min(...bitcoin)}) after ${ageHours} h.`);
  console.log(`  receipt: ${otsPath}`);
  console.log(`  confirm against Bitcoin with a stock client: ots verify -d ${epoch.aggregate.root} ${otsPath}`);
  return 0;
}

let exitCode = 1;
try {
  exitCode = firstRun ? await stamp() : await upgrade();
} catch (error) {
  console.error(`FAIL: ${error instanceof Error ? error.message : String(error)}`);
} finally {
  await witness.close();
}
process.exit(exitCode);
