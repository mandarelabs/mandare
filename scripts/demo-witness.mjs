#!/usr/bin/env node
/**
 * DEMO 5 + ACCEPTANCE TEST (S6, rule R7): the rewrite that can't hide.
 *
 * The truncation boundary has been documented since S0: a local attacker
 * who drops the newest entries (or rewrites history and re-signs with the
 * REAL door key) produces a chain that self-anchored verification calls
 * VALID. S6 closes it:
 *
 *   1. a door streams salted, content-free chain-head fingerprints to an
 *      external witness (32-byte tree roots — zero ledger content leaves
 *      the machine);
 *   2. the attacker doctors the ledger — truncation AND a re-signed
 *      rewrite — and self-anchored verification still passes;
 *   3. `mandare verify --witness` convicts both copies via RFC 6962
 *      consistency proofs against the witnessed head history;
 *   4. the witness aggregates all sources into one Merkle root and anchors
 *      it (mock adapter here; OpenTimestamps live);
 *   5. `mandare certify` emits the integrity certificate (SPEC §9.4) over
 *      TWO owner-selected entries, and a third party verifies it with NO
 *      ledger access — selective disclosure, proofs not data;
 *   6. a tampered certificate fails third-party verification.
 *
 * CI-safe: in-process ledger, real witness server (real HTTP), mock
 * anchor, no secrets. ASSERTS everything.
 *
 * Run: pnpm demo:witness
 * Capture: MANDARE_DEMO_CAPTURE=docs/demos/S6-witness-demo.txt pnpm demo:witness
 */
import { execFileSync, spawn } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(root, 'apps/cli/dist/main.js');

const ledgerLib = await import(join(root, 'packages/ledger/dist/index.js'));
const protocolLib = await import(join(root, 'packages/witness-protocol/dist/index.js'));
const specLib = await import(join(root, 'packages/spec/dist/index.js'));

const workDir = mkdtempSync(join(tmpdir(), 'mandare-witness-demo-'));
const honestDb = join(workDir, 'ledger.db');
const truncatedDb = join(workDir, 'ledger-truncated.db');
const rewrittenDb = join(workDir, 'ledger-rewritten.db');
const witnessDb = join(workDir, 'witness.db');
const certPath = join(workDir, 'certificate.json');

const captured = [];
function log(line = '') {
  console.log(line);
  captured.push(line);
}
let witnessProc = null;
function fail(message) {
  console.error(`DEMO FAIL: ${message}`);
  witnessProc?.kill('SIGKILL');
  process.exit(1);
}
process.on('uncaughtException', (error) => fail(error.stack ?? String(error)));
process.on('unhandledRejection', (error) => fail(error?.stack ?? String(error)));
setTimeout(() => fail('timed out after 120s'), 120_000).unref();

function runCli(args) {
  try {
    return { code: 0, stdout: execFileSync('node', [cli, ...args], { encoding: 'utf8' }) };
  } catch (error) {
    return { code: error.status ?? 1, stdout: `${error.stdout ?? ''}`, stderr: `${error.stderr ?? ''}` };
  }
}

log('════════════════════════════════════════════════════════════════════');
log(' MANDARE DEMO 5 — the rewrite that can\'t hide');
log('════════════════════════════════════════════════════════════════════');
log();

// 1. A door writes a real ledger and STREAMS its heads to the witness. -------
// The witness is the REAL `mandare witness serve` CLI in its own process —
// exactly how an operator runs it (mock anchor: CI has no network).
const witnessPort = 39400 + (process.pid % 200);
witnessProc = spawn(
  'node',
  [cli, 'witness', 'serve', '--db', witnessDb, '--port', String(witnessPort), '--anchor', 'mock'],
  { stdio: ['ignore', 'pipe', 'inherit'] }
);
const witnessUrl = `http://127.0.0.1:${witnessPort}`;
const witnessKeyHex = await new Promise((resolve, reject) => {
  let buffer = '';
  witnessProc.stdout.on('data', (chunk) => {
    buffer += String(chunk);
    const match = buffer.match(/public_key=([0-9a-f]{64})/);
    if (match && buffer.includes('listening')) resolve(match[1]);
  });
  witnessProc.on('exit', (code) => reject(new Error(`witness exited early (${code})`)));
  setTimeout(() => reject(new Error('witness did not start in time')), 15_000).unref();
});
log(`[witness] reference witness up at ${witnessUrl} (mandare witness serve)`);
log(`[witness] public key (distributed OUT-OF-BAND): ${witnessKeyHex}`);
log();

const ledger = ledgerLib.Ledger.open(honestDb, { doorId: 'gateway:demo' });
const client = new protocolLib.WitnessClient({
  url: witnessUrl,
  signer: ledger.signer(),
  readEntryHashes: () => Promise.resolve(ledger.entryHashes()),
  witnessPublicKeyHex: witnessKeyHex,
});
for (let i = 1; i <= 8; i += 1) {
  ledger.append({
    actor: 'did:mandare:demo-agent',
    mandate_id: 'mnd_demo',
    action: {
      type: 'llm.call.intent',
      target: 'api.example.com',
      request_hash: specLib.sha256Hex(`demo-call-${i}`),
    },
    cost: { amount: i * 250_000, currency: 'EUR', tokens_in: 100, tokens_out: 40 },
  });
  const { head } = await client.sync(); // per-entry streaming (lock 4)
  if (head.size !== i) fail(`witnessed head size ${head.size}, expected ${i}`);
}
log('[door]   8 entries appended; every head streamed + acked (lock 4)');

const history = await (await fetch(`${witnessUrl}/v1/sources/${ledger.doorKeyId}/history`)).json();
const historySizes = history.records.map((r) => r.head.size).join(',');
log(`[witness] recorded history sizes: ${historySizes}`);
log(`[witness] knows ONLY sizes + 32-byte salted roots — zero ledger content, e.g.`);
log(`[witness]   size=8 root=${history.records.at(-1).head.root}`);
if (historySizes !== '1,2,3,4,5,6,7,8') fail('witness history incomplete');
log();

// 2. The attacker doctors two copies — with the REAL door key. ---------------
log('[attacker] stealing the ledger file AND the door key (worst local case)…');
ledger.close();
copyFileSync(honestDb, truncatedDb);
copyFileSync(honestDb, rewrittenDb);

const doorKey = ledgerLib.loadOrCreateDoorKey(`${honestDb}.doorkey.pem`);
function resignChain(dbPath, mutate) {
  const db = new DatabaseSync(dbPath);
  db.exec('DROP TRIGGER ledger_entries_no_update;');
  db.exec('DROP TRIGGER ledger_entries_no_delete;');
  const rows = db.prepare('SELECT entry_json FROM ledger_entries ORDER BY seq').all();
  const entries = mutate(rows.map((row) => JSON.parse(row.entry_json)));
  db.exec('DELETE FROM ledger_entries;');
  const insert = db.prepare(
    'INSERT INTO ledger_entries (seq, entry_hash, prev_hash, entry_json) VALUES (?, ?, ?, ?)'
  );
  let prevHash = '0'.repeat(64);
  entries.forEach((entry, index) => {
    const { entry_hash, door_signature, ...rest } = entry;
    const preimage = { ...rest, seq: index + 1, prev_hash: prevHash };
    const entryHash = specLib.computeEntryHash(preimage);
    const resigned = {
      ...preimage,
      entry_hash: entryHash,
      door_signature: {
        alg: 'EdDSA',
        key_id: doorKey.keyId,
        key_provenance: doorKey.provenance,
        value: Buffer.from(doorKey.sign(specLib.hexToBytes(entryHash))).toString('base64url'),
      },
    };
    insert.run(resigned.seq, resigned.entry_hash, resigned.prev_hash, JSON.stringify(resigned));
    prevHash = entryHash;
  });
  db.close();
}
resignChain(truncatedDb, (entries) => entries.slice(0, 6)); // drop the newest 2
resignChain(rewrittenDb, (entries) => {
  entries[3] = { ...entries[3], cost: { ...entries[3].cost, amount: 1 } }; // "we never spent that"
  return entries;
});
log('[attacker] copy A: newest 2 entries DROPPED, chain re-signed');
log('[attacker] copy B: entry 4 cost rewritten €1.00 → €0.000001, chain re-signed');
log();

// 3. Self-anchored verification blesses both lies. ---------------------------
for (const [label, db] of [['truncated', truncatedDb], ['rewritten', rewrittenDb]]) {
  const result = runCli(['verify', '--db', db]);
  if (result.code !== 0) fail(`self-anchored verify of the ${label} copy should pass, got ${result.code}`);
  if (!result.stdout.includes('chain:    VALID')) fail(`${label}: expected VALID`);
  log(`[verify]  ${label} copy, self-anchored:      chain VALID — the lie is locally perfect`);
}
log();

// 4. `mandare verify --witness` convicts both. -------------------------------
const truncatedVerdict = runCli([
  'verify', '--db', truncatedDb, '--witness', witnessUrl, '--witness-key', witnessKeyHex,
]);
if (truncatedVerdict.code !== 1) fail('truncated copy must FAIL witness verification');
if (!truncatedVerdict.stdout.includes('TRUNCATION DETECTED')) fail('missing TRUNCATION DETECTED');
log('[verify]  truncated copy, --witness:      TRUNCATION DETECTED (exit 1)');
log(`          ${truncatedVerdict.stdout.split('\n').find((l) => l.includes('TRUNCATION'))?.trim()}`);

const rewrittenVerdict = runCli([
  'verify', '--db', rewrittenDb, '--witness', witnessUrl, '--witness-key', witnessKeyHex,
]);
if (rewrittenVerdict.code !== 1) fail('rewritten copy must FAIL witness verification');
if (!rewrittenVerdict.stdout.includes('FORK DETECTED')) fail('missing FORK DETECTED');
log('[verify]  rewritten copy, --witness:      FORK DETECTED (exit 1)');

const honestVerdict = runCli([
  'verify', '--db', honestDb, '--witness', witnessUrl, '--witness-key', witnessKeyHex,
]);
if (honestVerdict.code !== 0) fail(`honest copy must verify, got ${honestVerdict.code}`);
if (!honestVerdict.stdout.includes('witness:  CONSISTENT')) fail('honest copy not CONSISTENT');
log('[verify]  honest copy, --witness:         CONSISTENT (exit 0) — no false positives');
log();

// 5. Public anchoring: one aggregate root for every source. ------------------
const anchorRun = await (await fetch(`${witnessUrl}/v1/anchor/run`, { method: 'POST' })).json();
if (anchorRun.epoch !== 1) fail('expected epoch 1');
const epoch = await (await fetch(`${witnessUrl}/v1/epochs/latest`)).json();
log(`[anchor]  epoch 1 aggregate root ${epoch.aggregate.root.slice(0, 16)}… anchored (${epoch.anchor_status}, ${epoch.anchor_kind} adapter)`);
log('[anchor]  live deployments anchor via OpenTimestamps — same interface; receipts stay pending until the Bitcoin attestation lands (hours)');
log();

// 6. The integrity certificate (SPEC §9.4): selective disclosure. ------------
const certify = runCli([
  'certify', '--db', honestDb, '--witness', witnessUrl, '--witness-key', witnessKeyHex,
  '--disclose', '3,5', '--out', certPath,
]);
if (certify.code !== 0) fail(`certify exited ${certify.code}: ${certify.stderr}`);
log('[certify] integrity certificate written — chain valid · sequence complete ·');
log('          heads match witnessed history · root anchored — disclosing entries 3 and 5 ONLY:');
for (const line of certify.stdout.trim().split('\n')) log(`          ${line}`);
const cert = JSON.parse(readFileSync(certPath, 'utf8'));
if (cert.disclosed.length !== 2) fail('certificate must disclose exactly 2 entries');
if (JSON.stringify(cert).match(/"salt"/g).length !== 2) {
  fail('undisclosed entries leaked into the certificate');
}
log();

// 7. Third-party verification: no ledger, no Mandare service. ----------------
const thirdParty = runCli(['certify', 'verify', certPath, '--witness-key', witnessKeyHex]);
if (thirdParty.code !== 0) fail(`third-party verification failed: ${thirdParty.stdout}`);
if (!thirdParty.stdout.includes('certificate: VALID')) fail('expected certificate: VALID');
log('[3rd party] verifies the certificate with NO ledger access:');
for (const line of thirdParty.stdout.trim().split('\n')) log(`            ${line}`);
log();

// 8. A tampered certificate dies in the third party's hands. -----------------
const doctoredCert = JSON.parse(readFileSync(certPath, 'utf8'));
doctoredCert.disclosed[0].entry.cost.amount = 1; // "the audit sample was cheaper"
const doctoredPath = join(workDir, 'certificate-doctored.json');
writeFileSync(doctoredPath, JSON.stringify(doctoredCert));
const doctoredVerdict = runCli(['certify', 'verify', doctoredPath, '--witness-key', witnessKeyHex]);
if (doctoredVerdict.code !== 1) fail('doctored certificate must fail verification');
if (!doctoredVerdict.stdout.includes('certificate: INVALID')) fail('expected certificate: INVALID');
log('[3rd party] doctored certificate (disclosed amount edited): INVALID (exit 1)');
log();

log('════════════════════════════════════════════════════════════════════');
log(' DEMO PASS: the ledger streamed salted 32-byte head fingerprints to');
log(' an external witness. A truncated copy and a real-door-key rewrite');
log(' both passed self-anchored verification — and both were CONVICTED by');
log(' `mandare verify --witness` against the witnessed head history. The');
log(' aggregate root was publicly anchored, and `mandare certify` produced');
log(' a selective-disclosure integrity certificate a third party verified');
log(' without seeing anything but the two disclosed entries.');
log(' Proofs, not data.');
log('════════════════════════════════════════════════════════════════════');

witnessProc.kill('SIGTERM');
if (process.env.MANDARE_DEMO_CAPTURE) {
  const capturePath = join(root, process.env.MANDARE_DEMO_CAPTURE);
  mkdirSync(dirname(capturePath), { recursive: true });
  writeFileSync(capturePath, `${captured.join('\n')}\n`);
  console.log(`\n[demo] terminal capture written to ${process.env.MANDARE_DEMO_CAPTURE}`);
}
rmSync(workDir, { recursive: true, force: true });
