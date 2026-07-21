#!/usr/bin/env node
/**
 * LIVE OpenRouter provisioning smoke — LOCAL ONLY, never CI (CI stays
 * mock/no-secrets). Exercises the full per-agent key lifecycle through
 * `OpenRouterProvisioningClient` against the real Management API, and
 * CLEANS UP every key it creates (no lingering capped keys):
 *
 *   create (tiny cap) → getKey (confirm) → disable → rotate (create new,
 *   delete old) → delete → getKey (gone).
 *
 * NAMING: OpenRouter renamed "provisioning keys" → "Management keys"
 * (2026-07-22); the REST surface is unchanged (verified here). The
 * Management key is read from `.env` as OPENROUTER_PROVISIONING_KEY.
 *
 * CONSISTENCY: OpenRouter's LIST endpoint is eventually consistent (a
 * just-created/updated key can be missing or stale there). This smoke
 * verifies every state from the authoritative single-key path (mutation
 * response / getKey), never by re-listing.
 *
 * R2: runtime keys returned by create/rotate are secret material — this
 * script never prints them, and asserts none leaked into its own output.
 */
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const envPath = join(root, '.env');
if (!existsSync(envPath)) {
  console.error('provisioning-smoke: no .env at the repo root. See .env.example.');
  process.exit(2);
}
const env = {};
for (const line of readFileSync(envPath, 'utf8').split('\n')) {
  const match = /^([A-Z0-9_]+)=(.*)$/.exec(line.trim());
  if (match && match[2] !== '') env[match[1]] = match[2];
}
const managementKey = env.OPENROUTER_PROVISIONING_KEY;
if (!managementKey) {
  console.error('provisioning-smoke: OPENROUTER_PROVISIONING_KEY empty in .env.');
  process.exit(2);
}

const { OpenRouterProvisioningClient } = await import(
  join(root, 'packages/gateway/dist/provisioning.js')
);

const transcript = [];
function log(line) {
  console.log(line);
  transcript.push(line);
}
class SmokeError extends Error {}
function check(condition, message) {
  if (!condition) throw new SmokeError(message);
}

const client = new OpenRouterProvisioningClient({ provisioningKey: managementKey });
const NAME = 'mandare-prov-smoke-DELETE-ME';
const runtimeKeys = [];
const liveHashes = new Set(); // hashes we created and haven't deleted yet

async function cleanup() {
  for (const hash of liveHashes) {
    try {
      await client.deleteKey(hash);
    } catch {
      console.error(`  (cleanup) could not delete ${hash.slice(0, 12)}… — check the dashboard`);
    }
  }
}

let exitCode = 0;
try {
  // 1. Create a per-agent key with a tiny USD cap.
  const created = await client.createAgentKey({ name: NAME, limitUsd: 0.01, limitReset: 'monthly' });
  liveHashes.add(created.hash);
  runtimeKeys.push(created.key);
  check(/^sk-or-v1-/.test(created.key), 'create did not return a runtime key');
  check(Boolean(created.hash), 'create did not return a hash');
  check(created.limitUsd === 0.01, `create limit ${created.limitUsd}, expected 0.01`);
  check(created.disabled === false, 'newly created key should be enabled');
  log(`[prov] created key hash=${created.hash.slice(0, 12)}… name=${created.name} cap=$${created.limitUsd}`);

  // 2. Confirm via the authoritative single-key read (list is eventually consistent).
  const fetched = await client.getKey(created.hash);
  check(fetched !== null, 'getKey did not find the just-created key');
  check(!('key' in fetched), 'getKey must NOT expose runtime key material (R2)');
  check(fetched.disabled === false, 'getKey shows the key disabled unexpectedly');
  log('[prov] getKey confirms the key exists and is enabled (no runtime material exposed)');

  // 3. Disable it — the kill-at-OpenRouter belt-and-suspenders (S3). Verify
  //    from the PATCH response, which is authoritative and immediate.
  const disabled = await client.disableKey(created.hash);
  check(disabled.disabled === true, 'disable did not take effect (per the PATCH response)');
  log('[prov] disabled the key — PATCH response confirms disabled=true (kill-at-OpenRouter works)');

  // 4. Rotate: create replacement FIRST, then delete the old (never keyless).
  const rotated = await client.rotateAgentKey(created.hash, { name: NAME, limitUsd: 0.01 });
  liveHashes.delete(created.hash); // rotate deleted the old one
  liveHashes.add(rotated.hash);
  runtimeKeys.push(rotated.key);
  check(/^sk-or-v1-/.test(rotated.key), 'rotate did not return a fresh runtime key');
  check(rotated.hash !== created.hash, 'rotate returned the same hash');
  check((await client.getKey(created.hash)) === null, 'rotate did not delete the old key');
  log(`[prov] rotated → new hash=${rotated.hash.slice(0, 12)}…; old key confirmed gone`);

  // 5. Delete the replacement — clean slate.
  await client.deleteKey(rotated.hash);
  liveHashes.delete(rotated.hash);
  check((await client.getKey(rotated.hash)) === null, 'delete did not remove the key');
  log('[prov] deleted the rotated key; account clean');

  // R2: no runtime key string anywhere in our output.
  const blob = transcript.join('\n');
  check(
    ![...runtimeKeys, managementKey].some((secret) => blob.includes(secret)),
    'a key appeared in smoke output (R2 violation)'
  );

  log('\nPROVISIONING SMOKE PASS: create → getKey → disable → rotate → delete, all live, account left clean.');
} catch (error) {
  exitCode = 1;
  console.error(
    error instanceof SmokeError ? `PROVISIONING SMOKE FAIL: ${error.message}` : (error.stack ?? String(error))
  );
} finally {
  await cleanup();
}
process.exit(exitCode);
