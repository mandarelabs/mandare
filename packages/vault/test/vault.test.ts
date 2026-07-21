import { chmodSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, test } from 'vitest';

import { seal, open, hmacSha256, constantTimeEqual, generateMasterKey } from '../src/crypto.js';
import {
  buildStatusListPayload,
  parseRevocationRef,
  formatRevocationRef,
} from '../src/status-list.js';
import { popPreimage, MAX_TOKEN_TTL_SECONDS } from '../src/tokens.js';
import { Vault } from '../src/vault.js';
import type { VaultConfig } from '../src/config.js';
import { tempDir, memoryKeychain, fakeClock } from './helpers.js';

function fileConfig(dir: string): VaultConfig {
  return {
    backend: 'file',
    dbPath: join(dir, 'vault.db'),
    service: 'mandare-vault-test',
    account: 'master-key',
    masterKeyFile: join(dir, 'vault.masterkey'),
  };
}

describe('crypto envelope', () => {
  test('seal/open round-trips under the right key and aad', () => {
    const key = generateMasterKey();
    const blob = seal(key, 'provider:anthropic', 'sk-secret-123');
    expect(open(key, 'provider:anthropic', blob)).toBe('sk-secret-123');
  });

  test('a wrong aad fails authentication (ciphertext bound to its slot)', () => {
    const key = generateMasterKey();
    const blob = seal(key, 'provider:anthropic', 'sk-secret-123');
    expect(() => open(key, 'door:gateway', blob)).toThrow();
  });

  test('a wrong master key cannot open the blob', () => {
    const blob = seal(generateMasterKey(), 'a', 'secret');
    expect(() => open(generateMasterKey(), 'a', blob)).toThrow();
  });

  test('constantTimeEqual matches only identical strings', () => {
    expect(constantTimeEqual('abc', 'abc')).toBe(true);
    expect(constantTimeEqual('abc', 'abd')).toBe(false);
    expect(constantTimeEqual('abc', 'abcd')).toBe(false);
  });
});

describe('Vault secrets (file backend)', () => {
  let dir: ReturnType<typeof tempDir>;
  let vault: Vault;

  beforeEach(() => {
    dir = tempDir();
    vault = Vault.open(fileConfig(dir.path));
  });
  afterEach(() => {
    vault.close();
    dir.cleanup();
  });

  test('provider keys round-trip and record software provenance in file mode', () => {
    expect(vault.getProviderKey('anthropic')).toBeNull();
    vault.putProviderKey('anthropic', 'sk-ant-abc');
    expect(vault.getProviderKey('anthropic')).toBe('sk-ant-abc');
    expect(vault.provenance).toBe('software');
  });

  test('secrets are stored as ciphertext, never plaintext, on disk', () => {
    vault.putProviderKey('openai', 'sk-openai-PLAINTEXT-MARKER');
    vault.close();
    // Re-read the raw DB file bytes: the plaintext marker must not appear.
    const raw = readFileSync(join(dir.path, 'vault.db'));
    expect(raw.includes('PLAINTEXT-MARKER')).toBe(false);
    vault = Vault.open(fileConfig(dir.path));
    expect(vault.getProviderKey('openai')).toBe('sk-openai-PLAINTEXT-MARKER');
  });

  test('.env bootstrap import populates provider keys, then reads them back', () => {
    const imported = vault.importFromEnv({
      ANTHROPIC_API_KEY: 'sk-ant',
      OPENROUTER_API_KEY: 'sk-or',
      OPENROUTER_PROVISIONING_KEY: 'sk-prov',
      IRRELEVANT: 'ignored',
    });
    expect(imported).toContain('provider:anthropic');
    expect(imported).toContain('provider:openrouter');
    expect(imported).toContain('provisioning:openrouter');
    expect(vault.getProviderKey('anthropic')).toBe('sk-ant');
    expect(vault.getProvisioningKey()).toBe('sk-prov');
    expect(vault.getProviderKey('openai')).toBeNull();
  });

  test('door key PEM round-trips per door id', () => {
    expect(vault.getDoorKeyPem('gateway:local')).toBeNull();
    vault.putDoorKeyPem('gateway:local', '-----BEGIN PRIVATE KEY-----pem-----END PRIVATE KEY-----');
    expect(vault.getDoorKeyPem('gateway:local')).toContain('BEGIN PRIVATE KEY');
  });
});

describe('file-backend master key permissions', () => {
  let dir: ReturnType<typeof tempDir>;
  beforeEach(() => (dir = tempDir()));
  afterEach(() => dir.cleanup());

  test.skipIf(process.platform === 'win32')(
    'refuses to read a group/world-readable master key (fail-closed)',
    () => {
      const config = fileConfig(dir.path);
      // Plant a master key with loose permissions (a drifted/copied file).
      writeFileSync(config.masterKeyFile, Buffer.alloc(32).toString('base64'), { mode: 0o600 });
      chmodSync(config.masterKeyFile, 0o644);
      expect(() => Vault.open(config)).toThrow(/owner-only|600/);
    }
  );

  test.skipIf(process.platform === 'win32')('accepts a correctly 0600 master key', () => {
    const config = fileConfig(dir.path);
    const first = Vault.open(config); // creates the key at 0600
    first.close();
    const reopened = Vault.open(config);
    expect(reopened.provenance).toBe('software');
    reopened.close();
  });
});

describe('Vault keychain backend (injected)', () => {
  let dir: ReturnType<typeof tempDir>;
  afterEach(() => dir.cleanup());
  beforeEach(() => (dir = tempDir()));

  test('records keychain provenance and persists the master key across opens', () => {
    const keychain = memoryKeychain();
    const config: VaultConfig = { ...fileConfig(dir.path), backend: 'keychain' };
    const vault = Vault.open(config, { keychain });
    expect(vault.provenance).toBe('keychain');
    vault.putProviderKey('anthropic', 'sk-keychained');
    vault.close();
    // Same keychain (same master key) → the secret decrypts on reopen.
    const reopened = Vault.open(config, { keychain });
    expect(reopened.getProviderKey('anthropic')).toBe('sk-keychained');
    reopened.close();
  });
});

describe('scoped tokens (proof of possession)', () => {
  let dir: ReturnType<typeof tempDir>;
  let clock: ReturnType<typeof fakeClock>;
  let vault: Vault;

  beforeEach(() => {
    dir = tempDir();
    clock = fakeClock('2026-07-22T12:00:00.000Z');
    vault = Vault.open(fileConfig(dir.path), { clock: clock.clock });
  });
  afterEach(() => {
    vault.close();
    dir.cleanup();
  });

  function signedClaims(
    grant: { tokenId: string; popSecret: string },
    over: { method: string; path: string; nonce: string }
  ) {
    const timestamp = clock.clock().toISOString();
    const pop = hmacSha256(
      grant.popSecret,
      popPreimage({ tokenId: grant.tokenId, timestamp, ...over })
    );
    return { tokenId: grant.tokenId, timestamp, pop, ...over };
  }

  test('a correctly-signed request verifies and returns the bound actor/mandate', () => {
    const grant = vault.issueToken({ actor: 'did:mandare:agent-a', mandateId: 'mnd_1' });
    const result = vault.verifyRequest(
      signedClaims(grant, { method: 'POST', path: '/v1/messages', nonce: 'n1' })
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.verified.actor).toBe('did:mandare:agent-a');
      expect(result.verified.mandateId).toBe('mnd_1');
    }
  });

  test('the token id WITHOUT its pop secret is dead paper (BAD_POP)', () => {
    const grant = vault.issueToken({ actor: 'a', mandateId: 'm' });
    // Attacker exfiltrated the token id only; forges a proof with a guess.
    const timestamp = clock.clock().toISOString();
    const forged = {
      tokenId: grant.tokenId,
      method: 'POST',
      path: '/v1/messages',
      timestamp,
      nonce: 'stolen',
      pop: hmacSha256('attacker-guessed-secret', 'anything'),
    };
    const result = vault.verifyRequest(forged);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.refusal.code).toBe('BAD_POP');
  });

  test('a captured request cannot be replayed (single-use nonce)', () => {
    const grant = vault.issueToken({ actor: 'a', mandateId: 'm' });
    const claims = signedClaims(grant, { method: 'POST', path: '/v1/messages', nonce: 'once' });
    expect(vault.verifyRequest(claims).ok).toBe(true);
    const replay = vault.verifyRequest(claims);
    expect(replay.ok).toBe(false);
    if (!replay.ok) expect(replay.refusal.code).toBe('REPLAYED_NONCE');
  });

  test('a stale timestamp is refused before the nonce is even considered', () => {
    const grant = vault.issueToken({ actor: 'a', mandateId: 'm' });
    const claims = signedClaims(grant, { method: 'POST', path: '/v1/messages', nonce: 'n' });
    clock.advance(200); // beyond the ±120s window, still within TTL
    const result = vault.verifyRequest(claims);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.refusal.code).toBe('STALE_REQUEST');
  });

  test('an expired token is dead paper (TTL)', () => {
    const grant = vault.issueToken({ actor: 'a', mandateId: 'm', ttlSeconds: 300 });
    clock.advance(301);
    // Sign fresh at the new time so the timestamp is not the reason.
    const result = vault.verifyRequest(
      signedClaims(grant, { method: 'POST', path: '/v1/messages', nonce: 'n' })
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.refusal.code).toBe('TOKEN_EXPIRED');
  });

  test('revoking an actor kills its live tokens immediately (within TTL)', () => {
    const grant = vault.issueToken({ actor: 'doomed', mandateId: 'm' });
    expect(vault.revokeActorTokens('doomed')).toBe(1);
    const result = vault.verifyRequest(
      signedClaims(grant, { method: 'POST', path: '/v1/messages', nonce: 'n' })
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.refusal.code).toBe('TOKEN_REVOKED');
  });

  test('TTL above the 30-min ceiling is refused at mint time', () => {
    expect(() =>
      vault.issueToken({ actor: 'a', mandateId: 'm', ttlSeconds: MAX_TOKEN_TTL_SECONDS + 1 })
    ).toThrow(/30 min/);
  });

  test('an unknown token id is refused', () => {
    const result = vault.verifyRequest({
      tokenId: 'never-minted',
      method: 'POST',
      path: '/v1/messages',
      timestamp: clock.clock().toISOString(),
      nonce: 'n',
      pop: 'x',
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.refusal.code).toBe('UNKNOWN_TOKEN');
  });
});

describe('status list vocabulary', () => {
  test('revocation_ref round-trips', () => {
    expect(parseRevocationRef('statuslist:agents#7')).toEqual({ listId: 'agents', index: 7 });
    expect(formatRevocationRef('agents', 7)).toBe('statuslist:agents#7');
    expect(parseRevocationRef('not-a-ref')).toBeNull();
    expect(parseRevocationRef('statuslist:agents#-1')).toBeNull();
  });

  test('builds a standard IETF token status list payload with the right bits set', () => {
    const payload = buildStatusListPayload({
      listId: 'agents',
      slots: [
        { index: 0, revoked: false },
        { index: 1, revoked: true },
        { index: 2, revoked: false },
      ],
      issuer: 'mandare:door:gateway:local',
      iat: 1_700_000_000,
    });
    expect(payload.status_list.bits).toBe(1);
    expect(typeof payload.status_list.lst).toBe('string');
    expect(payload.iss).toBe('mandare:door:gateway:local');
  });
});
