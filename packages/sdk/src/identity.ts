import type { webcrypto } from 'node:crypto';

import type { PassportIdentity } from './fetch.js';
import type { TokenCredentials } from './pop.js';

/**
 * Loaders for the artifacts the CLI writes. Node-only conveniences — the
 * rest of the SDK stays WebCrypto/fetch-portable, so the fs import happens
 * lazily inside these helpers.
 */

interface AgentKeyFile {
  privateJwk: webcrypto.JsonWebKey;
  publicJwk: webcrypto.JsonWebKey;
}

function isJwk(value: unknown): value is webcrypto.JsonWebKey {
  return typeof value === 'object' && value !== null && typeof (value as { kty?: unknown }).kty === 'string';
}

/**
 * Load a passport identity from the files `mandare passport issue` writes:
 * the compact SD-JWT credential and the agent key pair (`--agent-key-out`).
 */
export async function loadPassportIdentity(
  credentialPath: string,
  agentKeyPath: string
): Promise<PassportIdentity> {
  const { readFile } = await import('node:fs/promises');
  const { didKeyFromPublicKey, publicKeyFromDidKey } = await import('@mandarelabs/passport');

  const credential = (await readFile(credentialPath, 'utf8')).trim();
  if (credential.length === 0 || credential.startsWith('{')) {
    throw new Error(`${credentialPath} is not a compact SD-JWT delegation credential`);
  }

  const rawKeys: unknown = JSON.parse(await readFile(agentKeyPath, 'utf8'));
  if (
    typeof rawKeys !== 'object' ||
    rawKeys === null ||
    !isJwk((rawKeys as { privateJwk?: unknown }).privateJwk) ||
    !isJwk((rawKeys as { publicJwk?: unknown }).publicJwk)
  ) {
    throw new Error(`${agentKeyPath} is not an agent key file ({ privateJwk, publicJwk })`);
  }
  const keys = rawKeys as AgentKeyFile;

  const publicX = keys.publicJwk.x;
  if (typeof publicX !== 'string') {
    throw new Error(`${agentKeyPath}: publicJwk carries no raw key material (x)`);
  }
  const rawPublic = Uint8Array.from(Buffer.from(publicX, 'base64url'));
  const agentDid = didKeyFromPublicKey(rawPublic);
  // Round-trip so a corrupted key file fails HERE, not at the door.
  publicKeyFromDidKey(agentDid);

  return { credential, agentDid, privateJwk: keys.privateJwk, publicJwk: keys.publicJwk };
}

/**
 * Parse the JSON `mandare token issue --json` prints into token credentials.
 */
export function tokenCredentialsFromIssueJson(json: string): TokenCredentials {
  const raw: unknown = JSON.parse(json);
  const tokenId = (raw as { token_id?: unknown }).token_id;
  const popSecret = (raw as { pop_secret?: unknown }).pop_secret;
  if (typeof tokenId !== 'string' || typeof popSecret !== 'string') {
    throw new Error('not a `mandare token issue --json` payload (token_id, pop_secret)');
  }
  return { tokenId, popSecret };
}
