import { createPrivateKey, createPublicKey, type KeyObject } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';

import { base64UrlToBytes, bytesToHex, sha256Hex } from '@mandarelabs/spec';

/**
 * `mandare directory` — build the Mandare key directory (JWKS profiled for
 * RFC 9421 / `/.well-known/http-message-signatures-directory`, see
 * packages/verifier/src/directory.ts for the format contract) from door key
 * PEM files.
 *
 * The door OPERATOR runs this and publishes the output somewhere verifiers
 * trust independently of the ledger file (their own site, Tessera-hosted
 * later). Only PUBLIC key material ever leaves this command.
 */

export interface DirectoryBuildOptions {
  /** PEM files: door private keys (public part is extracted) or public keys. */
  keyPaths: string[];
  /** Value for the `mnd:role` extension member on every key. */
  role?: string;
  /** Per-key validity end (JWK `exp`, epoch seconds). */
  exp?: number;
  /** Per-key validity start (JWK `nbf`, epoch seconds). */
  nbf?: number;
  /** Write the JWKS here instead of stdout. */
  outPath?: string;
}

export interface DirectoryBuildOutput {
  exitCode: 0 | 2;
  /** The JWKS document (pretty-printed JSON). */
  directoryJson: string;
  /** Informational lines for stderr: ledger key_id per key, output target. */
  infoLines: string[];
}

interface DirectoryJwk {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
  kid: string;
  use: 'sig';
  alg: 'EdDSA';
  nbf?: number;
  exp?: number;
  'mnd:role'?: string;
}

function publicKeyFromPem(pem: string, path: string): KeyObject {
  // Door key files hold the private key; accept plain public PEMs too.
  try {
    return createPublicKey(createPrivateKey(pem));
  } catch {
    try {
      return createPublicKey(pem);
    } catch {
      throw new Error(`${path}: not a readable PEM key`);
    }
  }
}

/** RFC 7638 JWK thumbprint for an OKP key: sha256 over the canonical required members. */
function jwkThumbprint(x: string): string {
  const canonical = `{"crv":"Ed25519","kty":"OKP","x":"${x}"}`;
  const hashHex = sha256Hex(canonical);
  const bytes = Buffer.from(hashHex, 'hex');
  return bytes.toString('base64url');
}

export async function buildDirectory(
  options: DirectoryBuildOptions
): Promise<DirectoryBuildOutput> {
  const infoLines: string[] = [];
  const keys: DirectoryJwk[] = [];

  for (const path of options.keyPaths) {
    const pem = await readFile(path, 'utf8');
    const publicKey = publicKeyFromPem(pem, path);
    if (publicKey.asymmetricKeyType !== 'ed25519') {
      throw new Error(`${path}: key is ${publicKey.asymmetricKeyType}, expected ed25519`);
    }
    const jwk = publicKey.export({ format: 'jwk' });
    if (typeof jwk.x !== 'string') {
      throw new Error(`${path}: could not extract raw Ed25519 public key`);
    }
    const rawPublicKey = base64UrlToBytes(jwk.x);
    const ledgerKeyId = sha256Hex(rawPublicKey);
    keys.push({
      kty: 'OKP',
      crv: 'Ed25519',
      x: jwk.x,
      kid: jwkThumbprint(jwk.x),
      use: 'sig',
      alg: 'EdDSA',
      ...(options.nbf === undefined ? {} : { nbf: options.nbf }),
      ...(options.exp === undefined ? {} : { exp: options.exp }),
      ...(options.role === undefined ? {} : { 'mnd:role': options.role }),
    });
    infoLines.push(
      `${path}: public key ${bytesToHex(rawPublicKey).slice(0, 16)}… ledger key_id ${ledgerKeyId.slice(0, 12)}…`
    );
  }

  const directoryJson = `${JSON.stringify({ keys }, null, 2)}\n`;
  if (options.outPath !== undefined) {
    await writeFile(options.outPath, directoryJson, 'utf8');
    infoLines.push(`directory written to ${options.outPath} (${keys.length} key${keys.length === 1 ? '' : 's'})`);
  }
  return { exitCode: 0, directoryJson, infoLines };
}
