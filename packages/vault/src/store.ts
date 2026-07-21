import { DatabaseSync } from 'node:sqlite';

import type { KeyProvenance } from '@mandarelabs/spec';

/**
 * The vault's persistent store: encrypted secrets, the short-lived token
 * registry, and the anti-replay nonce set. Every secret column holds
 * ciphertext (see crypto.ts) — the DB file is inert without the master key.
 *
 * Unlike the ledger this is a mutable operational store, not an append-only
 * chain: tokens expire and are pruned, kills flip a revoked flag.
 */

export interface SecretRow {
  ciphertext: string;
  provenance: KeyProvenance;
}

export interface TokenRow {
  tokenId: string;
  actor: string;
  mandateId: string;
  /** Encrypted proof-of-possession secret. */
  popCiphertext: string;
  issuedAt: string;
  expiresAt: string;
  revoked: boolean;
}

const CREATE_SCHEMA = `
CREATE TABLE IF NOT EXISTS vault_secrets (
  account    TEXT PRIMARY KEY,
  ciphertext TEXT NOT NULL,
  provenance TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS vault_tokens (
  token_id       TEXT PRIMARY KEY,
  actor          TEXT NOT NULL,
  mandate_id     TEXT NOT NULL,
  pop_ciphertext TEXT NOT NULL,
  issued_at      TEXT NOT NULL,
  expires_at     TEXT NOT NULL,
  revoked        INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX IF NOT EXISTS vault_tokens_actor ON vault_tokens (actor);
CREATE TABLE IF NOT EXISTS vault_nonces (
  nonce      TEXT PRIMARY KEY,
  expires_at TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS vault_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
) STRICT;
`;

export class VaultStore {
  private readonly db: DatabaseSync;

  private constructor(db: DatabaseSync) {
    this.db = db;
  }

  static open(dbPath: string): VaultStore {
    const db = new DatabaseSync(dbPath);
    db.exec('PRAGMA journal_mode = WAL;');
    db.exec('PRAGMA synchronous = FULL;');
    db.exec('PRAGMA busy_timeout = 5000;');
    db.exec(CREATE_SCHEMA);
    return new VaultStore(db);
  }

  close(): void {
    this.db.close();
  }

  // --- secrets --------------------------------------------------------------

  getSecret(account: string): SecretRow | null {
    const row = this.db
      .prepare('SELECT ciphertext, provenance FROM vault_secrets WHERE account = ?')
      .get(account) as { ciphertext: string; provenance: string } | undefined;
    return row === undefined
      ? null
      : { ciphertext: row.ciphertext, provenance: row.provenance as KeyProvenance };
  }

  putSecret(account: string, ciphertext: string, provenance: KeyProvenance, createdAt: string): void {
    this.db
      .prepare(
        `INSERT INTO vault_secrets (account, ciphertext, provenance, created_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(account) DO UPDATE SET
           ciphertext = excluded.ciphertext,
           provenance = excluded.provenance,
           created_at = excluded.created_at`
      )
      .run(account, ciphertext, provenance, createdAt);
  }

  deleteSecret(account: string): boolean {
    const info = this.db.prepare('DELETE FROM vault_secrets WHERE account = ?').run(account);
    return info.changes > 0;
  }

  listAccounts(): string[] {
    const rows = this.db
      .prepare('SELECT account FROM vault_secrets ORDER BY account ASC')
      .all() as { account: string }[];
    return rows.map((row) => row.account);
  }

  // --- tokens ---------------------------------------------------------------

  putToken(row: TokenRow): void {
    this.db
      .prepare(
        `INSERT INTO vault_tokens
           (token_id, actor, mandate_id, pop_ciphertext, issued_at, expires_at, revoked)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        row.tokenId,
        row.actor,
        row.mandateId,
        row.popCiphertext,
        row.issuedAt,
        row.expiresAt,
        row.revoked ? 1 : 0
      );
  }

  getToken(tokenId: string): TokenRow | null {
    const row = this.db
      .prepare(
        'SELECT token_id, actor, mandate_id, pop_ciphertext, issued_at, expires_at, revoked FROM vault_tokens WHERE token_id = ?'
      )
      .get(tokenId) as
      | {
          token_id: string;
          actor: string;
          mandate_id: string;
          pop_ciphertext: string;
          issued_at: string;
          expires_at: string;
          revoked: number;
        }
      | undefined;
    if (row === undefined) {
      return null;
    }
    return {
      tokenId: row.token_id,
      actor: row.actor,
      mandateId: row.mandate_id,
      popCiphertext: row.pop_ciphertext,
      issuedAt: row.issued_at,
      expiresAt: row.expires_at,
      revoked: row.revoked !== 0,
    };
  }

  /** Mark every token for an actor revoked. Returns how many were still live. */
  revokeActorTokens(actor: string): number {
    const info = this.db
      .prepare('UPDATE vault_tokens SET revoked = 1 WHERE actor = ? AND revoked = 0')
      .run(actor);
    return Number(info.changes);
  }

  /** Mark every token revoked (kill --all halts the vault). Returns live count. */
  revokeAllTokens(): number {
    const info = this.db.prepare('UPDATE vault_tokens SET revoked = 1 WHERE revoked = 0').run();
    return Number(info.changes);
  }

  deleteExpiredTokens(nowIso: string): number {
    const info = this.db.prepare('DELETE FROM vault_tokens WHERE expires_at < ?').run(nowIso);
    return Number(info.changes);
  }

  // --- nonces (single-use, anti-replay) -------------------------------------

  /**
   * Atomically claim a nonce: returns true if it was unseen (now recorded),
   * false if it was already used. INSERT with a PK conflict is the single-use
   * guarantee — two concurrent replays cannot both win.
   */
  claimNonce(nonce: string, expiresAt: string): boolean {
    const info = this.db
      .prepare('INSERT OR IGNORE INTO vault_nonces (nonce, expires_at) VALUES (?, ?)')
      .run(nonce, expiresAt);
    return Number(info.changes) > 0;
  }

  pruneNonces(nowIso: string): number {
    const info = this.db.prepare('DELETE FROM vault_nonces WHERE expires_at < ?').run(nowIso);
    return Number(info.changes);
  }

  // --- meta -----------------------------------------------------------------

  getMeta(key: string): string | null {
    const row = this.db.prepare('SELECT value FROM vault_meta WHERE key = ?').get(key) as
      | { value: string }
      | undefined;
    return row?.value ?? null;
  }

  setMeta(key: string, value: string): void {
    this.db
      .prepare(
        'INSERT INTO vault_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
      )
      .run(key, value);
  }
}
