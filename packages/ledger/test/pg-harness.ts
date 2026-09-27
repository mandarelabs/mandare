import { createServer, type AddressInfo } from 'node:net';
import { join } from 'node:path';

import EmbeddedPostgres from 'embedded-postgres';

/**
 * Embedded Postgres for the Postgres-driver suites, on a port the kernel
 * hands out — never a derived one.
 *
 * CI flake (2026-09-27): the suites used `556xx + pid % 100`. That range sits
 * inside Linux's ephemeral port range (32768–60999), and turbo runs every
 * package's tests at once, so another suite's socket already held
 * 127.0.0.1:55732. Postgres logged "could not bind IPv4 address", came up on
 * ::1 only, and the suite died with ECONNREFUSED 127.0.0.1.
 *
 * Two changes close it:
 * 1. the port comes from `listen(0)` on 127.0.0.1 (free at that instant);
 * 2. Postgres listens on 127.0.0.1 ONLY (no ::1, no Unix socket), so if the
 *    port is taken in the gap before Postgres binds, the server cannot come
 *    up half-bound — it exits, `start()` rejects, and we retry on a new port.
 */

export interface EmbeddedPg {
  embedded: EmbeddedPostgres;
  port: number;
  adminUrl: string;
}

const START_ATTEMPTS = 5;
const ADMIN_USER = 'postgres';
const ADMIN_PASSWORD = 'postgres';

function freeLoopbackPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      server.close(() => resolve(port));
    });
  });
}

function cluster(databaseDir: string, port: number): EmbeddedPostgres {
  return new EmbeddedPostgres({
    databaseDir,
    user: ADMIN_USER,
    password: ADMIN_PASSWORD,
    port,
    persistent: false,
    postgresFlags: ['-c', 'listen_addresses=127.0.0.1', '-c', 'unix_socket_directories='],
  });
}

export async function startEmbeddedPostgres(workDir: string): Promise<EmbeddedPg> {
  const databaseDir = join(workDir, 'pgdata');
  // initdb does not bind anything; the port only matters at start().
  await cluster(databaseDir, 0).initialise();

  let lastError: unknown;
  for (let attempt = 1; attempt <= START_ATTEMPTS; attempt += 1) {
    const port = await freeLoopbackPort();
    const embedded = cluster(databaseDir, port);
    try {
      await embedded.start();
      const adminUrl = `postgresql://${ADMIN_USER}:${ADMIN_PASSWORD}@127.0.0.1:${port}/postgres`;
      return { embedded, port, adminUrl };
    } catch (error) {
      // The postmaster exited (lost the bind race); try a fresh port.
      lastError = error ?? new Error(`postgres exited during start on port ${port}`);
    }
  }
  throw new Error(`embedded postgres did not start after ${START_ATTEMPTS} attempts`, {
    cause: lastError,
  });
}
