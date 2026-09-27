#!/usr/bin/env node
/**
 * Publish-set install smoke (S10-fix R-1): the npm packages release.yml
 * publishes must install on a stranger's machine from THEMSELVES ALONE.
 *
 * 1. Reads PUBLISH_PACKAGES from .github/workflows/release.yml (the one
 *    source of truth for what gets published).
 * 2. Closure + order: every @mandarelabs runtime dependency of a published
 *    package is itself published, EARLIER in the list (publish order).
 * 3. `pnpm pack`s the set (pnpm rewrites workspace:* → real versions), then
 *    `npm install`s ONLY those tarballs into an empty directory — third-party
 *    dependencies come from the public registry, no workspace in reach.
 * 4. Runs the installed `mandare help`, and an MCP `initialize` +
 *    `tools/list` round-trip against the installed `mandare-mcp` over stdio.
 *
 * Needs `pnpm build` first and network access to registry.npmjs.org.
 * Run: pnpm pack-install-smoke
 */
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const MCP_TIMEOUT_MS = 30_000;
const REQUIRED_TOOLS = ['mandare_verify', 'mandare_kill', 'mandare_budget_status'];
// `npm publish --provenance` refuses a package whose repository.url does not
// match the repository the provenance was built in.
const REPOSITORY_URL = 'git+https://github.com/mandarelabs/mandare.git';
// MCP registry limits (server.schema.json 2025-12-11).
const MCP_DESCRIPTION_MAX = 100;

const workDir = mkdtempSync(join(tmpdir(), 'mandare-pack-install-'));
function fail(message) {
  console.error(`PACK-INSTALL SMOKE FAIL: ${message}`);
  console.error(`(work dir kept for inspection: ${workDir})`);
  process.exit(1);
}

export function readPublishSet(releaseYml) {
  const match = /^\s*PUBLISH_PACKAGES:\s*>-\s*\n((?:[ \t]+\S.*\n)+)/m.exec(releaseYml);
  if (match === null) {
    throw new Error('PUBLISH_PACKAGES block not found in release.yml');
  }
  return match[1].split(/\s+/).filter((dir) => dir.length > 0);
}

function readManifest(dir) {
  return JSON.parse(readFileSync(join(root, dir, 'package.json'), 'utf8'));
}

function checkClosure(dirs) {
  const published = [];
  const problems = [];
  for (const dir of dirs) {
    const manifest = readManifest(dir);
    if (manifest.private === true) {
      problems.push(`${dir} (${manifest.name}) is private: true — cannot be published`);
    }
    if (manifest.repository?.url !== REPOSITORY_URL || manifest.repository?.directory !== dir) {
      problems.push(`${manifest.name} needs repository {url: ${REPOSITORY_URL}, directory: ${dir}} (npm provenance check)`);
    }
    const internal = Object.keys(manifest.dependencies ?? {}).filter((dep) => dep.startsWith('@mandarelabs/'));
    for (const dep of internal) {
      if (!published.includes(dep)) {
        const listedLater = dirs.some((other) => readManifest(other).name === dep);
        problems.push(
          listedLater
            ? `${manifest.name} depends on ${dep}, which is published AFTER it (wrong order)`
            : `${manifest.name} depends on ${dep}, which is NOT in PUBLISH_PACKAGES (E404 on install)`
        );
      }
    }
    published.push(manifest.name);
  }
  return { published, problems };
}

/** What `mcp-publisher publish` checks: the npm package claims the server name. */
function checkMcpManifest() {
  const server = JSON.parse(readFileSync(join(root, 'packages/mcp-server/server.json'), 'utf8'));
  const manifest = readManifest('packages/mcp-server');
  const problems = [];
  if (manifest.mcpName !== server.name) {
    problems.push(`package.json mcpName ${manifest.mcpName} ≠ server.json name ${server.name}`);
  }
  if (server.version !== manifest.version || server.packages?.[0]?.version !== manifest.version) {
    problems.push(`server.json versions must equal the package version ${manifest.version}`);
  }
  if (server.packages?.[0]?.identifier !== manifest.name || server.packages?.[0]?.registryType !== 'npm') {
    problems.push('server.json packages[0] must be registryType npm, identifier = the package name');
  }
  if (typeof server.description !== 'string' || server.description.length > MCP_DESCRIPTION_MAX) {
    problems.push(`server.json description must be ≤ ${MCP_DESCRIPTION_MAX} characters`);
  }
  const snakeCase = JSON.stringify(server).match(/"[a-z]+_[a-z_]+":/g);
  if (snakeCase !== null) {
    problems.push(`server.json uses pre-2025-09 snake_case fields: ${snakeCase.join(' ')}`);
  }
  return problems;
}

function packAll(dirs, dest) {
  for (const dir of dirs) {
    if (!existsSync(join(root, dir, 'dist'))) {
      fail(`${dir}/dist is missing — run \`pnpm build\` first`);
    }
    execFileSync('pnpm', ['pack', '--pack-destination', dest], { cwd: join(root, dir), stdio: 'pipe' });
  }
  return readdirSync(dest)
    .filter((file) => file.endsWith('.tgz'))
    .map((file) => join(dest, file));
}

function mcpRoundTrip(installDir) {
  const home = join(installDir, 'mcp-home');
  mkdirSync(home);
  const child = spawn(join(installDir, 'node_modules/.bin/mandare-mcp'), [], {
    cwd: installDir,
    env: {
      PATH: process.env.PATH,
      HOME: home,
      MANDARE_MCP_HOME: home,
      MANDARE_LEDGER_DB: join(home, 'ledger.db'),
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const send = (message) => child.stdin.write(`${JSON.stringify(message)}\n`);
  let stderr = '';
  child.stderr.on('data', (chunk) => {
    stderr += chunk;
  });
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`no tools/list reply within ${MCP_TIMEOUT_MS} ms; stderr: ${stderr}`));
    }, MCP_TIMEOUT_MS);
    let buffer = '';
    child.stdout.on('data', (chunk) => {
      buffer += chunk;
      let newline;
      while ((newline = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        const message = JSON.parse(line);
        if (message.id === 1) {
          if (message.result?.serverInfo?.name !== 'mandare') {
            reject(new Error(`unexpected initialize reply: ${line}`));
            return;
          }
          send({ jsonrpc: '2.0', method: 'notifications/initialized' });
          send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
        } else if (message.id === 2) {
          clearTimeout(timer);
          child.kill('SIGTERM');
          resolve((message.result?.tools ?? []).map((tool) => tool.name));
        }
      }
    });
    child.on('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`mandare-mcp exited (code ${code}) before tools/list; stderr: ${stderr}`));
    });
    send({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'pack-install-smoke', version: '0.0.0' },
      },
    });
  });
}

async function main() {
  const dirs = readPublishSet(readFileSync(join(root, '.github/workflows/release.yml'), 'utf8'));
  console.log(`publish set (${dirs.length}): ${dirs.join(' ')}`);

  const { published, problems: closureProblems } = checkClosure(dirs);
  const problems = [...closureProblems, ...checkMcpManifest()];
  if (problems.length > 0) {
    fail(`the publish set is not installable:\n  - ${problems.join('\n  - ')}`);
  }
  console.log('closure + publish order + provenance/MCP-registry metadata OK');

  const packDir = join(workDir, 'tarballs');
  mkdirSync(packDir);
  const tarballs = packAll(dirs, packDir);
  for (const tarball of tarballs) {
    const manifest = execFileSync('tar', ['-xOzf', tarball, 'package/package.json'], { encoding: 'utf8' });
    if (manifest.includes('"workspace:')) {
      fail(`${tarball} still carries workspace:* ranges`);
    }
  }
  console.log(`packed ${tarballs.length} tarballs`);

  const installDir = join(workDir, 'stranger');
  mkdirSync(installDir);
  writeFileSync(join(installDir, 'package.json'), JSON.stringify({ name: 'stranger', private: true }));
  try {
    execFileSync('npm', ['install', '--no-audit', '--no-fund', '--registry=https://registry.npmjs.org/', ...tarballs], {
      cwd: installDir,
      stdio: 'pipe',
      encoding: 'utf8',
    });
  } catch (error) {
    fail(`npm install of the packed set failed:\n${error.stderr ?? error.message}`);
  }
  for (const name of published) {
    if (!existsSync(join(installDir, 'node_modules', name, 'package.json'))) {
      fail(`${name} missing from the installed tree`);
    }
  }
  console.log('npm install from the tarballs alone OK');

  const help = execFileSync(join(installDir, 'node_modules/.bin/mandare'), ['help'], {
    cwd: installDir,
    encoding: 'utf8',
  });
  if (!/mandare verify/.test(help)) {
    fail(`installed \`mandare help\` printed no usage:\n${help}`);
  }
  console.log('installed `mandare help` OK');

  const tools = await mcpRoundTrip(installDir).catch((error) => fail(`MCP round-trip: ${error.message}`));
  const missing = REQUIRED_TOOLS.filter((tool) => !tools.includes(tool));
  if (missing.length > 0) {
    fail(`installed MCP server lacks tools: ${missing.join(', ')} (got ${tools.join(', ')})`);
  }
  console.log(`installed MCP server: initialize + tools/list OK (${tools.length} tools)`);

  rmSync(workDir, { recursive: true, force: true });
  console.log('PACK-INSTALL SMOKE PASS');
}

await main();
