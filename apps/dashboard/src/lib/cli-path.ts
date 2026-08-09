import { execFileSync } from 'node:child_process';

/**
 * Resolve the `mandare` CLI at RUNTIME, outside the bundler's reach.
 *
 * Two failed simpler attempts, recorded so nobody walks back into them:
 * a literal `require.resolve('@mandarelabs/cli/dist/main.js')` gets
 * statically bundled — and apps/cli/dist/main.js is a top-level-await
 * SCRIPT, so it EXECUTED inside next-server with the server's own argv;
 * webpack also shims `createRequire`, so even a dynamic specifier resolves
 * against the bundle (MODULE_NOT_FOUND). A one-shot child Node process uses
 * the REAL resolver against this app's node_modules; result cached.
 */

let cached: string | null = null;

export function cliPath(): string {
  const override = process.env.MANDARE_CLI;
  if (override !== undefined && override !== '') {
    return override;
  }
  if (cached === null) {
    cached = execFileSync(
      process.execPath,
      ['-e', "process.stdout.write(require.resolve('@mandarelabs/cli/dist/main.js'))"],
      { cwd: process.cwd(), encoding: 'utf8', timeout: 10_000 }
    ).trim();
  }
  return cached;
}
