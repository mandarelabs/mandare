import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';

/**
 * The MCP server is a thin adapter over the `mandare` CLI — the CLI is the
 * product's LOCAL authority surface (kill, verify, issuance), so the MCP
 * server re-uses that one code path instead of growing a second one. Every
 * tool call becomes one CLI invocation with a bounded argument list.
 *
 * R4 (agent input is hostile): the MODEL never chooses paths, database
 * locations, or vault settings — those come exclusively from the server
 * process environment set by the operator in their MCP host config. Tool
 * arguments are validated by zod schemas and passed as discrete argv entries
 * (never through a shell), so there is no injection surface.
 */

export interface CliResult {
  code: number;
  stdout: string;
  stderr: string;
}

const CLI_TIMEOUT_MS = 60_000;
/** Bound captured output — a hostile/corrupt ledger must not OOM the host. */
const MAX_OUTPUT_BYTES = 8 * 1024 * 1024;

export function resolveCliPath(): string {
  const override = process.env.MANDARE_CLI;
  if (override !== undefined && override !== '') {
    return override;
  }
  const require = createRequire(import.meta.url);
  return require.resolve('@mandarelabs/cli/dist/main.js');
}

export function runCli(
  args: string[],
  env: Record<string, string | undefined>
): Promise<CliResult> {
  return new Promise((resolve, reject) => {
    execFile(
      process.execPath,
      [resolveCliPath(), ...args],
      {
        env: { ...env },
        timeout: CLI_TIMEOUT_MS,
        maxBuffer: MAX_OUTPUT_BYTES,
        windowsHide: true,
      },
      (error, stdout, stderr) => {
        if (error !== null && typeof (error as NodeJS.ErrnoException).code !== 'number') {
          // Spawn/timeout/maxBuffer failure — not a CLI exit code.
          reject(error instanceof Error ? error : new Error(String(error)));
          return;
        }
        const code =
          error === null ? 0 : ((error as NodeJS.ErrnoException).code as unknown as number);
        resolve({ code, stdout, stderr });
      }
    );
  });
}
