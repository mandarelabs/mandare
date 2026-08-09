'use server';

import { execFile } from 'node:child_process';
import { revalidatePath } from 'next/cache';

import { cliPath } from './cli-path';

/**
 * The dashboard's ONE write surface: `mandare kill` via the CLI — the same
 * LOCAL authority an operator uses in the terminal, no parallel code path.
 * The dashboard is local-first (loopback bind by default); anyone who can
 * reach it holds operator power by definition, and killing only CLOSES
 * doors. Reinstate is deliberately NOT offered here — reopening a door is a
 * terminal act (`mandare reinstate`).
 */

const DID_PATTERN = /^did:[a-z0-9]+:[A-Za-z0-9._:%-]+$/;

export interface KillResult {
  ok: boolean;
  message: string;
}

/** Form-action wrapper: the fleet page re-renders from the ledger, which IS
 *  the result (a KILLED row). */
export async function killAgentAction(formData: FormData): Promise<void> {
  await killAgent(formData);
}

export async function killAgent(formData: FormData): Promise<KillResult> {
  const agent = formData.get('agent');
  if (typeof agent !== 'string' || !DID_PATTERN.test(agent)) {
    return { ok: false, message: 'not a DID' };
  }
  const result = await new Promise<KillResult>((resolve) => {
    execFile(
      process.execPath,
      [cliPath(), 'kill', agent, '--reason', 'dashboard kill button'],
      { timeout: 30_000, env: process.env },
      (error, stdout, stderr) => {
        if (error !== null) {
          resolve({ ok: false, message: (stderr || stdout || String(error)).slice(0, 500) });
          return;
        }
        resolve({ ok: true, message: stdout.split('\n')[0] ?? 'KILLED' });
      }
    );
  });
  revalidatePath('/');
  return result;
}
