import { execFileSync } from 'node:child_process';

function git(args: readonly string[]): string | undefined {
  try {
    return execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    // No git binary or no repository: the caller treats it as "unknown".
    return undefined;
  }
}

// In a shallow clone every file reports the boundary commit's date.
const hasFullHistory = git(['rev-parse', '--is-shallow-repository']) === 'false';

/**
 * Date of the last commit that changed `file`, read from git while the site
 * is built. Undefined whenever git cannot answer truthfully (no repository,
 * a shallow clone, an untracked file) — the sitemap then omits `<lastmod>`,
 * because no date is better than a wrong one.
 */
export function lastCommitDate(file: string): Date | undefined {
  if (!hasFullHistory) {
    return undefined;
  }
  const iso = git(['log', '-1', '--format=%cI', '--', file]);
  return iso === undefined || iso === '' ? undefined : new Date(iso);
}
