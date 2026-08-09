import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { NextConfig } from 'next';

/**
 * Local-first, zero-telemetry posture: no remote images, no external fonts
 * (system font stack in globals.css), no analytics. NEXT_TELEMETRY_DISABLED
 * is set by the dev/start environment (compose + install docs); Next itself
 * makes no runtime calls home.
 */
const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // Monorepo root (pnpm workspace) — keeps file tracing anchored correctly.
  outputFileTracingRoot: join(dirname(fileURLToPath(import.meta.url)), '..', '..'),
  // The CLI must stay a real on-disk Node resolution, NEVER a bundled module:
  // apps/cli/dist/main.js is a top-level-await SCRIPT — bundling it executes
  // it inside next-server with the server's argv (found the hard way: the
  // fleet page's require.resolve pulled it into the page bundle and it ran
  // `mandare start` in-process at boot).
  serverExternalPackages: ['@mandarelabs/cli'],
};

export default nextConfig;
