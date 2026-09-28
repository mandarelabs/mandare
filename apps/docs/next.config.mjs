import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createMDX } from 'fumadocs-mdx/next';

const withMDX = createMDX();

/** @type {import('next').NextConfig} */
const config = {
  reactStrictMode: true,
  poweredByHeader: false,
  outputFileTracingRoot: join(dirname(fileURLToPath(import.meta.url)), '..', '..'),
  // The site is served at mandarelabs.com/docs through a proxy rewrite on the
  // marketing site, so everything it needs lives under /docs: the pages, the
  // search API (app/docs/api/search) and, via this prefix, the JS/CSS chunks.
  assetPrefix: '/docs',
  async rewrites() {
    return {
      beforeFiles: [{ source: '/docs/_next/:path+', destination: '/_next/:path+' }],
    };
  },
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
        ],
      },
    ];
  },
};

export default withMDX(config);
