import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createMDX } from 'fumadocs-mdx/next';

const withMDX = createMDX();

/** @type {import('next').NextConfig} */
const config = {
  reactStrictMode: true,
  poweredByHeader: false,
  outputFileTracingRoot: join(dirname(fileURLToPath(import.meta.url)), '..', '..'),
};

export default withMDX(config);
