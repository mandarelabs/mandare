import { loader } from 'fumadocs-core/source';

import { docs } from '@/.source';

/**
 * fumadocs-mdx 11.10.x emits `files` as a thunk while fumadocs-core 15.8.x's
 * loader maps it as an array — both are "compatible" by peer range, so pin
 * the mismatch down HERE where it is visible. Drops out at the fumadocs 16
 * bump (S9 dependency pass).
 */
const raw = docs.toFumadocsSource();
const rawFiles: unknown = raw.files;
const files = typeof rawFiles === 'function' ? (rawFiles as () => unknown[])() : rawFiles;

export const source = loader({
  baseUrl: '/docs',
  // Runtime shape fixed above; the cast keeps the collection's page types.
  source: { files } as unknown as typeof raw,
});
